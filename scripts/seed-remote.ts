/**
 * Seeds the remote D1 database from your local one, so a new deployment (or a
 * fork's) starts with the 90-day history without running the backfill against
 * Cloudflare. Back-fill locally once, copy the snapshot up, and the hourly
 * ingest carries on from the snapshot's cursors.
 *
 *   npm run backfill                                   # once, into local D1
 *   npm run db:migrate:remote
 *   npm run seed:remote                                # shows the plan and its cost; writes nothing
 *   npm run seed:remote -- --yes                       # Workers Paid: all at once
 *   npm run seed:remote -- --yes --max-rows 90000      # Workers Free: one day's share; repeat daily
 *
 * D1 bills every inserted row plus one per index. A full snapshot is several
 * hundred thousand rows written: about 1% of Paid's monthly allowance, but
 * several days of Free's 100,000 a day. Each run stops before --max-rows,
 * saves its place in .cache/seed/, and the next run resumes from there.
 *
 * While a seed is unfinished, a "seeding" row in remote meta pauses ingest, so
 * the hourly job can't interleave with it. Cursors are copied last, and the
 * marker is removed with them.
 *
 * Options:
 *   --yes             write; without it, only the plan is shown
 *   --max-rows N      stop before this many (estimated) rows written in this run
 *   --restart         discard saved progress and take a fresh snapshot
 *   --force           seed even though the remote database already has data
 *   --into-local DIR  seed a scratch local database in DIR instead of remote (for testing)
 *
 * Runs only on a developer machine: it refuses under CI.
 */
import { existsSync } from 'node:fs';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { bumpDataVersionStatement, cursorKey, SEEDING_KEY } from '../src/ingest/meta';
import { parseArgs } from './lib/args';
import { nextChunk, planSeed, reportedRowsWritten } from './lib/seed';
import { inlineParams, parseResults, withRetries, wranglerRunner } from './lib/wrangler-store';

const { values } = parseArgs({
  options: {
    yes: { type: 'boolean' },
    'max-rows': { type: 'string' },
    restart: { type: 'boolean' },
    force: { type: 'boolean' },
    'into-local': { type: 'string' },
  },
});

const CACHE = path.join('.cache', 'seed');
const EXPORT_FILE = path.join(CACHE, 'export.sql');
const CHUNK_FILE = path.join(CACHE, 'chunk.sql');
const PROGRESS_FILE = path.join(CACHE, 'progress.json');
/** The same size the backfill flushes at. */
const CHUNK_BYTES = 8_000_000;

interface Progress {
  startedAt: string;
  /** Index of the next statement to send. */
  next: number;
  rowsEstimated: number;
  /** Rows Wrangler reported, when it reports them. */
  rowsReported: number;
}

const log = (m: string) => console.log(`[seed] ${m}`);

if (process.env.CI || process.env.GITHUB_ACTIONS) {
  throw new Error('seed:remote copies your local database, so it runs from a developer machine only, never in CI');
}
const maxRows = values['max-rows'] === undefined ? Infinity : Number(values['max-rows']);
if (!(maxRows > 0)) throw new Error('--max-rows must be a positive number');

const run = withRetries(wranglerRunner(process.cwd()), 2000);
const target = values['into-local'] ? ['--local', '--persist-to', values['into-local']] : ['--remote'];
const targetName = values['into-local'] ? `local database in ${values['into-local']}` : 'remote database';

async function query<T>(where: string[], sql: string): Promise<T[]> {
  return parseResults<T>(await run(['d1', 'execute', 'DB', ...where, '--json', '--command', sql]));
}

async function loadProgress(): Promise<Progress | null> {
  if (values.restart || !existsSync(PROGRESS_FILE) || !existsSync(EXPORT_FILE)) return null;
  return JSON.parse(await readFile(PROGRESS_FILE, 'utf8')) as Progress;
}

async function saveProgress(p: Progress): Promise<void> {
  await writeFile(PROGRESS_FILE, `${JSON.stringify(p, null, 2)}\n`);
}

/** Checks both databases and snapshots the local one. */
async function start(): Promise<Progress> {
  const [cursor] = await query<{ value: string }>(['--local'], `SELECT value FROM meta WHERE key = '${cursorKey('cve')}'`);
  if (!cursor) throw new Error('the local database has no data yet; run `npm run backfill` first');
  log(`local snapshot: CVEs up to ${(JSON.parse(cursor.value) as { day: string }).day}`);

  let remote: { vulns: number; seeding: number };
  try {
    [remote] = (await query<{ vulns: number; seeding: number }>(
      target,
      `SELECT (SELECT COUNT(*) FROM vulns) AS vulns, (SELECT COUNT(*) FROM meta WHERE key = '${SEEDING_KEY}') AS seeding`,
    )) as [{ vulns: number; seeding: number }];
  } catch {
    throw new Error(`the ${targetName} has no schema; run \`npm run db:migrate:remote\` first`);
  }
  if (remote.vulns > 0 && remote.seeding === 0 && !values.force) {
    throw new Error(`the ${targetName} already has ${remote.vulns} vulnerabilities; pass --force to overwrite them with the snapshot`);
  }

  await rm(CACHE, { recursive: true, force: true });
  await mkdir(CACHE, { recursive: true });
  await run(['d1', 'export', 'DB', '--local', '--no-schema', '--output', EXPORT_FILE]);
  const progress = { startedAt: new Date().toISOString(), next: 0, rowsEstimated: 0, rowsReported: 0 };
  await saveProgress(progress);
  return progress;
}

const progress = (await loadProgress()) ?? (await start());
const plan = planSeed(await readFile(EXPORT_FILE, 'utf8'));
const remainingRows = plan.slice(progress.next).reduce((sum, s) => sum + s.rows, 0);
log(
  `${progress.next > 0 ? `resuming at statement ${progress.next}: ` : ''}${plan.length - progress.next} of ${plan.length} statements left, ` +
    `about ${remainingRows.toLocaleString('en')} rows written in all`,
);
if (Number.isFinite(maxRows) && remainingRows > maxRows) {
  log(`at --max-rows ${maxRows.toLocaleString('en')} a run, that takes ${Math.ceil(remainingRows / maxRows)} runs`);
}
if (!values.yes) {
  log(`nothing written; add --yes to seed the ${targetName}`);
  process.exit(0);
}

const now = new Date();
await query(target, inlineParams(`INSERT OR REPLACE INTO meta (key, value, updated_at) VALUES ('${SEEDING_KEY}', ?, ?)`, [JSON.stringify({ startedAt: progress.startedAt }), now.toISOString()]));

let runRows = 0;
for (;;) {
  const chunk = nextChunk(plan, progress.next, CHUNK_BYTES, maxRows - runRows);
  if (!chunk) break;
  await writeFile(CHUNK_FILE, chunk.sql, 'utf8');
  const out = await run(['d1', 'execute', 'DB', ...target, '--file', CHUNK_FILE, '--yes']);
  const reported = reportedRowsWritten(out);
  runRows += chunk.rows;
  progress.next = chunk.end;
  progress.rowsEstimated += chunk.rows;
  progress.rowsReported += reported ?? 0;
  await saveProgress(progress);
  log(`${chunk.end} of ${plan.length} statements (${plan[chunk.end - 1]!.table}), ~${chunk.rows.toLocaleString('en')} rows${reported === null ? '' : `, ${reported.toLocaleString('en')} reported`}`);
}

if (progress.next < plan.length) {
  log(`stopped at --max-rows after ~${runRows.toLocaleString('en')} rows; run the same command again (tomorrow on Workers Free) to continue`);
  log('ingest stays paused until the seed finishes');
} else {
  const bump = bumpDataVersionStatement(new Date());
  await query(target, `DELETE FROM meta WHERE key = '${SEEDING_KEY}'; ${inlineParams(bump.sql, bump.params)}`);
  const reported = progress.rowsReported > 0 ? ` (${progress.rowsReported.toLocaleString('en')} reported by D1)` : '';
  log(`done: ~${progress.rowsEstimated.toLocaleString('en')} rows written${reported}; ingest resumes from the snapshot on its next run`);
  await rm(CACHE, { recursive: true, force: true });
}
