/**
 * Populates D1 with the last 90 days, and the safety net's year
 * (src/ingest/retention.ts: known-exploited, likely-exploited and CVSS 9.9+),
 * then leaves every source's cursor where regular ingest picks up. Safe to
 * re-run on a live database: unchanged records aren't rewritten.
 *
 *   npm run backfill                       # local D1
 *   npm run backfill -- --remote           # remote D1 (run `npm run db:migrate:remote` first)
 *   npm run backfill -- --cvelist ../cvelistV5 --no-update
 *
 * Steps:
 *   1. KEV: entries added inside the year, filled in from their CVE records.
 *   2. CVE: a shallow clone of cvelistV5 (in .cache/ by default); every record
 *      published inside the window, and those inside the year that qualify.
 *      The CVE cursor is set to the clone's newest dateUpdated, so the release
 *      zips continue from there.
 *   3. GitHub advisories modified inside the year, EPSS for everything stored,
 *      then this and last year's CVEs with EPSS of 10% or more
 *      (src/ingest/epss-net.ts). EPSS scores become the baseline, so the
 *      backfill raises no epss_crossed events.
 *
 * Along the way it fills cve_index (src/ingest/cve-index.ts) with every
 * record in the clone, every KEV entry and the day's EPSS file, whatever their
 * age: what a pasted list of CVEs is ranked from.
 *
 * --index-only fills just cve_index, on a database that already has the rest
 * (a deployment from before migration 0009). It writes about 800,000 rows:
 * under 2% of Workers Paid's monthly allowance, several days of Free's
 * 100,000 a day. On Free, add --max-rows (e.g. 80000) and run it once a day;
 * each run resumes where the last stopped (.cache/index-progress.json).
 *
 *   npm run backfill -- --index-only --remote
 *   npm run backfill -- --index-only --remote --max-rows 80000
 *
 * --index-only --exploit-refs fills just cve_index.exploit_ref (migration
 * 0010) on an index that is already full: it sends only the records with a
 * reference tagged "exploit", about 44,000 of 390,000 in October 2026, and
 * skips KEV and EPSS. It resumes the same way (.cache/exploit-refs-progress.json).
 *
 *   npm run backfill -- --index-only --exploit-refs --remote
 *
 * GITHUB_TOKEN, if set, raises the GitHub API limit.
 */
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { RETENTION_DAYS } from '../src/config';
import { applyPatches } from '../src/ingest/apply';
import { Budget } from '../src/ingest/budget';
import { hasExploitRef, indexStatements, refreshEpssIndex } from '../src/ingest/cve-index';
import { cursorKey, setMetaStatement } from '../src/ingest/meta';
import { runIngest, type RunReport } from '../src/ingest/run';
import { parseCveRecord } from '../src/ingest/sources/cve-record';
import type { CveCursor } from '../src/ingest/sources/cve';
import type { GhsaCursor } from '../src/ingest/sources/ghsa';
import { kevSource } from '../src/ingest/sources/kev';
import { firstExploitRef, type SourceContext, type VulnPatch } from '../src/ingest/types';
import { keepStart } from '../src/ingest/retention';
import { utcDay, windowStart } from '../src/lib/time';
import { parseArgs, parseTarget } from './lib/args';
import { cveFiles, ensureClone, readMeta } from './lib/cvelist-clone';
import { productionConfig } from './lib/production-config';
import { WranglerStore } from './lib/wrangler-store';

const { values } = parseArgs({
  options: {
    local: { type: 'boolean' },
    remote: { type: 'boolean' },
    cvelist: { type: 'string', default: path.join('.cache', 'cvelistV5') },
    'no-update': { type: 'boolean' },
    'skip-cve': { type: 'boolean' },
    'index-only': { type: 'boolean' },
    'exploit-refs': { type: 'boolean' },
    'max-rows': { type: 'string' },
  },
});
if (values['exploit-refs'] && !values['index-only']) throw new Error('--exploit-refs works with --index-only');
const maxRows = values['max-rows'] === undefined ? Infinity : Number(values['max-rows']);
// Below this a run can stop before writing anything (records go in steps of SCAN_CONCURRENCY, scores a statement at a time).
if (!(maxRows >= 10_000)) throw new Error('--max-rows must be at least 10000');
if (Number.isFinite(maxRows) && !values['index-only']) throw new Error('--max-rows works with --index-only');

const target = parseTarget(values);
const log = (m: string) => console.log(`[backfill] ${m}`);
const now = new Date();
const cutoff = windowStart(now, RETENTION_DAYS);
const yearStart = keepStart(now);
const store = new WranglerStore({ target, flushBytes: 8_000_000, config: target === 'remote' ? productionConfig() : undefined });
const githubToken = process.env.GITHUB_TOKEN || undefined;
const SCAN_CONCURRENCY = 256;
const unlimited = () => new Budget({ maxSubrequests: Number.MAX_SAFE_INTEGER, deadline: Number.MAX_SAFE_INTEGER });

function summarize(report: RunReport): void {
  for (const s of report.sources) {
    log(`${s.source}: ${s.status}${s.error ? ` (${s.error})` : ''}, ${s.received} received, ${s.written} written, ${s.events} events`);
  }
  if (report.sources.some((s) => s.status !== 'ok')) {
    throw new Error('a source did not finish; fix the cause and run the backfill again (it is safe to re-run)');
  }
}

async function migrate(): Promise<void> {
  if (target === 'local') {
    log('applying migrations to local D1');
    await promisify(execFile)(process.execPath, [path.join('node_modules', 'wrangler', 'bin', 'wrangler.js'), 'd1', 'migrations', 'apply', 'DB', '--local'], {
      env: { ...process.env, CI: 'true' },
    });
  }
  try {
    await store.all('SELECT COUNT(*) AS n FROM meta');
  } catch {
    throw new Error(`the ${target} database has no schema; run \`npm run db:migrate:${target}\` first`);
  }
}

/**
 * Scans the clone. Every record goes to cve_index; with `vulns`, the year's
 * also go to merge, which keeps those before the window only when they
 * qualify. In ID order, so an index-only run stopped by --max-rows resumes
 * after the last ID it wrote.
 */
async function backfillCve(opts: {
  vulns: boolean;
  after: string | null;
  maxRows: number;
  /** Index only the records this keeps (for --exploit-refs). */
  only?: (p: VulnPatch) => boolean;
}): Promise<{ last: string | null; done: boolean; rows: number }> {
  await ensureClone(values.cvelist!, !values['no-update'], log);
  log(
    opts.vulns
      ? `scanning ${values.cvelist} for records published since ${cutoff.slice(0, 10)}, and qualifying ones since ${yearStart.slice(0, 10)}; every record goes to cve_index`
      : `scanning ${values.cvelist} for cve_index${opts.after ? `, after ${opts.after}` : ''}`,
  );

  let scanned = 0;
  let maxTs = '';
  let maxId = '';
  let stored = 0;
  let indexed = 0;
  let last = opts.after;
  let batch: VulnPatch[] = [];
  let toIndex: VulnPatch[] = [];
  const flush = async (final: boolean) => {
    if (opts.vulns) {
      const extra =
        final && maxTs
          ? [setMetaStatement(cursorKey('cve'), { day: utcDay(new Date(maxTs)), ts: maxTs, id: maxId } satisfies CveCursor, now)]
          : [];
      const stats = await applyPatches(store, batch, { now, windowStart: cutoff, keepStart: yearStart, epssEvents: false, extraStatements: extra });
      stored += stats.written;
    }
    await store.batch(indexStatements(toIndex, { exploitRef }));
    indexed += toIndex.length;
    if (toIndex.length > 0) last = toIndex[toIndex.length - 1]!.id;
    batch = [];
    toIndex = [];
  };

  // Reading ~400k small files one at a time is slow (especially on Windows),
  // so files are read SCAN_CONCURRENCY at a time.
  const files: string[] = [];
  for await (const file of cveFiles(values.cvelist!)) files.push(file);
  const id = (file: string) => path.basename(file, '.json');
  files.sort((a, b) => (id(a) < id(b) ? -1 : id(a) > id(b) ? 1 : 0));
  const todo = opts.after ? files.filter((f) => id(f) > opts.after!) : files;
  log(`  ${files.length} record files found${todo.length < files.length ? `, ${todo.length} after ${opts.after}` : ''}`);

  const scanOne = async (file: string): Promise<{ patch: VulnPatch | null; inYear: boolean }> => {
    const meta = await readMeta(file);
    if (!meta) return { patch: null, inYear: false };
    if (meta.dateUpdated) {
      const ts = new Date(meta.dateUpdated).toISOString();
      if (ts > maxTs || (ts === maxTs && meta.cveId > maxId)) {
        maxTs = ts;
        maxId = meta.cveId;
      }
    }
    const inYear = meta.state === 'PUBLISHED' && !!meta.datePublished && new Date(meta.datePublished).toISOString() >= yearStart;
    return { patch: parseCveRecord(JSON.parse(await readFile(file, 'utf8'))), inYear };
  };

  for (let i = 0; i < todo.length; i += SCAN_CONCURRENCY) {
    const slice = todo.slice(i, i + SCAN_CONCURRENCY);
    if (indexed + toIndex.length + slice.length > opts.maxRows) {
      await flush(false);
      await store.flush();
      log(`cve: stopped at --max-rows after ${indexed} index rows; the next run resumes after ${last}`);
      return { last, done: false, rows: indexed };
    }
    for (const { patch, inYear } of await Promise.all(slice.map(scanOne))) {
      if (!patch) continue;
      if (!opts.only || opts.only(patch)) toIndex.push(patch);
      if (inYear) batch.push(patch);
    }
    scanned += slice.length;
    if (scanned % 25_600 < SCAN_CONCURRENCY) log(`  ${scanned} records scanned, ${stored} stored, ${indexed + toIndex.length} indexed`);
    if (toIndex.length >= 2000) await flush(false);
  }
  await flush(true);
  await store.flush();
  log(`cve: ${scanned} records scanned, ${stored} stored, ${indexed} indexed${opts.vulns ? `; cursor at ${maxTs} (${maxId})` : ''}`);
  return { last, done: true, rows: indexed };
}

/** Where an index-only run stopped. */
interface IndexProgress {
  /** Last CVE record indexed from the clone; null before the first. */
  cveAfter: string | null;
  cveDone: boolean;
}
const PROGRESS_FILE = path.join('.cache', 'index-progress.json');

async function backfillIndexOnly(): Promise<void> {
  const progress: IndexProgress = existsSync(PROGRESS_FILE)
    ? (JSON.parse(await readFile(PROGRESS_FILE, 'utf8')) as IndexProgress)
    : { cveAfter: null, cveDone: false };
  const save = async () => {
    await mkdir(path.dirname(PROGRESS_FILE), { recursive: true });
    await writeFile(PROGRESS_FILE, `${JSON.stringify(progress, null, 2)}\n`);
  };
  let left = maxRows;

  // 1. Every record in the clone.
  if (!progress.cveDone) {
    const res = await backfillCve({ vulns: false, after: progress.cveAfter, maxRows: left });
    progress.cveAfter = res.last;
    progress.cveDone = res.done;
    left -= res.rows;
    await save();
    if (!res.done) return;
  }

  // 2. Every KEV entry: the whole catalog, whatever its cursor says.
  const budget = unlimited();
  const ctx: SourceContext = { fetch: budget.wrapFetch(fetch), store, budget, now: () => now, log, runtime: 'node' };
  const kev = await kevSource.fetchChanges(kevSource.initialCursor(now), ctx);
  await store.batch(indexStatements(kev.records, { exploitRef }));
  await store.flush();
  left -= kev.records.length;
  log(`kev: ${kev.records.length} entries indexed`);

  // 3. EPSS: the day's file as the baseline, then whatever moved since (resumable on its own).
  const epss = await refreshEpssIndex(ctx, { baseline: true, maxRows: Math.max(0, left) });
  await store.flush();
  log(`epss: ${epss.written} scores indexed${epss.done ? '' : '; stopped at --max-rows, run again to continue'}`);
  if (epss.done && epss.date === null) log('epss: no finished EPSS pass in this database yet; run the full backfill (or let ingest run), then this again');
  if (epss.done && epss.date !== null) {
    await rm(PROGRESS_FILE, { force: true });
    log('cve_index is complete; ingest keeps it current from here');
  }
}

/** Where an --exploit-refs run stopped: the last record sent, and whether the clone is done. */
const EXPLOIT_REFS_PROGRESS = path.join('.cache', 'exploit-refs-progress.json');

async function backfillExploitRefs(): Promise<void> {
  if (!exploitRef) throw new Error(`the ${target} database has no cve_index.exploit_ref; run \`npm run db:migrate:${target}\` first`);
  const progress: IndexProgress = existsSync(EXPLOIT_REFS_PROGRESS)
    ? (JSON.parse(await readFile(EXPLOIT_REFS_PROGRESS, 'utf8')) as IndexProgress)
    : { cveAfter: null, cveDone: false };
  const res = await backfillCve({
    vulns: false,
    after: progress.cveAfter,
    maxRows,
    only: (p) => p.source === 'cve' && !p.withdrawn && firstExploitRef(p.fields.refs ?? []) !== null,
  });
  if (res.done) {
    await rm(EXPLOIT_REFS_PROGRESS, { force: true });
    log(`exploit refs: ${res.rows} records indexed; cve_index.exploit_ref is complete`);
    return;
  }
  await mkdir(path.dirname(EXPLOIT_REFS_PROGRESS), { recursive: true });
  await writeFile(EXPLOIT_REFS_PROGRESS, `${JSON.stringify({ cveAfter: res.last, cveDone: false } satisfies IndexProgress, null, 2)}\n`);
}

await migrate();
// False only on a remote database without migration 0010: the index is written without exploit_ref.
const exploitRef = await hasExploitRef(store);

if (values['index-only']) {
  await (values['exploit-refs'] ? backfillExploitRefs() : backfillIndexOnly());
  process.exit(0);
}

// 1. KEV first, so old CVEs that were added to KEV inside the window exist
//    before anything else refers to them.
await store.batch([setMetaStatement(cursorKey('kev'), { etag: null, lastModified: null }, now)]);
summarize(await runIngest({ store, fetch, budget: unlimited(), runtime: 'node', githubToken, sources: ['kev'], epssEvents: false, maintenance: false, log }));

// 2. CVE records from the clone.
if (!values['skip-cve']) await backfillCve({ vulns: true, after: null, maxRows: Infinity });

// 3. GitHub advisories over the whole year, then EPSS as the baseline (and the high-EPSS catch-up).
await store.batch([
  setMetaStatement(cursorKey('ghsa'), { since: yearStart, next: null, maxSeen: null } satisfies GhsaCursor, now),
  setMetaStatement(cursorKey('epss'), { scoreDate: null, lastId: null }, now),
]);
summarize(
  await runIngest({
    store,
    fetch,
    budget: unlimited(),
    runtime: 'node',
    githubToken,
    sources: ['ghsa', 'epss'],
    epssEvents: false,
    epssIndexBaseline: true,
    maintenance: 'force',
    log,
  }),
);

const [counts] = await store.all<Record<string, number>>(
  `SELECT (SELECT COUNT(*) FROM vulns) AS vulns, (SELECT COUNT(*) FROM affected) AS affected,
          (SELECT COUNT(*) FROM events) AS events, (SELECT COUNT(*) FROM catalog) AS catalog,
          (SELECT COUNT(*) FROM cve_index) AS cve_index`,
);
log(`done: ${JSON.stringify(counts)}`);
