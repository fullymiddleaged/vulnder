/**
 * Populates D1 with the last 90 days, then leaves every source's cursor where
 * regular ingest picks up.
 *
 *   npm run backfill                       # local D1
 *   npm run backfill -- --remote           # remote D1 (run `npm run db:migrate:remote` first)
 *   npm run backfill -- --cvelist ../cvelistV5 --no-update
 *
 * Steps:
 *   1. KEV: entries added inside the window, filled in from their CVE records.
 *   2. CVE: a shallow clone of cvelistV5 (in .cache/ by default); every record
 *      published inside the window. The CVE cursor is set to the clone's newest
 *      dateUpdated, so the release zips continue from there.
 *   3. GitHub advisories modified inside the window, and EPSS for everything
 *      stored. EPSS scores become the baseline, so the backfill raises no
 *      epss_crossed events.
 *
 * GITHUB_TOKEN, if set, raises the GitHub API limit.
 */
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { RETENTION_DAYS } from '../src/config';
import { applyPatches } from '../src/ingest/apply';
import { Budget } from '../src/ingest/budget';
import { cursorKey, setMetaStatement } from '../src/ingest/meta';
import { runIngest, type RunReport } from '../src/ingest/run';
import { parseCveRecord } from '../src/ingest/sources/cve-record';
import type { CveCursor } from '../src/ingest/sources/cve';
import type { GhsaCursor } from '../src/ingest/sources/ghsa';
import type { VulnPatch } from '../src/ingest/types';
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
  },
});

const target = parseTarget(values);
const log = (m: string) => console.log(`[backfill] ${m}`);
const now = new Date();
const cutoff = windowStart(now, RETENTION_DAYS);
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

async function backfillCve(): Promise<void> {
  await ensureClone(values.cvelist!, !values['no-update'], log);
  log(`scanning ${values.cvelist} for records published since ${cutoff.slice(0, 10)}`);

  let scanned = 0;
  let maxTs = '';
  let maxId = '';
  let stored = 0;
  let batch: VulnPatch[] = [];
  const flush = async (final: boolean) => {
    const extra =
      final && maxTs
        ? [setMetaStatement(cursorKey('cve'), { day: utcDay(new Date(maxTs)), ts: maxTs, id: maxId } satisfies CveCursor, now)]
        : [];
    const stats = await applyPatches(store, batch, { now, windowStart: cutoff, epssEvents: false, extraStatements: extra });
    stored += stats.written;
    batch = [];
  };

  // Reading ~400k small files one at a time is slow (especially on Windows),
  // so files are read SCAN_CONCURRENCY at a time.
  const files: string[] = [];
  for await (const file of cveFiles(values.cvelist!)) files.push(file);
  log(`  ${files.length} record files found`);

  const scanOne = async (file: string): Promise<VulnPatch | null> => {
    const meta = await readMeta(file);
    if (!meta) return null;
    if (meta.dateUpdated) {
      const ts = new Date(meta.dateUpdated).toISOString();
      if (ts > maxTs || (ts === maxTs && meta.cveId > maxId)) {
        maxTs = ts;
        maxId = meta.cveId;
      }
    }
    if (meta.state !== 'PUBLISHED' || !meta.datePublished || new Date(meta.datePublished).toISOString() < cutoff) return null;
    return parseCveRecord(JSON.parse(await readFile(file, 'utf8')));
  };

  for (let i = 0; i < files.length; i += SCAN_CONCURRENCY) {
    const patches = await Promise.all(files.slice(i, i + SCAN_CONCURRENCY).map(scanOne));
    for (const p of patches) if (p) batch.push(p);
    scanned += Math.min(SCAN_CONCURRENCY, files.length - i);
    if (scanned % 25_600 < SCAN_CONCURRENCY) log(`  ${scanned} records scanned, ${stored} stored`);
    if (batch.length >= 2000) await flush(false);
  }
  await flush(true);
  await store.flush();
  log(`cve: ${scanned} records scanned, ${stored} stored; cursor at ${maxTs} (${maxId})`);
}

await migrate();

// 1. KEV first, so old CVEs that were added to KEV inside the window exist
//    before anything else refers to them.
await store.batch([setMetaStatement(cursorKey('kev'), { etag: null, lastModified: null }, now)]);
summarize(await runIngest({ store, fetch, budget: unlimited(), runtime: 'node', githubToken, sources: ['kev'], epssEvents: false, maintenance: false, log }));

// 2. CVE records from the clone.
if (!values['skip-cve']) await backfillCve();

// 3. GitHub advisories over the whole window, then EPSS as the baseline.
await store.batch([
  setMetaStatement(cursorKey('ghsa'), { since: cutoff, next: null, maxSeen: null } satisfies GhsaCursor, now),
  setMetaStatement(cursorKey('epss'), { scoreDate: null, lastId: null }, now),
]);
summarize(
  await runIngest({ store, fetch, budget: unlimited(), runtime: 'node', githubToken, sources: ['ghsa', 'epss'], epssEvents: false, maintenance: 'force', log }),
);

const [counts] = await store.all<Record<string, number>>(
  `SELECT (SELECT COUNT(*) FROM vulns) AS vulns, (SELECT COUNT(*) FROM affected) AS affected,
          (SELECT COUNT(*) FROM events) AS events, (SELECT COUNT(*) FROM catalog) AS catalog`,
);
log(`done: ${JSON.stringify(counts)}`);
