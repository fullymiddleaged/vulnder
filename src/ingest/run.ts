import { RETENTION_DAYS } from '../config';
import { utcDay, windowStart } from '../lib/time';
import { applyPatches, type ApplyStats } from './apply';
import { Budget, BudgetExhausted, RateLimited } from './budget';
import { openIndex, refreshEpssIndex, type EpssIndexReport, type IndexWriter } from './cve-index';
import { catchUpHighEpss } from './epss-net';
import { EOL_CURSOR_KEY, EOL_LAST_KEY, EOL_STATUS_KEY, EOL_STORED_SQL, eolStatements, fetchEol, type EolCursor, type EolRow } from './eol';
import { exploitLastKey, refreshExploits, type ExploitReport, type ExploitSource } from './exploits';
import { refreshReports, REPORTS_EVERY_MINUTES, REPORTS_LAST_KEY, type ReportsReport } from './reports';
import { metasploitSpec } from './metasploit';
import { nucleiSpec } from './nuclei';
import { assignFamilies, type Embedder, type FamilyReport } from './families';
import { maintenanceStatements } from './maintenance';
import { keepStart } from './retention';
import {
  bumpDataVersionStatement,
  cursorKey,
  EMPTY_STATUS,
  getMeta,
  getMetas,
  LAST_MAINTENANCE_KEY,
  SEEDING_KEY,
  setMetaStatement,
  statusKey,
  type SourceStatus,
} from './meta';
import { cveSource, fetchCveRecord } from './sources/cve';
import { epssSource } from './sources/epss';
import { ghsaSource } from './sources/ghsa';
import { kevSource } from './sources/kev';
import type { Statement, Store } from './store';
import type { Source, SourceContext, SourceName, VulnPatch } from './types';

/** Run order matters: CVE and GHSA create records that KEV and EPSS then enrich. */
export const SOURCES: Record<SourceName, Source<unknown>> = {
  cve: cveSource as Source<unknown>,
  ghsa: ghsaSource as Source<unknown>,
  kev: kevSource as Source<unknown>,
  epss: epssSource as Source<unknown>,
};
export const SOURCE_ORDER: SourceName[] = ['cve', 'ghsa', 'kev', 'epss'];

export interface RunOptions {
  store: Store;
  /** Unbudgeted fetch; the run wraps it with the budget. */
  fetch: typeof fetch;
  budget: Budget;
  runtime: 'worker' | 'node';
  now?: () => Date;
  log?: (message: string) => void;
  githubToken?: string;
  /** Waits between paced or retried upstream calls; setTimeout when left out. */
  sleep?: (ms: number) => Promise<void>;
  sources?: SourceName[];
  /** False during backfill: EPSS values become the baseline without events. */
  epssEvents?: boolean;
  /** Daily prune and catalog recount. 'force' runs it even if it ran today. */
  maintenance?: boolean | 'force';
  /** Daily vendor support dates from endoflife.date (src/ingest/eol.ts). 'force' fetches even if it ran today. */
  eol?: boolean | 'force';
  /** Daily Metasploit module index (src/ingest/metasploit.ts). 'force' fetches even if it ran today. */
  metasploit?: boolean | 'force';
  /** Daily Nuclei template index (src/ingest/nuclei.ts). 'force' fetches even if it ran today. */
  nuclei?: boolean | 'force';
  /** Trusted sources' write-ups (src/ingest/reports.ts), at most every 45 minutes. 'force' fetches whenever it runs. */
  reports?: boolean | 'force';
  /** Workers AI embeddings for variant families; without it, families wait. */
  embed?: Embedder;
  /** Most vulns to assign families in a UTC day (FREE_PLAN_FAMILY_DAILY on Free); no cap when left out. */
  familyDailyVulns?: number;
  /**
   * Lets the first EPSS pass into cve_index write every scored CVE (about
   * 400,000 rows). Only the backfill sets it; without it, ingest waits for one.
   */
  epssIndexBaseline?: boolean;
}

export interface SourceReport {
  source: SourceName;
  status: 'ok' | 'partial' | 'error';
  pages: number;
  received: number;
  written: number;
  skipped: number;
  deleted: number;
  events: number;
  error?: string;
}

export interface RunReport {
  sources: SourceReport[];
  maintenance: boolean;
  subrequests: number;
  /** D1 statements, also counted in subrequests. */
  d1Queries: number;
  /** True when the run did nothing because a seed is in progress. */
  waitingForSeed?: boolean;
  families?: FamilyReport;
  /** The daily support-dates fetch, when this run made it. */
  eol?: EolReport;
  /** The daily exploit-availability fetches, when this run made them. */
  metasploit?: ExploitReport;
  nuclei?: ExploitReport;
  /** The trusted sources' feeds, when this run read them. */
  reports?: ReportsReport;
  /** Rows sent to cve_index beside the sources (src/ingest/cve-index.ts); undefined when the table is missing. */
  cveIndex?: { rows: number; epss?: EpssIndexReport };
}

export interface EolReport {
  status: 'ok' | 'unchanged' | 'error';
  /** Release rows written or deleted. */
  written: number;
  error?: string;
}

/**
 * One ingest run. Each source pages through its changes until it is caught up
 * or the budget runs out; every page's writes and its new cursor are stored in
 * one batch, so a run that stops early resumes where it left off.
 */
export async function runIngest(opts: RunOptions): Promise<RunReport> {
  const now = opts.now ?? (() => new Date());
  const log = opts.log ?? (() => {});
  const { store, budget } = opts;
  // A seed replaces cursors at the end; anything ingested before then would be
  // overwritten or fetched twice, so wait for it.
  // Whether a seed is running, and when each daily or hourly step last ran, in one query.
  const lastRun = await getMetas(store, [SEEDING_KEY, LAST_MAINTENANCE_KEY, EOL_LAST_KEY, exploitLastKey('metasploit'), exploitLastKey('nuclei'), REPORTS_LAST_KEY]);
  if (lastRun.has(SEEDING_KEY)) {
    log('a seed is in progress (scripts/seed-remote.ts); skipping this run');
    return { sources: [], maintenance: false, subrequests: budget.spent, d1Queries: budget.d1Spent, waitingForSeed: true };
  }
  const ctx: SourceContext = {
    fetch: budget.wrapFetch(opts.fetch),
    store,
    budget,
    now,
    log,
    githubToken: opts.githubToken,
    runtime: opts.runtime,
    sleep: opts.sleep,
  };
  const reports: SourceReport[] = [];
  let anyWrites = false;
  // Opened before anything is written, so a missing table is found while nothing is buffered.
  const cveIndex = await openIndex(store, budget, log);
  let indexRows = 0;

  // Once a UTC day: vendor support dates. One subrequest and a few D1
  // statements, taken first: the sources and families spend whatever budget
  // they are given, so a step after them never ran on a busy cron.
  let eol: EolReport | undefined;
  if (opts.eol !== false && budget.has(4)) {
    const today = utcDay(now());
    if (opts.eol === 'force' || lastRun.get(EOL_LAST_KEY) !== today) {
      eol = await refreshEol(ctx, today);
      if (eol.written > 0) anyWrites = true;
      log(`eol: ${eol.status}, ${eol.written} release row(s) written${eol.error ? ` (${eol.error})` : ''}`);
    }
  }

  // Once a UTC day each: exploit availability. One subrequest when unchanged.
  const exploits: Partial<Record<ExploitSource, ExploitReport>> = {};
  for (const spec of [metasploitSpec, nucleiSpec]) {
    const opt = opts[spec.source];
    if (opt === false || !budget.has(4)) continue;
    const today = utcDay(now());
    if (opt !== 'force' && lastRun.get(exploitLastKey(spec.source)) === today) continue;
    const r = await refreshExploits(ctx, spec, today);
    exploits[spec.source] = r;
    if (r.written > 0) anyWrites = true;
    log(`${spec.source}: ${r.status}, ${r.written} row(s) written${r.error ? ` (${r.error})` : ''}`);
  }

  // About hourly: trusted sources' write-ups. One subrequest per source when unchanged.
  let writeUps: ReportsReport | undefined;
  if (opts.reports !== false && budget.has(8)) {
    const last = lastRun.get(REPORTS_LAST_KEY);
    const at = typeof last === 'string' ? Date.parse(last) : NaN;
    const due = Number.isNaN(at) || now().getTime() - at >= REPORTS_EVERY_MINUTES * 60_000;
    if (opts.reports === 'force' || due) {
      writeUps = await refreshReports(ctx);
      if (writeUps.written > 0) anyWrites = true;
      log(`reports: ${writeUps.status}, ${writeUps.written} row(s) sent, ${writeUps.pages} page(s) read${writeUps.errors.length > 0 ? ` (${writeUps.errors.join('; ')})` : ''}`);
    }
  }

  const order = opts.sources ?? SOURCE_ORDER;
  for (const [index, name] of order.entries()) {
    const source = SOURCES[name];
    const report: SourceReport = { source: name, status: 'ok', pages: 0, received: 0, written: 0, skipped: 0, deleted: 0, events: 0 };
    const status: SourceStatus = { ...EMPTY_STATUS, ...((await getMeta<SourceStatus>(store, statusKey(name))) ?? {}) };
    let cursor = (await getMeta<unknown>(store, cursorKey(name))) ?? source.initialCursor(now());
    // Each source may start pages until it has used its share of what is left,
    // so a source that is far behind cannot starve the ones after it. A share
    // it does not use rolls over to the sources after it.
    const shareEnd = budget.spent + Math.floor(budget.remaining / (order.length - index));

    try {
      for (;;) {
        // Leave room for the page's own fetch and its D1 batch.
        if (!budget.has(4) || (report.pages > 0 && budget.spent + 4 > shareEnd)) {
          report.status = 'partial';
          break;
        }
        const res = await source.fetchChanges(cursor, ctx);
        const stats = await applyPatches(store, res.records, {
          now: now(),
          windowStart: windowStart(now(), RETENTION_DAYS),
          keepStart: keepStart(now()),
          epssEvents: opts.epssEvents ?? true,
          extraStatements: [setMetaStatement(cursorKey(name), res.nextCursor, now())],
        });
        report.pages++;
        add(report, stats);
        // Beside the page, after it: an index write that fails or is skipped never holds the source back.
        if (cveIndex && (name === 'cve' || name === 'kev')) indexRows += await cveIndex.write(res.records);
        if (name === 'kev' && stats.inserted.length > 0) {
          add(report, await enrichFromCveRecords(ctx, stats.inserted, opts, now, cveIndex));
        }
        cursor = res.nextCursor;
        if (res.done) break;
      }
    } catch (err) {
      if (err instanceof BudgetExhausted || err instanceof RateLimited) {
        report.status = 'partial';
        log(`${name}: stopped early (${err.message})`);
      } else {
        report.status = 'error';
        report.error = err instanceof Error ? err.message : String(err);
        log(`${name}: error: ${report.error}`);
      }
    }

    const at = now().toISOString();
    status.lastRunAt = at;
    status.partial = report.status === 'partial';
    status.lastRecords = report.received;
    if (report.status === 'ok') status.lastSuccessAt = at;
    if (report.status === 'error') {
      status.lastError = report.error ?? 'unknown error';
      status.lastErrorAt = at;
    } else {
      status.lastError = null;
    }
    await store.batch([setMetaStatement(statusKey(name), status, now())]);
    if (report.written > 0 || report.deleted > 0 || report.events > 0) anyWrites = true;
    reports.push(report);
    log(
      `${name}: ${report.status}, ${report.pages} page(s), ${report.received} received, ${report.written} written, ` +
        `${report.events} event(s), ${report.skipped} skipped, ${report.deleted} deleted`,
    );
  }

  // After an EPSS pass: bring back CVEs from the last year whose EPSS has passed 10%.
  if (order.includes('epss')) {
    try {
      const net = await catchUpHighEpss(ctx, opts.epssEvents ?? true, cveIndex);
      if (net.candidates > 0 || net.fetched > 0) log(`epss net: ${net.candidates} candidate(s), ${net.fetched} record(s) fetched, ${net.stored} stored`);
      if (net.stats && (net.stats.written > 0 || net.stats.events > 0)) anyWrites = true;
    } catch (err) {
      log(`epss net: error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // The index's EPSS columns, from the day's file against the last one written.
  let epssIndex: EpssIndexReport | undefined;
  if (cveIndex && order.includes('epss')) {
    try {
      epssIndex = await refreshEpssIndex(ctx, { baseline: opts.epssIndexBaseline });
      if (epssIndex.written > 0) log(`cve index: ${epssIndex.written} EPSS score(s) written${epssIndex.done ? '' : ' (more next run)'}`);
    } catch (err) {
      log(`cve index: EPSS error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  if (indexRows > 0 || (epssIndex?.written ?? 0) > 0) anyWrites = true;

  let families: FamilyReport | undefined;
  if (opts.embed) {
    try {
      families = await assignFamilies({ store, budget, embed: opts.embed, now, log, dailyVulns: opts.familyDailyVulns });
    } catch (err) {
      if (!(err instanceof BudgetExhausted)) throw err;
      families = { assigned: 0, joined: 0, tokens: 0, stopped: 'budget' };
    }
    log(`families: ${families.assigned} assigned, ${families.joined} joined a family, ${families.tokens} tokens${families.stopped ? ` (stopped: ${families.stopped})` : ''}`);
    if (families.joined > 0) anyWrites = true;
  }

  let maintained = false;
  if (opts.maintenance !== false) {
    const today = utcDay(now());
    const last = lastRun.get(LAST_MAINTENANCE_KEY);
    if (opts.maintenance === 'force' || last !== today) {
      await store.batch([...maintenanceStatements(now()), setMetaStatement(LAST_MAINTENANCE_KEY, today, now())]);
      maintained = true;
      anyWrites = true;
    }
  }

  if (anyWrites) await store.batch([bumpDataVersionStatement(now())]);
  await store.flush?.();
  return {
    sources: reports,
    maintenance: maintained,
    subrequests: budget.spent,
    d1Queries: budget.d1Spent,
    ...(families ? { families } : {}),
    ...(eol ? { eol } : {}),
    ...exploits,
    ...(writeUps ? { reports: writeUps } : {}),
    ...(cveIndex ? { cveIndex: { rows: indexRows, ...(epssIndex ? { epss: epssIndex } : {}) } } : {}),
  };
}

/**
 * Fetches endoflife.date and writes what changed, with its status. A failure
 * keeps the last good dates and is tried again tomorrow.
 */
async function refreshEol(ctx: SourceContext, today: string): Promise<EolReport> {
  const { store, now, log } = ctx;
  const status: SourceStatus = { ...EMPTY_STATUS, ...((await getMeta<SourceStatus>(store, EOL_STATUS_KEY)) ?? {}) };
  const cursor = (await getMeta<EolCursor>(store, EOL_CURSOR_KEY)) ?? { etag: null };
  const at = now().toISOString();
  status.lastRunAt = at;
  status.partial = false;
  let report: EolReport;
  const writes: Statement[] = [];
  try {
    const res = await fetchEol(cursor, ctx);
    if (res.missing.length > 0) log(`eol: endoflife.date no longer lists ${res.missing.join(', ')} (see src/stack/eol.ts)`);
    let written = 0;
    if (res.status === 'fetched') {
      const diff = eolStatements(await store.all<EolRow>(EOL_STORED_SQL), res.rows, now());
      writes.push(...diff.statements);
      written = diff.rows;
    }
    writes.push(setMetaStatement(EOL_CURSOR_KEY, res.nextCursor, now()));
    report = { status: res.status === 'unchanged' ? 'unchanged' : 'ok', written };
    status.lastSuccessAt = at;
    status.lastError = null;
    status.lastRecords = res.rows.length;
  } catch (err) {
    if (err instanceof BudgetExhausted) return { status: 'error', written: 0, error: 'budget' };
    const message = err instanceof Error ? err.message : String(err);
    report = { status: 'error', written: 0, error: message };
    status.lastError = message;
    status.lastErrorAt = at;
  }
  await store.batch([...writes, setMetaStatement(EOL_STATUS_KEY, status, now()), setMetaStatement(EOL_LAST_KEY, today, now())]);
  return report;
}

/**
 * KEV can add an old CVE that ingest has never seen. The KEV entry creates a
 * stub; this fills it in from the full CVE record, as far as the budget allows.
 */
async function enrichFromCveRecords(
  ctx: SourceContext,
  ids: string[],
  opts: RunOptions,
  now: () => Date,
  index: IndexWriter | null,
): Promise<ApplyStats> {
  const patches: VulnPatch[] = [];
  for (const id of ids) {
    if (!ctx.budget.has(4)) break;
    try {
      const patch = await fetchCveRecord(ctx, id);
      if (patch) patches.push(patch);
    } catch (err) {
      if (err instanceof BudgetExhausted) break;
      ctx.log(`kev: could not fetch CVE record ${id}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  const stats = await applyPatches(ctx.store, patches, {
    now: now(),
    windowStart: windowStart(now(), RETENTION_DAYS),
    keepStart: keepStart(now()),
    epssEvents: opts.epssEvents ?? true,
  });
  await index?.write(patches);
  // These records were counted when KEV received them.
  return { ...stats, received: 0, inserted: [] };
}

function add(report: SourceReport, stats: ApplyStats): void {
  report.received += stats.received;
  report.written += stats.written;
  report.skipped += stats.skipped;
  report.deleted += stats.deleted;
  report.events += stats.events;
}
