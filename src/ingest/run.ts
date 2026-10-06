import { RETENTION_DAYS } from '../config';
import { utcDay, windowStart } from '../lib/time';
import { applyPatches, type ApplyStats } from './apply';
import { Budget, BudgetExhausted, RateLimited } from './budget';
import { maintenanceStatements } from './maintenance';
import {
  bumpDataVersionStatement,
  cursorKey,
  EMPTY_STATUS,
  getMeta,
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
import type { Store } from './store';
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
  sources?: SourceName[];
  /** False during backfill: EPSS values become the baseline without events. */
  epssEvents?: boolean;
  /** Daily prune and catalog recount. 'force' runs it even if it ran today. */
  maintenance?: boolean | 'force';
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
  /** True when the run did nothing because a seed is in progress. */
  waitingForSeed?: boolean;
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
  if ((await getMeta(store, SEEDING_KEY)) !== null) {
    log('a seed is in progress (scripts/seed-remote.ts); skipping this run');
    return { sources: [], maintenance: false, subrequests: 0, waitingForSeed: true };
  }
  const ctx: SourceContext = {
    fetch: budget.wrapFetch(opts.fetch),
    store,
    budget,
    now,
    log,
    githubToken: opts.githubToken,
    runtime: opts.runtime,
  };
  const reports: SourceReport[] = [];
  let anyWrites = false;

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
          epssEvents: opts.epssEvents ?? true,
          extraStatements: [setMetaStatement(cursorKey(name), res.nextCursor, now())],
        });
        report.pages++;
        add(report, stats);
        if (name === 'kev' && stats.inserted.length > 0) {
          add(report, await enrichFromCveRecords(ctx, stats.inserted, opts, now));
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

  let maintained = false;
  if (opts.maintenance !== false) {
    const today = utcDay(now());
    const last = await getMeta<string>(store, LAST_MAINTENANCE_KEY);
    if (opts.maintenance === 'force' || last !== today) {
      await store.batch([...maintenanceStatements(now()), setMetaStatement(LAST_MAINTENANCE_KEY, today, now())]);
      maintained = true;
      anyWrites = true;
    }
  }

  if (anyWrites) await store.batch([bumpDataVersionStatement(now())]);
  await store.flush?.();
  return { sources: reports, maintenance: maintained, subrequests: budget.spent };
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
    epssEvents: opts.epssEvents ?? true,
  });
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
