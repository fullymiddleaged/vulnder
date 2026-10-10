import { EPSS_HIGH, RETENTION_DAYS, USER_AGENT } from '../config';
import { windowStart } from '../lib/time';
import { applyPatches, type ApplyStats } from './apply';
import { BudgetExhausted, RateLimited } from './budget';
import { cursorKey, getMeta, setMetaStatement } from './meta';
import { keepStart } from './retention';
import { fetchCveRecord } from './sources/cve';
import { EPSS_URL, parseEpssResponse, type EpssCursor } from './sources/epss';
import type { SourceContext, VulnPatch } from './types';

/**
 * The safety net's EPSS half (src/ingest/retention.ts). The EPSS source only
 * scores CVEs already stored, so one pruned at 90 days whose EPSS later passes
 * 10% would never come back. Once per EPSS score date, this asks FIRST for
 * every CVE from this year and last scored at 10% or more, and fetches the CVE
 * record of each one not stored, as far as the budget allows; merge keeps the
 * ones published in the last year. IDs that turn out not to qualify are
 * remembered, so each is fetched once rather than every day.
 */

export const EPSS_NET_KEY = 'epss_net';
/** FIRST returns at most this many rows a page; each year's list is well under it (about 640 for 2025). */
const PAGE = 2000;
const CVE_ID = /^CVE-\d{4}-\d{4,}$/;

interface Candidate {
  id: string;
  epss: number;
  percentile: number;
  date: string;
}

export interface EpssNetState {
  /** The score date the candidates came from. */
  scoreDate: string | null;
  /** High-EPSS CVEs not stored, still to fetch. */
  pending: Candidate[];
  /** Fetched before and didn't qualify (or have no record): not fetched again. */
  checked: string[];
}

export interface EpssNetReport {
  candidates: number;
  fetched: number;
  stored: number;
}

export async function catchUpHighEpss(ctx: SourceContext, epssEvents: boolean): Promise<EpssNetReport & { stats: ApplyStats | null }> {
  const report = { candidates: 0, fetched: 0, stored: 0, stats: null as ApplyStats | null };
  // Only once the EPSS source has finished its pass for a score date.
  const cursor = await getMeta<EpssCursor>(ctx.store, cursorKey('epss'));
  if (!cursor?.scoreDate || cursor.lastId !== null) return report;
  const state: EpssNetState = (await getMeta<EpssNetState>(ctx.store, EPSS_NET_KEY)) ?? { scoreDate: null, pending: [], checked: [] };

  try {
    if (state.scoreDate !== cursor.scoreDate) {
      if (!ctx.budget.has(4)) return report;
      const year = ctx.now().getUTCFullYear();
      const found: Candidate[] = [];
      for (const y of [year, year - 1]) found.push(...(await highEpss(ctx, y, cursor.scoreDate)));
      const ids = found.map((c) => c.id);
      const stored = new Set(
        (await ctx.store.all<{ id: string }>('SELECT id FROM vulns WHERE id IN (SELECT value FROM json_each(?))', [JSON.stringify(ids)])).map((r) => r.id),
      );
      const checked = new Set(state.checked);
      state.scoreDate = cursor.scoreDate;
      state.pending = found.filter((c) => !stored.has(c.id) && !checked.has(c.id));
      // Forget IDs that fell out of the list; they'll be checked again if they return.
      state.checked = state.checked.filter((id) => ids.includes(id));
      report.candidates = found.length;
    }

    const patches: VulnPatch[] = [];
    const tried: string[] = [];
    while (state.pending.length > 0 && ctx.budget.has(4)) {
      const c = state.pending[0]!;
      try {
        const patch = await fetchCveRecord(ctx, c.id);
        // The score travels with the record, so merge can see why it qualifies.
        if (patch) patches.push({ ...patch, fields: { ...patch.fields, epss: c.epss, epssPercentile: c.percentile, epssDate: c.date } });
      } catch (err) {
        if (err instanceof BudgetExhausted || err instanceof RateLimited) break;
        ctx.log(`epss net: could not fetch CVE record ${c.id}: ${err instanceof Error ? err.message : String(err)}`);
      }
      tried.push(c.id);
      state.pending.shift();
    }
    report.fetched = tried.length;
    if (patches.length > 0) {
      const now = ctx.now();
      // The usual window, so an older CVE coming back raises no "published" event.
      report.stats = await applyPatches(ctx.store, patches, { now, windowStart: windowStart(now, RETENTION_DAYS), keepStart: keepStart(now), epssEvents });
      report.stored = report.stats.inserted.length;
    }
    const inserted = new Set(report.stats?.inserted ?? []);
    state.checked.push(...tried.filter((id) => !inserted.has(id)));
  } finally {
    await ctx.store.batch([setMetaStatement(EPSS_NET_KEY, state, ctx.now())]);
  }
  return report;
}

async function highEpss(ctx: SourceContext, year: number, date: string): Promise<Candidate[]> {
  const params = new URLSearchParams({ 'epss-gt': String(EPSS_HIGH - 1e-4), q: `CVE-${year}-`, date, limit: String(PAGE) });
  const res = await ctx.fetch(`${EPSS_URL}?${params}`, { headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' } });
  if (res.status === 429) throw new RateLimited('epss', 'HTTP 429');
  if (!res.ok) throw new Error(`EPSS: HTTP ${res.status}`);
  return parseEpssResponse(await res.json())
    .filter((p) => CVE_ID.test(p.id) && p.id.startsWith(`CVE-${year}-`))
    .map((p) => ({ id: p.id, epss: p.fields.epss!, percentile: p.fields.epssPercentile!, date: p.fields.epssDate! }));
}
