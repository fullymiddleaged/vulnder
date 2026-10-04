import { z } from 'zod';
import { USER_AGENT } from '../../config';
import { RateLimited } from '../budget';
import type { FetchResult, Source, SourceContext, VulnPatch } from '../types';

/**
 * FIRST EPSS (https://api.first.org/epss/). Once a day, after the score date
 * advances, walks every CVE held in D1 in ID order and fetches its score in
 * batches that fit the API's 2,000-character `cve=` limit.
 */

export const EPSS_URL = 'https://api.first.org/data/v1/epss';
const MAX_CVE_PARAM_CHARS = 2000;

export interface EpssCursor {
  /** Score date of the pass in progress or last completed. */
  scoreDate: string | null;
  /** Last CVE ID covered in the pass in progress; null when no pass is running. */
  lastId: string | null;
}

const EpssResponse = z.object({
  status: z.string().optional(),
  data: z.array(
    z.object({
      cve: z.string(),
      epss: z.string(),
      percentile: z.string(),
      date: z.string(),
    }),
  ),
});

export const epssSource: Source<EpssCursor> = {
  name: 'epss',

  initialCursor(): EpssCursor {
    return { scoreDate: null, lastId: null };
  },

  async fetchChanges(cursor: EpssCursor, ctx: SourceContext): Promise<FetchResult<EpssCursor>> {
    let { scoreDate, lastId } = cursor;
    if (lastId === null) {
      // No pass running: start one only if a newer score date is out.
      const latest = await latestScoreDate(ctx);
      if (!latest || latest === scoreDate) return { records: [], nextCursor: cursor, done: true };
      scoreDate = latest;
      lastId = '';
    }

    const candidates = await ctx.store.all<{ id: string }>(
      "SELECT id FROM vulns WHERE id > ? AND id LIKE 'CVE-%' ORDER BY id LIMIT 200",
      [lastId],
    );
    if (candidates.length === 0) return { records: [], nextCursor: { scoreDate, lastId: null }, done: true };

    const ids: string[] = [];
    let chars = 0;
    for (const { id } of candidates) {
      const add = id.length + (ids.length > 0 ? 1 : 0);
      if (chars + add > MAX_CVE_PARAM_CHARS) break;
      ids.push(id);
      chars += add;
    }

    const url = `${EPSS_URL}?${new URLSearchParams({ cve: ids.join(','), date: scoreDate!, limit: String(ids.length + 10) })}`;
    const body = await getJson(ctx, url);
    const records = parseEpssResponse(body);
    const finished = ids.length === candidates.length && candidates.length < 200;
    return {
      records,
      nextCursor: { scoreDate, lastId: finished ? null : ids[ids.length - 1]! },
      done: finished,
    };
  },
};

async function latestScoreDate(ctx: SourceContext): Promise<string | null> {
  const body = await getJson(ctx, `${EPSS_URL}?limit=1`);
  const parsed = EpssResponse.safeParse(body);
  return parsed.success ? (parsed.data.data[0]?.date ?? null) : null;
}

async function getJson(ctx: SourceContext, url: string): Promise<unknown> {
  const res = await ctx.fetch(url, { headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' } });
  if (res.status === 429) throw new RateLimited('epss', 'HTTP 429');
  if (!res.ok) throw new Error(`EPSS: HTTP ${res.status}`);
  return res.json();
}

/** EPSS values arrive as strings; anything outside [0, 1] is dropped. */
export function parseEpssResponse(body: unknown): VulnPatch[] {
  const parsed = EpssResponse.safeParse(body);
  if (!parsed.success) throw new Error('EPSS: unexpected response shape');
  const out: VulnPatch[] = [];
  for (const d of parsed.data.data) {
    const epss = Number(d.epss);
    const percentile = Number(d.percentile);
    if (!Number.isFinite(epss) || epss < 0 || epss > 1) continue;
    if (!Number.isFinite(percentile) || percentile < 0 || percentile > 1) continue;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(d.date)) continue;
    out.push({ source: 'epss', id: d.cve, aliases: [], fields: { epss, epssPercentile: percentile, epssDate: d.date } });
  }
  return out;
}
