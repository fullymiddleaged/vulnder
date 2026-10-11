import { z } from 'zod';
import { USER_AGENT } from '../../config';
import { RateLimited } from '../budget';
import { epssDecision, type StoredEpss } from '../merge';
import type { Store } from '../store';
import type { FetchResult, Source, SourceContext, VulnPatch } from '../types';

/**
 * FIRST EPSS. Once a day, after the score date advances (one small API call
 * to https://api.first.org/epss/), downloads that date's full scores file
 * (~2.7 MB gzipped, every CVE) and compares it with the scores held in D1.
 * Only CVEs whose score moved enough to write or fire an event
 * (epssDecision) become patches, handed out in ID order a page at a time.
 */

export const EPSS_URL = 'https://api.first.org/data/v1/epss';
export const EPSS_FILE_BASE = 'https://epss.empiricalsecurity.com/';
export const epssFileUrl = (date: string) => `${EPSS_FILE_BASE}epss_scores-${date}.csv.gz`;

/** Patches per page: one allForKeys chunk in applyPatches. */
const PAGE = 400;
/** Stored scores read per D1 query while comparing. */
const STORED_PAGE = 10_000;

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

/**
 * Patches for a pass, kept per store so pages within one run share one
 * download. A run that stops early downloads again next time and resumes
 * after the cursor's lastId.
 */
const passes = new WeakMap<Store, { scoreDate: string; patches: VulnPatch[] }>();

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

    let pass = passes.get(ctx.store);
    if (pass?.scoreDate !== scoreDate) {
      const patches = await changedScores(ctx, scoreDate!);
      // The file is not up yet: try again next run, without starting the pass.
      if (patches === null) return { records: [], nextCursor: cursor, done: true };
      pass = { scoreDate: scoreDate!, patches };
      passes.set(ctx.store, pass);
    }

    const from = lastId;
    const start = pass.patches.findIndex((p) => p.id > from);
    const records = start === -1 ? [] : pass.patches.slice(start, start + PAGE);
    const finished = start === -1 || start + PAGE >= pass.patches.length;
    if (finished) passes.delete(ctx.store);
    return {
      records,
      nextCursor: { scoreDate, lastId: finished ? null : records[records.length - 1]!.id },
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

/**
 * Patches, sorted by ID, for the stored CVEs whose score on `date` is worth
 * applying; null when that date's file is not published yet. Decided as if
 * events were on: during a backfill that skips only writes too small to matter.
 */
async function changedScores(ctx: SourceContext, date: string): Promise<VulnPatch[] | null> {
  const stored = await storedScores(ctx.store);
  const res = await ctx.fetch(epssFileUrl(date), { headers: { 'User-Agent': USER_AGENT } });
  // The bucket answers 403 for a file that does not exist.
  if (res.status === 403 || res.status === 404) {
    await res.body?.cancel();
    return null;
  }
  if (res.status === 429) throw new RateLimited('epss', 'HTTP 429');
  if (!res.ok || !res.body) throw new Error(`EPSS file: HTTP ${res.status}`);

  const patches: VulnPatch[] = [];
  const lines = res.body.pipeThrough(new DecompressionStream('gzip')).pipeThrough(new TextDecoderStream());
  for await (const line of splitLines(lines)) {
    const score = parseEpssLine(line);
    if (!score) continue;
    const before = stored.get(score.cve);
    if (!before || !epssDecision(before, score.epss, score.percentile, true).write) continue;
    patches.push({ source: 'epss', id: score.cve, aliases: [], fields: { epss: score.epss, epssPercentile: score.percentile, epssDate: date } });
  }
  return patches.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/** A page of stored CVE scores: a primary-key range, so it reads only the rows it returns. */
export const STORED_EPSS_SQL = "SELECT id, epss, epss_percentile, epss_baseline FROM vulns WHERE id > ? AND id < 'CVE.' ORDER BY id LIMIT ?";

async function storedScores(store: Store): Promise<Map<string, StoredEpss>> {
  const out = new Map<string, StoredEpss>();
  let after = 'CVE-';
  for (;;) {
    const rows = await store.all<{ id: string; epss: number | null; epss_percentile: number | null; epss_baseline: number | null }>(STORED_EPSS_SQL, [
      after,
      STORED_PAGE,
    ]);
    for (const r of rows) out.set(r.id, { epss: r.epss, epssPercentile: r.epss_percentile, epssBaseline: r.epss_baseline });
    if (rows.length < STORED_PAGE) return out;
    after = rows[rows.length - 1]!.id;
  }
}

async function* splitLines(text: ReadableStream<string>): AsyncGenerator<string> {
  let rest = '';
  for await (const chunk of text) {
    const parts = (rest + chunk).split('\n');
    rest = parts.pop()!;
    yield* parts;
  }
  if (rest) yield rest;
}

/** One `cve,epss,percentile` row; null for the comment and header lines and anything malformed or out of range. */
export function parseEpssLine(line: string): { cve: string; epss: number; percentile: number } | null {
  const [cve, e, p] = line.trim().split(',');
  if (!cve?.startsWith('CVE-') || e === undefined || p === undefined) return null;
  const epss = Number(e);
  const percentile = Number(p);
  if (e === '' || !Number.isFinite(epss) || epss < 0 || epss > 1) return null;
  if (p === '' || !Number.isFinite(percentile) || percentile < 0 || percentile > 1) return null;
  return { cve, epss, percentile };
}

/** EPSS API values arrive as strings; anything outside [0, 1] is dropped. Used by src/ingest/epss-net.ts. */
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
