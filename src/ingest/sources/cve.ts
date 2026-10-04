import { strFromU8, unzipSync } from 'fflate';
import { USER_AGENT } from '../../config';
import { CVE_ID } from '../../lib/normalize';
import { utcDay, nextDay } from '../../lib/time';
import type { FetchResult, Source, SourceContext, VulnPatch } from '../types';
import { githubGet, nextLink } from './github';
import { parseCveRecord } from './cve-record';

/**
 * MITRE cvelistV5, read from the release delta zips.
 *
 * Each release carries `YYYY-MM-DD_delta_CVEs_at_HHMMZ.zip` (every record changed
 * since midnight UTC that day, cumulative) and, once the day is over,
 * `YYYY-MM-DD_delta_CVEs_at_end_of_day.zip`. The date in the asset name can
 * differ from the release tag, so zips are found by asset name, never by tag.
 *
 * The cursor is (day, dateUpdated, cveId). For each day the source reads the
 * end-of-day zip if it exists, otherwise the latest hourly zip, and processes
 * records after the cursor in (dateUpdated, id) order. It only moves on to the
 * next day once that day's end-of-day zip has been read in full, so nothing
 * committed late in the day is skipped.
 */

export interface CveCursor {
  /** The UTC day whose zip is being read. */
  day: string;
  /** dateUpdated of the last record processed. */
  ts: string;
  /** cveId of the last record processed (tie-breaker for equal timestamps). */
  id: string;
}

export const RELEASES_URL = 'https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=100';
export const RAW_BASE = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves';

const PAGE_SIZE = 250;
/** Enough to look back ~90 days at ~22 releases a day. */
const MAX_RELEASE_PAGES = 25;
const ASSET_NAME = /^(\d{4}-\d{2}-\d{2})_delta_CVEs_at_(end_of_day|\d{4}Z)\.zip$/;

interface DayAssets {
  endOfDay: string | null;
  /** [HHMM, url], latest first after sorting. */
  hourly: [string, string][];
}

interface ZipEntry {
  name: string;
  ts: string;
  id: string;
}

interface RunCache {
  releases?: { index: Map<string, DayAssets>; oldestDay: string | null; nextUrl: string | null; pages: number };
  zips: Map<string, { bytes: Uint8Array; entries: ZipEntry[] }>;
}

const caches = new WeakMap<SourceContext, RunCache>();
function cacheFor(ctx: SourceContext): RunCache {
  let c = caches.get(ctx);
  if (!c) {
    c = { zips: new Map() };
    caches.set(ctx, c);
  }
  return c;
}

export const cveSource: Source<CveCursor> = {
  name: 'cve',

  initialCursor(now: Date): CveCursor {
    const day = utcDay(now);
    return { day, ts: `${day}T00:00:00.000Z`, id: '' };
  },

  async fetchChanges(cursor: CveCursor, ctx: SourceContext): Promise<FetchResult<CveCursor>> {
    const today = utcDay(ctx.now());
    const day = cursor.day;
    if (day > today) return { records: [], nextCursor: cursor, done: true };

    const assets = await findDayAssets(ctx, day);
    if (!assets) {
      if (day === today) return { records: [], nextCursor: cursor, done: true };
      throw new Error(`no cvelistV5 delta release found for ${day}; re-run the backfill`);
    }

    const hourly = [...assets.hourly].sort((a, b) => b[0].localeCompare(a[0]));
    const url = assets.endOfDay ?? hourly[0]?.[1];
    if (!url) return { records: [], nextCursor: cursor, done: true };
    const final = assets.endOfDay !== null;

    const zip = await loadZip(ctx, url);
    const pending = zip.entries.filter((e) => after(e, cursor));
    const page = pending.slice(0, PAGE_SIZE);

    if (page.length > 0) {
      const wanted = new Set(page.map((e) => e.name));
      const files = unzipSync(zip.bytes, { filter: (f) => wanted.has(f.name) });
      const records: VulnPatch[] = [];
      for (const e of page) {
        const data = files[e.name];
        if (!data) continue;
        const patch = parseRecordBytes(data);
        if (patch) records.push(patch);
      }
      const last = page[page.length - 1]!;
      return { records, nextCursor: { day, ts: last.ts, id: last.id }, done: false };
    }

    if (final && day < today) {
      // Move to the next day, re-reading the last hour of this one so records
      // committed just after midnight with an earlier dateUpdated are not lost.
      const overlap = `${day}T23:00:00.000Z`;
      const ts = cursor.ts < overlap ? cursor.ts : overlap;
      return { records: [], nextCursor: { day: nextDay(day), ts, id: '' }, done: false };
    }
    return { records: [], nextCursor: cursor, done: true };
  },
};

function after(e: ZipEntry, c: CveCursor): boolean {
  return e.ts > c.ts || (e.ts === c.ts && e.id > c.id);
}

function parseRecordBytes(data: Uint8Array): VulnPatch | null {
  try {
    return parseCveRecord(JSON.parse(strFromU8(data)));
  } catch {
    return null;
  }
}

/** Finds the delta zips for a day, paging back through releases as needed. */
async function findDayAssets(ctx: SourceContext, day: string): Promise<DayAssets | null> {
  const cache = cacheFor(ctx);
  if (!cache.releases) {
    cache.releases = { index: new Map(), oldestDay: null, nextUrl: RELEASES_URL, pages: 0 };
  }
  const r = cache.releases;
  // Releases come newest first, so once an older day has been seen, the newest
  // zips for `day` (end-of-day and latest hourly) have been seen too.
  while (r.nextUrl && r.pages < MAX_RELEASE_PAGES && (r.oldestDay === null || r.oldestDay > day)) {
    const res = await githubGet(ctx, r.nextUrl, 'cve');
    if (!res.ok) throw new Error(`cvelistV5 releases: HTTP ${res.status}`);
    const releases = (await res.json()) as { assets?: { name?: string; browser_download_url?: string }[] }[];
    r.pages++;
    r.nextUrl = nextLink(res.headers.get('link'));
    for (const rel of releases) {
      for (const a of rel.assets ?? []) {
        const m = ASSET_NAME.exec(a.name ?? '');
        if (!m || !a.browser_download_url) continue;
        const [, assetDay, when] = m as unknown as [string, string, string];
        if (!r.index.has(assetDay)) r.index.set(assetDay, { endOfDay: null, hourly: [] });
        const entry = r.index.get(assetDay)!;
        if (when === 'end_of_day') entry.endOfDay = a.browser_download_url;
        else entry.hourly.push([when, a.browser_download_url]);
        if (r.oldestDay === null || assetDay < r.oldestDay) r.oldestDay = assetDay;
      }
    }
    if (releases.length === 0) break;
  }
  return r.index.get(day) ?? null;
}

async function loadZip(ctx: SourceContext, url: string): Promise<{ bytes: Uint8Array; entries: ZipEntry[] }> {
  const cache = cacheFor(ctx);
  const hit = cache.zips.get(url);
  if (hit) return hit;
  const res = await ctx.fetch(url, { headers: { 'User-Agent': USER_AGENT } });
  if (!res.ok) throw new Error(`cvelistV5 zip ${url}: HTTP ${res.status}`);
  const bytes = new Uint8Array(await res.arrayBuffer());
  const entries = indexZip(bytes);
  const value = { bytes, entries };
  // Only the zip being read is kept, to bound memory in the Worker.
  cache.zips.clear();
  cache.zips.set(url, value);
  return value;
}

/** Lists the CVE records in a delta zip, sorted by (dateUpdated, id). */
export function indexZip(bytes: Uint8Array): ZipEntry[] {
  const files = unzipSync(bytes, { filter: (f) => /(^|\/)CVE-\d{4}-\d+\.json$/.test(f.name) });
  const entries: ZipEntry[] = [];
  for (const [name, data] of Object.entries(files)) {
    try {
      const json = JSON.parse(strFromU8(data)) as { cveMetadata?: { cveId?: unknown; dateUpdated?: unknown } };
      const id = json.cveMetadata?.cveId;
      const ts = json.cveMetadata?.dateUpdated;
      if (typeof id !== 'string' || !CVE_ID.test(id) || typeof ts !== 'string') continue;
      const iso = new Date(ts);
      if (Number.isNaN(iso.getTime())) continue;
      entries.push({ name, ts: iso.toISOString(), id });
    } catch {
      // skip unreadable files
    }
  }
  entries.sort((a, b) => (a.ts === b.ts ? a.id.localeCompare(b.id) : a.ts.localeCompare(b.ts)));
  return entries;
}

/** The raw GitHub URL of one CVE record in cvelistV5. */
export function cveRecordUrl(id: string): string {
  const [, year, seq] = id.split('-') as [string, string, string];
  return `${RAW_BASE}/${year}/${Math.floor(Number(seq) / 1000)}xxx/${id}.json`;
}

/** Fetches and parses one CVE record, e.g. for an old CVE that just landed on KEV. */
export async function fetchCveRecord(ctx: SourceContext, id: string): Promise<VulnPatch | null> {
  if (!CVE_ID.test(id)) return null;
  const res = await ctx.fetch(cveRecordUrl(id), { headers: { 'User-Agent': USER_AGENT } });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`cvelistV5 record ${id}: HTTP ${res.status}`);
  return parseCveRecord(await res.json());
}
