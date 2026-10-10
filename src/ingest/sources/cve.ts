import { strFromU8, unzipSync } from 'fflate';
import { USER_AGENT } from '../../config';
import { CVE_ID } from '../../lib/normalize';
import { utcDay, nextDay } from '../../lib/time';
import { RateLimited } from '../budget';
import type { FetchResult, Source, SourceContext, VulnPatch } from '../types';
import { githubError, githubFetch, githubGet, nextLink } from './github';
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
 *
 * Zips are found through the GitHub releases API. When that is rate limited
 * (Workers share egress IPs, so an unauthenticated quota can be spent by
 * others), they are downloaded by release tag instead: each delta zip sits in
 * a release tagged `cve_YYYY-MM-DD_HHMMZ` or `cve_YYYY-MM-DD_at_end_of_day`, and
 * downloads don't count against the API quota.
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
export const DOWNLOAD_BASE = 'https://github.com/CVEProject/cvelistV5/releases/download';

const PAGE_SIZE = 250;
/**
 * GitHub lists only the first 1000 releases (HTTP 422 after that): about 45
 * days at ~22 releases a day. A cursor further back needs the backfill.
 */
export const MAX_RELEASE_PAGES = 10;
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

/** The zip to read for a day; final when it is the end-of-day zip. */
interface DayZip {
  url: string;
  final: boolean;
}

interface LoadedZip {
  bytes: Uint8Array;
  entries: ZipEntry[];
}

interface RunCache {
  releases?: { index: Map<string, DayAssets>; oldestDay: string | null; nextUrl: string | null; pages: number };
  /** Set once the releases API is rate limited; the rest of the run downloads by tag. */
  listingLimited: boolean;
  /** Days already looked up by tag in this run. */
  byTag: Map<string, DayZip | null>;
  zips: Map<string, LoadedZip>;
}

const caches = new WeakMap<SourceContext, RunCache>();
function cacheFor(ctx: SourceContext): RunCache {
  let c = caches.get(ctx);
  if (!c) {
    c = { listingLimited: false, byTag: new Map(), zips: new Map() };
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

    const found = await findDayZip(ctx, day, today);
    if (!found) {
      if (day === today) return { records: [], nextCursor: cursor, done: true };
      throw new Error(`no cvelistV5 delta release found for ${day}; re-run the backfill`);
    }
    const { url, final } = found;

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

/**
 * The zip to read for a day: the end-of-day zip if there is one, otherwise the
 * latest hourly zip. Null when the day has none yet.
 */
async function findDayZip(ctx: SourceContext, day: string, today: string): Promise<DayZip | null> {
  const cache = cacheFor(ctx);
  if (!cache.listingLimited) {
    try {
      const assets = await findDayAssets(ctx, day);
      if (!assets) return null;
      if (assets.endOfDay) return { url: assets.endOfDay, final: true };
      const latest = [...assets.hourly].sort((a, b) => b[0].localeCompare(a[0]))[0];
      return latest ? { url: latest[1], final: false } : null;
    } catch (err) {
      if (!(err instanceof RateLimited)) throw err;
      ctx.log(`cve: ${err.message}; downloading zips by release tag instead`);
      cache.listingLimited = true;
    }
  }
  return findDayZipByTag(ctx, day, today);
}

/**
 * Finds a day's zip without the releases API, by trying the end-of-day release
 * (for a finished day) and then each hourly release from the latest hour back.
 * A zip that exists is downloaded by the probe and kept for loadZip.
 */
async function findDayZipByTag(ctx: SourceContext, day: string, today: string): Promise<DayZip | null> {
  const cache = cacheFor(ctx);
  const known = cache.byTag.get(day);
  if (known !== undefined) return known;
  const candidates: DayZip[] = [];
  if (day < today) candidates.push({ url: `${DOWNLOAD_BASE}/cve_${day}_at_end_of_day/${day}_delta_CVEs_at_end_of_day.zip`, final: true });
  for (let h = day === today ? ctx.now().getUTCHours() : 23; h >= 0; h--) {
    const at = `${String(h).padStart(2, '0')}00Z`;
    candidates.push({ url: `${DOWNLOAD_BASE}/cve_${day}_${at}/${day}_delta_CVEs_at_${at}.zip`, final: false });
  }
  let found: DayZip | null = null;
  for (const c of candidates) {
    if (await tryLoadZip(ctx, c.url)) {
      found = c;
      break;
    }
  }
  cache.byTag.set(day, found);
  return found;
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
    if (res.status === 422) {
      // Past the 1000-release listing limit: nothing older can be found.
      ctx.log(`cve: ${(await githubError(res, 'cvelistV5 releases')).message}; stopped paging`);
      r.nextUrl = null;
      break;
    }
    if (!res.ok) throw await githubError(res, 'cvelistV5 releases');
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

async function loadZip(ctx: SourceContext, url: string): Promise<LoadedZip> {
  const zip = await tryLoadZip(ctx, url);
  if (!zip) throw new Error(`cvelistV5 zip ${url}: HTTP 404`);
  return zip;
}

/** Downloads and indexes a delta zip, or returns null when it doesn't exist. */
async function tryLoadZip(ctx: SourceContext, url: string): Promise<LoadedZip | null> {
  const cache = cacheFor(ctx);
  const hit = cache.zips.get(url);
  if (hit) return hit;
  const res = await githubFetch(ctx, url, { headers: { 'User-Agent': USER_AGENT } }, 'cve');
  if (res.status === 404) {
    await res.body?.cancel();
    return null;
  }
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
  const res = await githubFetch(ctx, cveRecordUrl(id), { headers: { 'User-Agent': USER_AGENT } }, 'cve');
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`cvelistV5 record ${id}: HTTP ${res.status}`);
  return parseCveRecord(await res.json());
}
