import { USER_AGENT } from '../config';
import { BudgetExhausted } from './budget';
import { EMPTY_STATUS, getMetas, setMetaStatement, type SourceStatus } from './meta';
import { REPORT_SOURCES, type ReportSource } from './reporters';
import { chunkByJsonSize, stmt, type Statement } from './store';
import type { SourceContext } from './types';

/**
 * Write-ups of a CVE by a trusted source (src/ingest/reporters.ts): which of
 * them has named it, where and when. Each source's RSS feed is fetched with a
 * conditional GET once an hour, so a quiet hour is one subrequest each. Rows go
 * into `exploits` (source = the reporter's id, kind = 'report', migration 0014
 * adds `published_at`), which the feed already reads by CVE ID, so ranking
 * costs no extra query (src/match/priority.ts).
 *
 * Feeds are untrusted input. Only CVE IDs, an https link on the source's own
 * host and the post's date are kept, never titles or text. A feed that fails,
 * is too big or doesn't parse writes nothing for that source and leaves the
 * others working; ranking then behaves as it would without it.
 */

/** Item kinds in `exploits` for a write-up: one that calls for urgent action, or any other. */
export const REPORT_KIND = 'report';
export const URGENT_KIND = 'urgent';
/**
 * Keywords that make a post urgent: critical, urgent, emergency, immediate(ly),
 * zero-day, and exploitation as it happens (exploiting, exploitation, actively
 * or being exploited, exploited in the wild). Bare "exploit" and "exploited"
 * are left out: disclosures use them for what could happen ("could be
 * exploited"). Read from a post's title and the opening of its summary only,
 * where a source states its verdict; a full article mentions "critical" in
 * passing. On the five feeds in October 2026 this marked every alert urgent and
 * no research write-up or fixed disclosure. Attack wording is never evidence:
 * only KEV and CISA count as exploited.
 */
const URGENT = /\b(?:critical|urgent(?:ly)?|emergency|immediate(?:ly)?|exploiting|exploitation|(?:actively|being)\s+exploited|exploited\s+in\s+the\s+wild|zero[-\s]?day|0-day)\b/i;
/** How much of a summary is read for that wording. */
const URGENT_SUMMARY_CHARS = 400;

/** True when a post's title or the opening of its summary calls the bug critical or asks to update now. */
export function isUrgent(title: string, summary: string): boolean {
  const opening = summary.replace(/<[^<>]{0,500}>/g, ' ').slice(0, URGENT_SUMMARY_CHARS);
  return URGENT.test(title) || URGENT.test(opening);
}
export const REPORTS_STATUS_KEY = 'status:reports';
/** The last attempt, so a run more often than hourly doesn't fetch again. */
export const REPORTS_LAST_KEY = 'reports:last';
export const reportsCursorKey = (id: string) => `cursor:reports:${id}`;
/** Feeds are 0.5–0.7 MB; one far bigger isn't the feed we know. */
export const MAX_FEED_CHARS = 3_000_000;
/** A fetched page (CERT-EU's JSON, an NCSC news page) of more than this isn't read. */
export const MAX_PAGE_CHARS = 1_000_000;
/** Pages fetched per run, across sources; the rest wait for the next run. */
export const MAX_PAGES_PER_RUN = 6;
/** Links remembered per source as already read, newest first. Feeds hold 4–120 items. */
const MAX_REMEMBERED = 200;
/** Minutes between attempts. */
export const REPORTS_EVERY_MINUTES = 45;
/** Posts older than this aren't written: ranking looks back 30 days, the backtest 90. */
export const REPORT_DAYS = 120;
/** Write-ups are kept this long, for measuring the rule against KEV adds. */
export const REPORT_KEEP_DAYS = 365;
/** The UTC day write-ups older than REPORT_KEEP_DAYS were last dropped. */
export const REPORTS_PRUNED_KEY = 'reports:pruned';

export interface ReportCursor {
  etag: string | null;
  lastModified: string | null;
  /** Item links whose page was already read (or need none), so they aren't fetched again. */
  read: string[];
}

export interface ReportRow {
  cve_id: string;
  url: string;
  /** YYYY-MM-DD, the post's date. */
  published_at: string;
  /** URGENT_KIND when any of the source's posts on it calls for urgent action. */
  kind: typeof REPORT_KIND | typeof URGENT_KIND;
}

export interface FeedItem {
  title: string;
  link: string | null;
  date: string | null;
  /** The description: a summary, or for some sources the whole article. */
  summary: string;
  /** The summary and any full content, for finding CVE IDs. */
  text: string;
}

export interface ReportsReport {
  status: 'ok' | 'unchanged' | 'error';
  /** Report rows sent, new or dated earlier. */
  written: number;
  pages: number;
  errors: string[];
}

const CVE_GLOBAL = /\bCVE-(\d{4})-(\d{4,7})\b/gi;

/** Distinct CVE IDs in a text, upper-cased, in order of first appearance. */
export function cveIdsIn(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(CVE_GLOBAL)) out.add(`CVE-${m[1]}-${m[2]}`);
  return [...out];
}

/** The text of the first <name …>…</name> in `xml`, CDATA unwrapped; '' when absent. */
function field(xml: string, name: string): string {
  let open = xml.indexOf(`<${name}`);
  // `<link` must not match `<linkedin…`: the next character has to end the name.
  while (open >= 0 && !/[\s>/]/.test(xml.charAt(open + name.length + 1))) open = xml.indexOf(`<${name}`, open + 1);
  if (open < 0) return '';
  const start = xml.indexOf('>', open);
  if (start < 0 || xml.charAt(start - 1) === '/') return '';
  const end = xml.indexOf(`</${name}>`, start);
  if (end < 0) return '';
  const body = xml.slice(start + 1, end).trim();
  return body.startsWith('<![CDATA[') && body.endsWith(']]>') ? body.slice(9, -3) : body;
}

/** The five XML entities, and numeric ones for ASCII; nothing is expanded beyond that. */
function unescapeXml(s: string): string {
  return s.replace(/&(amp|lt|gt|quot|apos|#\d{1,3}|#x[0-9a-f]{1,2});/gi, (m, e: string) => {
    const lower = e.toLowerCase();
    if (lower === 'amp') return '&';
    if (lower === 'lt') return '<';
    if (lower === 'gt') return '>';
    if (lower === 'quot') return '"';
    if (lower === 'apos') return "'";
    const code = lower.startsWith('#x') ? parseInt(lower.slice(2), 16) : parseInt(lower.slice(1), 10);
    return code >= 32 && code < 127 ? String.fromCharCode(code) : m;
  });
}

/**
 * The items of an RSS 2.0 feed: each <item>…</item>, read with indexOf, so
 * time is linear in the feed's length whatever it holds. An unclosed item ends
 * the list.
 */
export function parseFeed(xml: string): FeedItem[] {
  const out: FeedItem[] = [];
  let at = 0;
  for (;;) {
    let start = xml.indexOf('<item', at);
    while (start >= 0 && !/[\s>]/.test(xml.charAt(start + 5))) start = xml.indexOf('<item', start + 5);
    if (start < 0) return out;
    const end = xml.indexOf('</item>', start);
    if (end < 0) return out;
    const item = xml.slice(start, end);
    at = end + 7;
    const link = unescapeXml(field(item, 'link')) || null;
    const date = field(item, 'pubDate') || field(item, 'dc:date') || null;
    const summary = field(item, 'description');
    out.push({
      title: unescapeXml(field(item, 'title')),
      link,
      date,
      summary,
      text: `${summary}\n${field(item, 'content:encoded')}`,
    });
  }
}

/** The link, when it's https on the source's host or a subdomain of it; otherwise null. */
export function sourceLink(link: string | null, host: string): string | null {
  if (!link) return null;
  let u: URL;
  try {
    u = new URL(link.trim());
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || u.username || u.password || u.port) return null;
  const h = u.hostname.toLowerCase();
  return h === host || h.endsWith(`.${host}`) ? u.toString() : null;
}

/** European zone names the sources write, as offsets. */
const ZONES: Readonly<Record<string, string>> = { CET: '+0100', CEST: '+0200', BST: '+0100', WET: '+0000', WEST: '+0100', EET: '+0200', EEST: '+0300' };
const ownZone = (z: string): string | undefined => (Object.hasOwn(ZONES, z) ? ZONES[z] : undefined);

/** YYYY-MM-DD from an RSS date (RFC 822 or ISO 8601), or null. A date after today counts as today. */
export function postDay(date: string | null, now: Date): string | null {
  if (!date) return null;
  const trimmed = date.trim().slice(0, 64);
  // RFC 822 allows only US zone names; CERT-EU writes CEST, which Date.parse doesn't know.
  const zone = /\s([A-Z]{3,4})$/.exec(trimmed)?.[1];
  const offset = zone ? ownZone(zone) : undefined;
  const t = Date.parse(offset ? `${trimmed.slice(0, -zone!.length)}${offset}` : trimmed);
  if (!Number.isFinite(t)) return null;
  return new Date(Math.min(t, now.getTime())).toISOString().slice(0, 10);
}

/**
 * The CVEs a post counts for: every one it names when it names at most
 * `maxCves`, otherwise only those in its title, so a monthly roundup naming
 * dozens counts for none of them.
 */
export function countedCves(title: string, ids: string[], maxCves: number): string[] {
  if (ids.length <= maxCves) return ids;
  const inTitle = new Set(cveIdsIn(title));
  return ids.filter((id) => inTitle.has(id));
}

/** A fetched page's own summary, for urgency: CERT-EU's JSON title and description; nothing from HTML. */
export function pageSummary(body: string): string {
  if (!body.trimStart().startsWith('{')) return '';
  try {
    const json = JSON.parse(body) as Record<string, unknown>;
    return [json.title, json.description].filter((p): p is string => typeof p === 'string').join('\n');
  } catch {
    return '';
  }
}

/** The text of a fetched page worth reading for CVE IDs: CERT-EU's JSON body, or the page as it is. */
export function pageText(body: string): string {
  if (body.trimStart().startsWith('{')) {
    try {
      const json = JSON.parse(body) as Record<string, unknown>;
      const parts = [json.title, json.description, json.content_markdown].filter((p): p is string => typeof p === 'string');
      return parts.join('\n');
    } catch {
      return '';
    }
  }
  return body;
}

/**
 * Keeps each source's earliest post on a CVE, and marks the row urgent once any
 * of its posts is. A row that would change neither isn't written.
 */
const UPSERT_REPORTS = `INSERT INTO exploits (cve_id, source, kind, url, published_at, updated_at)
SELECT json_extract(value, '$.cve_id'), ?, json_extract(value, '$.kind'), json_extract(value, '$.url'), json_extract(value, '$.published_at'), ?
FROM json_each(?) WHERE true
ON CONFLICT (cve_id, source) DO UPDATE SET
  url = CASE WHEN exploits.published_at IS NULL OR excluded.published_at < exploits.published_at THEN excluded.url ELSE exploits.url END,
  published_at = CASE WHEN exploits.published_at IS NULL OR excluded.published_at < exploits.published_at THEN excluded.published_at ELSE exploits.published_at END,
  kind = CASE WHEN excluded.kind = '${URGENT_KIND}' THEN '${URGENT_KIND}' ELSE exploits.kind END,
  updated_at = excluded.updated_at
WHERE exploits.published_at IS NULL OR excluded.published_at < exploits.published_at OR (excluded.kind = '${URGENT_KIND}' AND exploits.kind != '${URGENT_KIND}')`;

export function reportStatements(rows: ReportRow[], source: string, now: Date): Statement[] {
  return chunkByJsonSize(rows).map((chunk) => stmt(UPSERT_REPORTS, source, now.toISOString(), JSON.stringify(chunk)));
}

/** Probes for migration 0014's column: reads nothing, fails only when it's missing. */
export const REPORTS_PROBE_SQL = "SELECT published_at FROM exploits WHERE cve_id = ''";

interface SourceResult {
  rows: ReportRow[];
  cursor: ReportCursor;
  pages: number;
  unchanged: boolean;
  /** Pages were left to read next run. */
  deferred: boolean;
}

/** One source: its feed, then the pages of new items that need reading, as far as `pagesLeft` allows. */
async function readSource(ctx: SourceContext, src: ReportSource, cursor: ReportCursor, pagesLeft: number): Promise<SourceResult> {
  const now = ctx.now();
  const headers: Record<string, string> = { 'User-Agent': USER_AGENT };
  if (cursor.etag) headers['If-None-Match'] = cursor.etag;
  if (cursor.lastModified) headers['If-Modified-Since'] = cursor.lastModified;
  const res = await ctx.fetch(src.feed, { headers });
  if (res.status === 304) return { rows: [], cursor, pages: 0, unchanged: true, deferred: false };
  if (!res.ok) throw new Error(`${src.name}: HTTP ${res.status}`);
  const body = await res.text();
  if (body.length > MAX_FEED_CHARS) throw new Error(`${src.name}: feed of ${body.length} characters is too big`);
  const items = parseFeed(body);
  if (items.length === 0) throw new Error(`${src.name}: no items in the feed`);

  const oldest = new Date(now.getTime() - REPORT_DAYS * 86_400_000).toISOString().slice(0, 10);
  const read = new Set(cursor.read);
  const rows: ReportRow[] = [];
  let pages = 0;
  // A page left for later (the run's page cap, the budget, an upstream error) must not hide behind a 304 next run.
  let deferred = false;
  for (const item of items) {
    const link = sourceLink(item.link, src.host);
    const day = postDay(item.date, now);
    if (!link || !day || day < oldest) continue;
    let ids = cveIdsIn(`${item.title}\n${item.text}`);
    // A page read for IDs (CERT-EU's JSON) has its own summary to judge urgency by.
    let summary = item.summary;
    if (ids.length === 0 && src.page && !read.has(link)) {
      if (!src.page.when.test(item.title)) {
        read.add(link);
        continue;
      }
      const pageUrl = sourceLink(src.page.url(link), src.host);
      if (!pageUrl) {
        read.add(link);
        continue;
      }
      if (pages >= pagesLeft || !ctx.budget.has(4)) {
        deferred = true;
        continue;
      }
      pages++;
      const page = await ctx.fetch(pageUrl, { headers: { 'User-Agent': USER_AGENT } });
      // A missing page is read as nothing; anything else is tried again next run.
      if (page.ok || page.status === 404) {
        const text = page.ok ? await page.text() : '';
        if (text.length <= MAX_PAGE_CHARS) {
          ids = cveIdsIn(pageText(text));
          summary = `${summary}\n${pageSummary(text)}`;
        }
        read.add(link);
      } else {
        deferred = true;
      }
    } else if (ids.length > 0) {
      read.add(link);
    }
    const kind = isUrgent(item.title, summary) ? URGENT_KIND : REPORT_KIND;
    for (const id of countedCves(item.title, ids, src.maxCves)) rows.push({ cve_id: id, url: link, published_at: day, kind });
  }
  // One row per CVE: the earliest post, urgent if any of them was.
  const earliest = new Map<string, ReportRow>();
  for (const r of rows) {
    const e = earliest.get(r.cve_id);
    const kind = r.kind === URGENT_KIND || e?.kind === URGENT_KIND ? URGENT_KIND : REPORT_KIND;
    earliest.set(r.cve_id, { ...(!e || r.published_at < e.published_at ? r : e), kind });
  }
  const next: ReportCursor = {
    etag: deferred ? null : res.headers.get('etag'),
    lastModified: deferred ? null : res.headers.get('last-modified'),
    read: [...read].slice(-MAX_REMEMBERED),
  };
  return { rows: [...earliest.values()], cursor: next, pages, unchanged: false, deferred };
}

/**
 * Reads every trusted source and writes what they report. Each source's rows
 * and its cursor go in one batch with the status, so a run that stops early
 * reads the rest next time. Without migration 0014 nothing is fetched and the
 * status says why.
 */
export async function refreshReports(ctx: SourceContext, sources: readonly ReportSource[] = REPORT_SOURCES): Promise<ReportsReport> {
  const { store, now } = ctx;
  const at = now().toISOString();
  // The status and every cursor in one query.
  const meta = await getMetas(store, [REPORTS_STATUS_KEY, REPORTS_PRUNED_KEY, ...sources.map((s) => reportsCursorKey(s.id))]);
  const status: SourceStatus = { ...EMPTY_STATUS, ...((meta.get(REPORTS_STATUS_KEY) as Partial<SourceStatus> | undefined) ?? {}) };
  status.lastRunAt = at;
  status.partial = false;
  const report: ReportsReport = { status: 'unchanged', written: 0, pages: 0, errors: [] };
  const writes: Statement[] = [setMetaStatement(REPORTS_LAST_KEY, at, now())];
  // A stored cursor means an earlier run found migration 0014's column, so only the first runs probe for it.
  const probed = sources.some((s) => meta.has(reportsCursorKey(s.id)));
  try {
    if (!probed) await store.all(REPORTS_PROBE_SQL);
  } catch {
    report.errors.push('no exploits.published_at column; apply migration 0014');
  }
  if (report.errors.length === 0) {
    // Once a UTC day, here rather than in maintenance.ts, since it needs migration 0014's column.
    const today = at.slice(0, 10);
    if (meta.get(REPORTS_PRUNED_KEY) !== today) {
      const cutoff = new Date(now().getTime() - REPORT_KEEP_DAYS * 86_400_000).toISOString().slice(0, 10);
      writes.push(stmt(`DELETE FROM exploits WHERE kind IN ('${REPORT_KIND}', '${URGENT_KIND}') AND published_at < ?`, cutoff), setMetaStatement(REPORTS_PRUNED_KEY, today, now()));
    }
    let records = 0;
    for (const src of sources) {
      if (!ctx.budget.has(4)) {
        status.partial = true;
        break;
      }
      const stored = meta.get(reportsCursorKey(src.id)) as Partial<ReportCursor> | undefined;
      const cursor: ReportCursor = {
        etag: typeof stored?.etag === 'string' ? stored.etag : null,
        lastModified: typeof stored?.lastModified === 'string' ? stored.lastModified : null,
        read: Array.isArray(stored?.read) ? stored.read.filter((l): l is string => typeof l === 'string') : [],
      };
      try {
        const r = await readSource(ctx, src, cursor, MAX_PAGES_PER_RUN - report.pages);
        report.pages += r.pages;
        records += r.rows.length;
        if (!r.unchanged) {
          writes.push(...reportStatements(r.rows, src.id, now()), setMetaStatement(reportsCursorKey(src.id), r.cursor, now()));
          report.written += r.rows.length;
          report.status = 'ok';
          if (r.deferred) status.partial = true;
        }
      } catch (err) {
        if (err instanceof BudgetExhausted) {
          status.partial = true;
          break;
        }
        report.errors.push(err instanceof Error ? err.message : String(err));
      }
    }
    status.lastRecords = records;
  }
  if (report.errors.length > 0) {
    report.status = 'error';
    status.lastError = report.errors.join('; ');
    status.lastErrorAt = at;
  } else {
    status.lastSuccessAt = at;
    status.lastError = null;
  }
  await store.batch([...writes, setMetaStatement(REPORTS_STATUS_KEY, status, now())]);
  return report;
}
