import fc from 'fast-check';
import { beforeEach, describe, expect, it } from 'vitest';
import { getMeta } from '../src/ingest/meta';
import { REPORT_SOURCES } from '../src/ingest/reporters';
import {
  countedCves,
  cveIdsIn,
  isUrgent,
  MAX_TITLE_CHARS,
  plainTitle,
  MAX_FEED_CHARS,
  pageText,
  parseFeed,
  postDay,
  refreshReports,
  REPORTS_PROBE_SQL,
  REPORTS_STATUS_KEY,
  reportsCursorKey,
  sourceLink,
  type ReportCursor,
} from '../src/ingest/reports';
import type { Store } from '../src/ingest/store';
import { resetDb, rows, sourceContext, store } from './helpers/db';
import { FakeFetch } from './helpers/fake-fetch';
import { cveRecords, reportFeeds, reportPages, serveReports } from './helpers/fixtures';
import { applyPatches } from '../src/ingest/apply';
import { parseCveRecord } from '../src/ingest/sources/cve-record';
import { matchStack } from '../src/match/match';
import { parseStack } from '../src/stack/format';

const NOW = new Date('2026-10-22T12:00:00Z');
const PHP = ['CVE-2026-109618', 'CVE-2026-109619'];
const feeds = reportFeeds as Record<string, { etag: string | null; body: string }>;
const pages = reportPages as Record<string, string>;

beforeEach(resetDb);

/** RSS around some items, as the sources write it. */
const rss = (...items: string[]) => `<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>${items.join('')}</channel></rss>`;
const item = (title: string, link: string, date: string, body = '') =>
  `<item><title><![CDATA[${title}]]></title><link>${link}</link><pubDate>${date}</pubDate><description><![CDATA[${body}]]></description></item>`;

describe('reading a feed', () => {
  it('reads items, unwrapping CDATA and unescaping links, in linear passes', () => {
    const xml = rss(
      item('CVE-2026-0001 in <b>X</b>', 'https://www.huntress.com/blog/a?x=1&amp;y=2', 'Wed, 21 Oct 2026 15:22:52 GMT', 'about cve-2026-0002'),
      '<item><title>No link</title><linkedin>https://evil.example</linkedin></item>',
      '<items>not an item</items>',
    );
    expect(parseFeed(xml)).toEqual([
      { title: 'CVE-2026-0001 in <b>X</b>', link: 'https://www.huntress.com/blog/a?x=1&y=2', date: 'Wed, 21 Oct 2026 15:22:52 GMT', summary: 'about cve-2026-0002', text: 'about cve-2026-0002\n' },
      { title: 'No link', link: null, date: null, summary: '', text: '\n' },
    ]);
    // An unclosed item ends the list; hostile input is just text.
    expect(parseFeed(`${rss(item('a', 'https://x', 'd'))}<item><title>`)).toHaveLength(1);
    expect(parseFeed('<item'.repeat(50_000))).toEqual([]);
  });

  it('finds CVE IDs in any case, once each, and no longer than seven digits', () => {
    expect(cveIdsIn('cve-2026-109618 and CVE-2026-109619, again CVE-2026-109618; CVE-2026-123456789 xCVE-2026-1234')).toEqual(PHP);
  });

  it('keeps only https links on the source’s own host', () => {
    expect(sourceLink('https://www.rapid7.com/blog/post/x/', 'rapid7.com')).toBe('https://www.rapid7.com/blog/post/x/');
    expect(sourceLink('https://rapid7.com/x', 'rapid7.com')).toBe('https://rapid7.com/x');
    for (const bad of ['http://www.rapid7.com/x', 'https://rapid7.com.evil.example/x', 'https://notrapid7.com/x', 'https://user@rapid7.com/x', 'https://rapid7.com:8443/x', 'javascript:alert(1)', 'not a url', null]) {
      expect(sourceLink(bad, 'rapid7.com')).toBeNull();
    }
  });

  it('dates posts by UTC day, CERT-EU’s CEST included, and never after today', () => {
    expect(postDay('Wed, 21 Oct 2026 17:20:18 CEST', NOW)).toBe('2026-10-21');
    expect(postDay('Thu, 22 Oct 2026 01:30:00 CEST', NOW)).toBe('2026-10-21');
    expect(postDay('2026-10-21T04:00:00Z', NOW)).toBe('2026-10-21');
    expect(postDay('Wed, 21 Oct 2026 15:22:52 GMT', NOW)).toBe('2026-10-21');
    expect(postDay('Mon, 01 Jan 2029 00:00:00 GMT', NOW)).toBe('2026-10-22');
    expect(postDay('soon', NOW)).toBeNull();
    expect(postDay('Wed, 21 Oct 2026 17:20:18 XYZT', NOW)).toBeNull();
    expect(postDay(null, NOW)).toBeNull();
  });

  it('counts a roundup only for the CVEs in its title', () => {
    const many = Array.from({ length: 12 }, (_, i) => `CVE-2026-${1000 + i}`);
    expect(countedCves('Patch Tuesday', many, 5)).toEqual([]);
    expect(countedCves('CVE-2026-1003 and friends', many, 5)).toEqual(['CVE-2026-1003']);
    expect(countedCves('Two bugs', PHP, 5)).toEqual(PHP);
  });

  it('calls a post urgent on simple keywords in its title or the opening of its summary, never deep in the article', () => {
    // As the sources write their alerts (October 2026 feeds).
    for (const title of [
      'Critical Vulnerabilities in PHP',
      'Active Exploitation of SolarWinds Web Help Desk (CVE-2025-26399)',
      'Wing FTP Server RCE (CVE-2025-47812) Exploited in the Wild | Huntress',
      'Cleo Software Actively Being Exploited in the Wild | Huntress',
      'Ivanti Connect Secure zero-day exploited in the wild (CVE-2026-104935)',
      'Threat Advisory: Hackers Are Exploiting CVE-2021-40444 | Huntress',
      'Fortinet 0-day',
      'Update immediately to 1.2.3',
    ]) {
      expect(isUrgent(title, '')).toBe(true);
    }
    for (const summary of [
      '<p>Two <b>critical</b> PHP RCEs leaked before the patch.</p>',
      'On 9 September 2026, Check Point released emergency security updates addressing two vulnerabilities.',
      'The NCSC is encouraging UK organisations to take immediate action to mitigate a security issue.',
      'Huntress has observed threat actors exploiting a Microsoft Windows Server Update Services (WSUS) vulnerability.',
      'Huntress has observed a series of strikingly similar intrusions beginning with CitrixBleed 2 exploitation.',
    ]) {
      expect(isUrgent('A write-up', summary)).toBe(true);
    }
    // Severity below critical, a keyword only deep in the article, or inside another word: not urgent.
    expect(isUrgent('High Vulnerability in the Linux Kernel', '')).toBe(false);
    expect(isUrgent('Q3 threat update', `${'quiet words '.repeat(60)} a critical bug`)).toBe(false);
    expect(isUrgent('Hypercritical thinking', '')).toBe(false);
    // Disclosures say what could happen; "exploit" on its own isn't an alert.
    expect(isUrgent('Unauthenticated SQL Injection In Channel Software WebAlliance eCommerce', 'An unauthenticated attacker can exploit this to read the database.')).toBe(false);
    expect(isUrgent('Authentication Bypass, Remote Code Execution, and Database Read in Eptura Archibus (FIXED)', 'These could be exploited to take over the server.')).toBe(false);
    expect(isUrgent('A proof-of-concept exploit for CVE-2026-0001', '')).toBe(false);
  });

  it('keeps a title as short plain text: no tags, entities decoded, hidden characters dropped', () => {
    expect(plainTitle('<b>Rapid Response:</b> php2shell &amp; friends')).toBe('Rapid Response: php2shell & friends');
    expect(plainTitle('a'+String.fromCharCode(0x202e)+'b'+String.fromCharCode(0)+'c   d')).toBe('abc d');
    expect(plainTitle('x'.repeat(500))).toHaveLength(MAX_TITLE_CHARS);
    expect(plainTitle('<i></i>  ')).toBeNull();
  });

  it('reads CERT-EU’s JSON for its text, and a page as it is', () => {
    const json = pages['https://cert.europa.eu/publications/security-advisories/2026-018/json']!;
    expect(cveIdsIn(pageText(json))).toEqual(PHP);
    expect(pageText('<p>CVE-2026-0001</p>')).toBe('<p>CVE-2026-0001</p>');
    expect(pageText('{not json')).toBe('');
  });
});

describe('refreshReports', () => {
  const upstream = (overrides: Record<string, string | Response> = {}) => serveReports(new FakeFetch(), overrides);
  const stored = () =>
    rows<{ cve_id: string; source: string; kind: string; url: string; published_at: string; title: string | null }>("SELECT cve_id, source, kind, url, published_at, title FROM exploits WHERE kind IN ('report', 'urgent') ORDER BY cve_id, source");

  it('records which sources wrote up PHP2Shell, with each post and its day', async () => {
    const report = await refreshReports(sourceContext(upstream().fetch, NOW));
    expect(report.errors).toEqual([]);
    expect(report.status).toBe('ok');
    const php = (await stored()).filter((r) => PHP.includes(r.cve_id));
    for (const id of PHP) {
      expect(php.filter((r) => r.cve_id === id).map((r) => r.source)).toEqual(['cert_eu', 'huntress', 'ncsc_uk', 'rapid7']);
    }
    expect(php.find((r) => r.source === 'cert_eu')).toMatchObject({ url: 'https://cert.europa.eu/publications/security-advisories/2026-018/', published_at: '2026-10-21' });
    expect(php.every((r) => r.published_at === '2026-10-21' && r.url.startsWith('https://'))).toBe(true);
    expect(php.find((r) => r.source === 'cert_eu')).toMatchObject({ title: '2026-018: Critical Vulnerabilities in PHP' });
    // Every one of them called it critical or urgent.
    expect(php.every((r) => r.kind === 'urgent')).toBe(true);
    // A watchTowr post naming more than five CVEs counts only for those in its title.
    const tower = new Set((await stored()).filter((r) => r.source === 'watchtowr').map((r) => r.cve_id));
    const posts = parseFeed(feeds.watchtowr!.body).map((i) => ({ title: cveIdsIn(i.title), all: cveIdsIn(`${i.title}
${i.text}`) }));
    const long = posts.find((p) => p.all.length > 5)!;
    const short = new Set(posts.filter((p) => p.all.length <= 5).flatMap((p) => p.all));
    for (const id of long.title) expect(tower.has(id)).toBe(true);
    for (const id of long.all.filter((id) => !long.title.includes(id) && !short.has(id) && !posts.some((p) => p.title.includes(id)))) expect(tower.has(id)).toBe(false);
    expect(long.all.length).toBeGreaterThan(long.title.length);
    expect(await getMeta(store(), REPORTS_STATUS_KEY)).toMatchObject({ lastSuccessAt: NOW.toISOString(), lastError: null });
  });

  it('asks conditionally next time; unchanged feeds and read pages cost one request each', async () => {
    await refreshReports(sourceContext(upstream().fetch, NOW));
    const second = upstream();
    const before = await stored();
    const report = await refreshReports(sourceContext(second.fetch, new Date(NOW.getTime() + 3_600_000)));
    expect(await stored()).toEqual(before);
    // A feed without an ETag is fetched in full, but its pages aren't read again.
    expect(second.urls().filter((u) => !REPORT_SOURCES.some((s) => s.feed === u))).toEqual([]);
    expect(report.pages).toBe(0);
  });

  it('keeps the earliest post per source and CVE', async () => {
    const huntress = REPORT_SOURCES.find((s) => s.id === 'huntress')!;
    const later = rss(item('CVE-2026-109618 follow-up', 'https://www.huntress.com/blog/later', 'Fri, 30 Oct 2026 10:00:00 GMT'));
    const earlier = rss(item('CVE-2026-109618 early', 'https://www.huntress.com/blog/early', 'Mon, 19 Oct 2026 10:00:00 GMT'));
    const ctx = (body: string) => sourceContext(upstream({ huntress: body }).fetch, new Date('2026-11-01T00:00:00Z'));
    await refreshReports(ctx(feeds.huntress!.body), [huntress]);
    await refreshReports(ctx(later), [huntress]);
    await refreshReports(ctx(earlier), [huntress]);
    expect((await stored()).find((r) => r.cve_id === 'CVE-2026-109618')).toMatchObject({ url: 'https://www.huntress.com/blog/early', published_at: '2026-10-19' });
  });

  it('marks a source’s row urgent once any of its posts is, keeping its earliest post', async () => {
    const rapid7 = REPORT_SOURCES.find((s) => s.id === 'rapid7')!;
    const at = new Date('2026-11-01T00:00:00Z');
    const quiet = rss(item('Notes on CVE-2026-0005', 'https://www.rapid7.com/blog/notes', 'Mon, 19 Oct 2026 10:00:00 GMT'));
    const loud = rss(item('CVE-2026-0005: Critical RCE, patch now', 'https://www.rapid7.com/blog/loud', 'Fri, 30 Oct 2026 10:00:00 GMT'));
    await refreshReports(sourceContext(upstream({ rapid7: quiet }).fetch, at), [rapid7]);
    expect((await stored())[0]).toMatchObject({ kind: 'report' });
    await refreshReports(sourceContext(upstream({ rapid7: loud }).fetch, at), [rapid7]);
    expect((await stored())[0]).toMatchObject({ kind: 'urgent', url: 'https://www.rapid7.com/blog/notes', published_at: '2026-10-19' });
    // A quiet post later never takes urgency away.
    await refreshReports(sourceContext(upstream({ rapid7: quiet }).fetch, at), [rapid7]);
    expect((await stored())[0]).toMatchObject({ kind: 'urgent' });
  });

  it('drops posts linking off the source’s host, and ones too old to matter', async () => {
    const rapid7 = REPORT_SOURCES.find((s) => s.id === 'rapid7')!;
    const body = rss(
      item('CVE-2026-0001', 'https://evil.example/rapid7', 'Wed, 21 Oct 2026 10:00:00 GMT'),
      item('CVE-2026-0002', 'https://www.rapid7.com/blog/old', 'Wed, 01 Jan 2025 10:00:00 GMT'),
      item('CVE-2026-0003', 'https://www.rapid7.com/blog/new', 'Wed, 21 Oct 2026 10:00:00 GMT'),
    );
    await refreshReports(sourceContext(upstream({ rapid7: body }).fetch, NOW), [rapid7]);
    expect((await stored()).map((r) => r.cve_id)).toEqual(['CVE-2026-0003']);
  });

  it('keeps the other sources working when one fails, is too big or holds no items', async () => {
    for (const bad of [new Response('down', { status: 503 }), 'x'.repeat(MAX_FEED_CHARS + 1), '<html>not a feed</html>']) {
      await resetDb();
      const report = await refreshReports(sourceContext(upstream({ rapid7: bad }).fetch, NOW));
      expect(report.status).toBe('error');
      expect(report.errors).toHaveLength(1);
      expect(report.errors[0]).toMatch(/^Rapid7: /);
      const sources = new Set((await stored()).map((r) => r.source));
      expect(sources.has('rapid7')).toBe(false);
      expect(sources.has('huntress')).toBe(true);
      expect(await getMeta(store(), REPORTS_STATUS_KEY)).toMatchObject({ lastError: report.errors[0], lastErrorAt: NOW.toISOString() });
    }
  });

  it('reads a page it couldn’t get last time, instead of trusting the 304', async () => {
    const cert = REPORT_SOURCES.find((s) => s.id === 'cert_eu')!;
    const php = 'https://cert.europa.eu/publications/security-advisories/2026-018/json';
    const down = upstream().on(php, () => new Response('busy', { status: 503 }));
    // FakeFetch takes the first route that matches, so the outage goes first.
    const outage = new FakeFetch().on(php, () => new Response('busy', { status: 503 }));
    for (const s of REPORT_SOURCES) outage.on(s.feed, (req) => down.fetch(req));
    outage.on(/^https:\/\//, (req) => down.fetch(req));
    await refreshReports(sourceContext(outage.fetch, NOW), [cert]);
    expect((await stored()).some((r) => r.cve_id === PHP[0])).toBe(false);
    expect((await getMeta<ReportCursor>(store(), reportsCursorKey('cert_eu')))?.etag).toBeNull();
    await refreshReports(sourceContext(upstream().fetch, NOW), [cert]);
    expect((await stored()).filter((r) => r.cve_id === PHP[0]).map((r) => r.source)).toEqual(['cert_eu']);
  });

  it('reads only NCSC UK news about a vulnerability, never its guidance pages', async () => {
    const ncsc = REPORT_SOURCES.find((s) => s.id === 'ncsc_uk')!;
    const f = upstream();
    await refreshReports(sourceContext(f.fetch, NOW), [ncsc]);
    expect(f.urls().filter((u) => u !== ncsc.feed)).toEqual([]);
    expect((await stored()).map((r) => r.cve_id)).toEqual(PHP);
  });

  it('fetches nothing before migration 0014, and says why', async () => {
    const real = store();
    const noColumn: Store = {
      ...real,
      all: async (sql, params) => {
        if (sql === REPORTS_PROBE_SQL) throw new Error('no such column: published_at');
        return real.all(sql, params);
      },
      batch: (s) => real.batch(s),
    };
    const f = upstream();
    const report = await refreshReports(sourceContext(f.fetch, NOW, { store: noColumn }));
    expect(f.calls).toHaveLength(0);
    expect(report).toMatchObject({ status: 'error', errors: ['no exploits.published_at column; apply migration 0014'] });
  });

  it('probes for the column only until a run has stored a cursor', async () => {
    const real = store();
    const sql: string[] = [];
    const counting: Store = { all: async (q, p) => (sql.push(q), real.all(q, p)), batch: (s) => real.batch(s) };
    await refreshReports(sourceContext(upstream().fetch, NOW, { store: counting }));
    expect(sql.filter((q) => q === REPORTS_PROBE_SQL)).toHaveLength(1);
    sql.length = 0;
    await refreshReports(sourceContext(upstream().fetch, new Date(NOW.getTime() + 3_600_000), { store: counting }));
    // The status and every cursor in one query, and nothing else.
    expect(sql).toHaveLength(1);
  });
});

describe('PHP2Shell, end to end', () => {
  it('ranks Act now within 3 days from the recorded write-ups, with links to them', async () => {
    const patch = parseCveRecord(cveRecords['CVE-2026-109618']!)!;
    await applyPatches(store(), [patch], { now: NOW, windowStart: '2026-07-24T00:00:00.000Z', epssEvents: true });
    const stack = parseStack('p:php_group/php@8.3.10');
    const match = () => matchStack(store(), stack, { now: NOW, days: 30, osv: { affecting: async () => new Map() } });

    const before = (await match()).results[0]!;
    expect(before).toMatchObject({ id: 'CVE-2026-109618', priority: 'attend', fixedVersions: ['8.3.36'], links: { reports: [] } });

    await refreshReports(sourceContext(serveReports(new FakeFetch()).fetch, NOW));
    const after = (await match()).results[0]!;
    expect(after).toMatchObject({ priority: 'act', respondWithinHours: 72 });
    expect(after.why.decisive!.text).toMatch(/^Critical bug reported by .+: Act now while EPSS and CISA catch up$/);
    expect(after.links.reports).toHaveLength(4);
    expect(after.links.reports.every((u) => u.startsWith('https://'))).toBe(true);
    expect(after.reports.map((r) => r.source).sort()).toEqual(['CERT-EU', 'Huntress', 'NCSC UK', 'Rapid7']);
    expect(after.reports.find((r) => r.source === 'NCSC UK')).toMatchObject({ title: 'Critical security issue affecting PHP', publishedAt: '2026-10-21', urgent: true });
  });
});

describe('hostile feeds', () => {
  const PIECES = ['<item>', '</item>', '<item ', '<title>', '</title>', '<link>', '</link>', '<pubDate>', '</pubDate>', '<description>', '</description>', '<![CDATA[', ']]>', '&amp;', '&#x41;', '&#0;', 'CVE-2026-109618', 'https://www.rapid7.com/x', 'javascript:alert(1)', 'critical', '<', '>', '"'];
  const piece = fc.oneof({ weight: 4, arbitrary: fc.constantFrom(...PIECES) }, { weight: 1, arbitrary: fc.string({ unit: 'binary', maxLength: 24 }) });
  const feed = fc.array(piece, { maxLength: 80 }).map((p) => p.join(''));

  it('parses anything without throwing, keeping only https links on the host and real CVE IDs', () => {
    fc.assert(
      fc.property(feed, (xml) => {
        for (const i of parseFeed(xml)) {
          const link = sourceLink(i.link, 'rapid7.com');
          if (link !== null) expect(new URL(link)).toMatchObject({ protocol: 'https:' });
          for (const id of cveIdsIn(`${i.title}\n${i.text}`)) expect(id).toMatch(/^CVE-\d{4}-\d{4,7}$/);
          expect(typeof isUrgent(i.title, i.summary)).toBe('boolean');
          postDay(i.date, NOW);
        }
      }),
      { numRuns: 500 },
    );
  });
});
