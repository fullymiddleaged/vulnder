import { strToU8, zipSync } from 'fflate';
import { REPORT_SOURCES } from '../../src/ingest/reporters';
import cve2002_0192 from '../fixtures/cve/records/CVE-2002-0192.json';
import cve2022_48816 from '../fixtures/cve/records/CVE-2022-48816.json';
import cve2023_0884 from '../fixtures/cve/records/CVE-2023-0884.json';
import cve2024_0228 from '../fixtures/cve/records/CVE-2024-0228.json';
import cve2024_34393 from '../fixtures/cve/records/CVE-2024-34393.json';
import cve2025_0020 from '../fixtures/cve/records/CVE-2025-0020.json';
import cve2025_0167 from '../fixtures/cve/records/CVE-2025-0167.json';
import cve2025_0168 from '../fixtures/cve/records/CVE-2025-0168.json';
import cve2025_12828 from '../fixtures/cve/records/CVE-2025-12828.json';
import cve2026_100107 from '../fixtures/cve/records/CVE-2026-100107.json';
import cve2026_100148 from '../fixtures/cve/records/CVE-2026-100148.json';
import cve2026_104886 from '../fixtures/cve/records/CVE-2026-104886.json';
import cve2026_104910 from '../fixtures/cve/records/CVE-2026-104910.json';
import cve2026_109618 from '../fixtures/cve/records/CVE-2026-109618.json';
import releases from '../fixtures/cve/releases.json';
import epssLatest from '../fixtures/epss/latest.json';
import epssScores from '../fixtures/epss/scores.json';
import ghsaPage from '../fixtures/ghsa/page.json';
import kevFeed from '../fixtures/kev/feed.json';
// endoflife.date's /api/v1/products/full, cut down to the products src/stack/eol.ts maps and one it doesn't (nginx).
import eolFull from '../fixtures/eol/full.json';
// Metasploit's module index and Nuclei's cves.json, cut to a few real entries (scripts/record-fixtures.ts --exploits).
import metasploitIndex from '../fixtures/exploits/metasploit.json';
import nucleiIndex from '../fixtures/exploits/nuclei.json';
// Each trusted source's RSS feed cut to its newest items, and the pages read for CVE IDs (scripts/record-fixtures.ts --reports).
import reportFeeds from '../fixtures/reports/feeds.json';
import reportPages from '../fixtures/reports/pages.json';

export type CveRecordJson = { cveMetadata: { cveId: string; dateUpdated: string; datePublished?: string; state: string } };

export const cveRecords: Record<string, CveRecordJson> = {
  // Rejected: a duplicate, a reservation duplicate, the old ConsultIDs form with two, and one pointing nowhere.
  'CVE-2002-0192': cve2002_0192 as CveRecordJson,
  'CVE-2023-0884': cve2023_0884 as CveRecordJson,
  'CVE-2024-0228': cve2024_0228 as CveRecordJson,
  'CVE-2025-0020': cve2025_0020 as CveRecordJson,
  // Exploit-tagged references: in the CNA's list, and only in CISA-ADP's.
  'CVE-2025-0168': cve2025_0168 as CveRecordJson,
  'CVE-2025-0167': cve2025_0167 as CveRecordJson,
  'CVE-2022-48816': cve2022_48816 as CveRecordJson,
  'CVE-2024-34393': cve2024_34393 as CveRecordJson,
  'CVE-2025-12828': cve2025_12828 as CveRecordJson,
  'CVE-2026-100107': cve2026_100107 as CveRecordJson,
  'CVE-2026-100148': cve2026_100148 as CveRecordJson,
  'CVE-2026-104886': cve2026_104886 as CveRecordJson,
  'CVE-2026-104910': cve2026_104910 as CveRecordJson,
  // PHP: fixed on four release branches.
  'CVE-2026-109618': cve2026_109618 as CveRecordJson,
};

export { eolFull, epssLatest, epssScores, ghsaPage, kevFeed, metasploitIndex, nucleiIndex, releases, reportFeeds, reportPages };

/** The recorded Metasploit index as its file's text. */
export const metasploitBody = () => JSON.stringify(metasploitIndex.body);
/** The recorded Nuclei lines as cves.json's text. */
export const nucleiBody = () => `${nucleiIndex.lines.join('\n')}\n`;

/** A delta zip laid out like cvelistV5's (deltaCves/CVE-*.json), built from recorded records. */
export function deltaZip(records: CveRecordJson[]): Uint8Array {
  const files: Record<string, Uint8Array> = {};
  for (const r of records) files[`deltaCves/${r.cveMetadata.cveId}.json`] = strToU8(JSON.stringify(r));
  return zipSync(files);
}

/**
 * A deep copy whose CISA-ADP SSVC assessment says `exploitation`, dated
 * `timestamp`, optionally with a KEV entry in the same container. The record
 * must have a CISA-ADP SSVC metric already (CVE-2022-48816 does).
 */
export function withSsvc(record: CveRecordJson, exploitation: string, timestamp: string, kev = false): CveRecordJson {
  type Metric = { other?: { type?: string; content?: { options?: Record<string, string>[]; timestamp?: string } } };
  type Adp = { providerMetadata?: { shortName?: string }; metrics?: Metric[] };
  const copy = structuredClone(record) as CveRecordJson & { containers: { adp: Adp[] } };
  const cisa = copy.containers.adp.find((a) => a.providerMetadata?.shortName === 'CISA-ADP')!;
  const ssvc = cisa.metrics!.find((m) => m.other?.type === 'ssvc')!.other!.content!;
  ssvc.options = ssvc.options!.map((o) => ('Exploitation' in o ? { Exploitation: exploitation } : o));
  ssvc.timestamp = timestamp;
  if (kev) cisa.metrics!.push({ other: { type: 'kev', content: { timestamp } } });
  return copy;
}

/** A deep copy with cveMetadata overrides, for shaping test scenarios. */
export function withMeta(record: CveRecordJson, meta: Partial<CveRecordJson['cveMetadata']>): CveRecordJson {
  const copy = structuredClone(record);
  Object.assign(copy.cveMetadata, meta);
  return copy;
}

/**
 * Serves the recorded trusted-source feeds (answering 304 to a matching
 * If-None-Match) and their recorded pages; any other page is a 404.
 */
export function serveReports<F extends { on(match: string | RegExp, handler: (req: Request) => Response): F }>(f: F, overrides: Record<string, string | Response> = {}): F {
  const feeds = reportFeeds as Record<string, { etag: string | null; body: string }>;
  const pages = reportPages as Record<string, string>;
  for (const src of REPORT_SOURCES) {
    const etag = feeds[src.id]!.etag ?? `"${src.id}-1"`;
    f.on(src.feed, (req) => {
      const o = overrides[src.id];
      if (o instanceof Response) return o.clone();
      if (o === undefined && req.headers.get('if-none-match') === etag) return new Response(null, { status: 304 });
      return new Response(o ?? feeds[src.id]!.body, { headers: { etag } });
    });
  }
  return f.on(/^https:\/\/(cert\.europa\.eu|www\.ncsc\.gov\.uk)\//, (req) => (req.url in pages ? new Response(pages[req.url]) : new Response('gone', { status: 404 })));
}
