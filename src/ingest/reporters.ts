/**
 * Trusted sources whose write-ups of a CVE count toward "reported"
 * (src/ingest/reports.ts, src/match/priority.ts). A short fixed list,
 * chosen by hand: each writes up only what matters, publishes RSS, and covered
 * PHP2Shell (CVE-2026-109618/9) within a day, apart from watchTowr, whose
 * research posts come later and fewer. Adding one is an entry here and a
 * recorded fixture; it never needs a model or a search API.
 *
 * Coverage is never evidence of exploitation, even when a post says so: only
 * CISA KEV and CISA reporting active exploitation are.
 */
export interface ReportSource {
  /** Stored as `exploits.source`; never 'metasploit' or 'nuclei'. */
  id: string;
  /** As reasons name it: "Reported by Huntress, Rapid7 and CERT-EU". */
  name: string;
  feed: string;
  /** Item links must be https on this host or a subdomain of it. */
  host: string;
  /**
   * For a feed that doesn't name CVE IDs: the item's page is fetched once, when
   * its title passes `when`, and read for them. `url` turns the item's link into
   * the page to read (CERT-EU's JSON).
   */
  page?: { when: RegExp; url: (link: string) => string };
  /** A post naming more CVEs than this counts only for those in its title (a Patch Tuesday roundup counts for none). */
  maxCves: number;
}

export const REPORT_SOURCES: readonly ReportSource[] = [
  { id: 'huntress', name: 'Huntress', feed: 'https://www.huntress.com/blog/rss.xml', host: 'huntress.com', maxCves: 5 },
  { id: 'rapid7', name: 'Rapid7', feed: 'https://www.rapid7.com/blog/rss/', host: 'rapid7.com', maxCves: 5 },
  { id: 'watchtowr', name: 'watchTowr', feed: 'https://labs.watchtowr.com/rss/', host: 'labs.watchtowr.com', maxCves: 5 },
  {
    id: 'cert_eu',
    name: 'CERT-EU',
    feed: 'https://cert.europa.eu/publications/security-advisories-rss',
    host: 'cert.europa.eu',
    // Every security advisory is about vulnerabilities; the feed names products only.
    page: { when: /./, url: (link) => `${link.replace(/\/+$/, '')}/json` },
    maxCves: 10,
  },
  {
    id: 'ncsc_uk',
    name: 'NCSC UK',
    feed: 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml',
    host: 'ncsc.gov.uk',
    // Most of the feed is guidance and blogs; only news of a vulnerability is read.
    page: { when: /vulnerabilit|exploit|security issue/i, url: (link) => link },
    maxCves: 10,
  },
];

const BY_ID = new Map(REPORT_SOURCES.map((s) => [s.id, s]));

/** The source for an `exploits.source` value, if it's one of these. */
export function reportSource(id: string): ReportSource | undefined {
  return BY_ID.get(id);
}
