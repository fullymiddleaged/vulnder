import { EPSS_HIGH } from '../config';
import { addDays } from '../lib/time';
import { allForKeys, type Store } from '../ingest/store';
import type { Ref, Ssvc } from '../ingest/types';
import { formatItem, type StackItem } from '../stack/format';
import { queryKey, type OsvClient, type OsvQuery } from './osv';

/**
 * Matches a confirmed stack against stored vulnerabilities.
 *
 * Tiers come from exploitation signals only: KEV is "exploited", EPSS at or
 * above 0.10 is "likely", everything else is "backlog". CVSS is shown but never
 * used to rank.
 *
 * Confidence:
 * - "version_confirmed": a package version was given and OSV says it is affected;
 * - "product_match": the product is named but its version is unknown or could
 *   not be checked.
 * A versioned package that OSV checked and found unaffected is dropped. Only
 * package rows from GitHub advisories are checked this way, because GitHub
 * advisories are always in OSV; for other rows a missing OSV result would not
 * mean "not affected".
 */

export type Tier = 'exploited' | 'likely' | 'backlog';
export type Confidence = 'version_confirmed' | 'product_match';

export interface MatchedVuln {
  id: string;
  aliases: string[];
  title: string | null;
  summary: string | null;
  publishedAt: string | null;
  modifiedAt: string | null;
  tier: Tier;
  evidence: {
    kevAddedAt: string | null;
    kevDueDate: string | null;
    knownRansomware: boolean;
    epss: number | null;
    epssPercentile: number | null;
    epssDate: string | null;
  };
  confidence: Confidence;
  /** Stack items (canonical form) that matched. */
  matched: string[];
  fixedVersions: string[];
  cvss: { score: number; vector: string | null } | null;
  cwe: string[];
  ssvc: Ssvc | null;
  links: { advisory: string | null; patch: string | null };
}

export interface ChangeEvent {
  vulnId: string;
  type: 'published' | 'kev_added' | 'epss_crossed' | 'fix_released';
  occurredAt: string;
  detail: Record<string, unknown>;
}

export interface MatchResult {
  results: MatchedVuln[];
  /** Items with nothing in the window: still watched by the feed. */
  watching: string[];
  /** True when OSV could not be reached and versions went unchecked. */
  versionCheckUnavailable: boolean;
}

export interface MatchOptions {
  now: Date;
  days: number;
  osv: OsvClient;
}

interface AffectedRow {
  vuln_id: string;
  source: string;
  kind: 'package' | 'product';
  ecosystem: string | null;
  package_name: string | null;
  vendor: string | null;
  product: string | null;
  fixed_version: string | null;
}

interface VulnRow {
  id: string;
  aliases: string;
  title: string | null;
  summary: string | null;
  published_at: string | null;
  modified_at: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  cwe: string;
  epss: number | null;
  epss_percentile: number | null;
  epss_date: string | null;
  kev_added_at: string | null;
  kev_ransomware: number;
  kev_due_date: string | null;
  ssvc: string | null;
  refs: string;
}

const TIER_RANK: Record<Tier, number> = { exploited: 0, likely: 1, backlog: 2 };

const itemKey = (item: StackItem) =>
  item.kind === 'package' ? `pkg:${item.ecosystem}:${item.name}` : `prod:${item.vendor}/${item.product}`;
const rowKey = (r: AffectedRow) => (r.kind === 'package' ? `pkg:${r.ecosystem}:${r.package_name}` : `prod:${r.vendor}/${r.product}`);

export async function matchStack(store: Store, items: StackItem[], opts: MatchOptions): Promise<MatchResult> {
  const since = addDays(opts.now, -opts.days).toISOString();
  const byKey = new Map<string, StackItem[]>();
  for (const item of items) {
    const k = itemKey(item);
    if (!byKey.has(k)) byKey.set(k, []);
    byKey.get(k)!.push(item);
  }

  // 1. Affected rows for every stack item.
  const packages = items.filter((i) => i.kind === 'package').map((i) => [i.ecosystem, i.name]);
  const products = items.filter((i) => i.kind === 'product').map((i) => [i.vendor, i.product]);
  const affected: AffectedRow[] = [];
  const cols = 'vuln_id, source, kind, ecosystem, package_name, vendor, product, fixed_version';
  if (packages.length > 0) {
    affected.push(
      ...(await store.all<AffectedRow>(
        `SELECT ${cols} FROM affected WHERE kind = 'package'
         AND (ecosystem, package_name) IN (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?))`,
        [JSON.stringify(packages)],
      )),
    );
  }
  if (products.length > 0) {
    affected.push(
      ...(await store.all<AffectedRow>(
        `SELECT ${cols} FROM affected WHERE kind = 'product'
         AND (vendor, product) IN (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?))`,
        [JSON.stringify(products)],
      )),
    );
  }

  // 2. The vulns among those that are inside the window.
  const vulnRows = await allForKeys<VulnRow>(
    store,
    `SELECT id, aliases, title, summary, published_at, modified_at, cvss_score, cvss_vector, cwe, epss, epss_percentile,
            epss_date, kev_added_at, kev_ransomware, kev_due_date, ssvc, refs
     FROM vulns WHERE id IN (SELECT value FROM json_each(?))
       AND (published_at >= '${since}' OR last_event_at >= '${since}')`,
    affected.map((a) => a.vuln_id),
  );
  const vulns = new Map(vulnRows.map((v) => [v.id, v]));
  const rowsByVuln = new Map<string, AffectedRow[]>();
  for (const a of affected) {
    if (!vulns.has(a.vuln_id)) continue;
    if (!rowsByVuln.has(a.vuln_id)) rowsByVuln.set(a.vuln_id, []);
    rowsByVuln.get(a.vuln_id)!.push(a);
  }

  // 3. Check versioned packages against OSV, only where there is something to check.
  const queries: OsvQuery[] = [];
  for (const rows of rowsByVuln.values()) {
    for (const r of rows) {
      if (r.kind !== 'package' || r.source !== 'ghsa') continue;
      for (const item of byKey.get(rowKey(r)) ?? []) {
        if (item.kind === 'package' && item.version) queries.push({ ecosystem: item.ecosystem, name: item.name, version: item.version });
      }
    }
  }
  let osvResults: Map<string, Set<string>> | null = null;
  let versionCheckUnavailable = false;
  if (queries.length > 0) {
    try {
      osvResults = await opts.osv.affecting(queries);
    } catch {
      versionCheckUnavailable = true;
    }
  }

  // 4. Decide confidence per vuln.
  const results: MatchedVuln[] = [];
  const matchedItems = new Set<string>();
  for (const [vulnId, rows] of rowsByVuln) {
    const v = vulns.get(vulnId)!;
    const ids = new Set([v.id, ...parseJson<string[]>(v.aliases, [])]);
    let confirmed = false;
    let unverified = false;
    const matched = new Set<string>();
    const fixes = new Set<string>();

    for (const r of rows) {
      for (const item of byKey.get(rowKey(r)) ?? []) {
        if (item.kind === 'package' && item.version && r.source === 'ghsa' && osvResults) {
          const affecting = osvResults.get(queryKey({ ecosystem: item.ecosystem, name: item.name, version: item.version }));
          if (affecting && [...affecting].some((id) => ids.has(id))) {
            confirmed = true;
            matched.add(formatItem(item));
            if (r.fixed_version) fixes.add(r.fixed_version);
          }
          // Checked and not affected: this row does not count as a match.
          continue;
        }
        unverified = true;
        matched.add(formatItem(item));
        if (r.fixed_version) fixes.add(r.fixed_version);
      }
    }
    if (!confirmed && !unverified) continue;
    for (const m of matched) matchedItems.add(m);
    results.push(toResult(v, confirmed ? 'version_confirmed' : 'product_match', [...matched].sort(), [...fixes].sort()));
  }

  results.sort(compareResults);
  const watching = items.map(formatItem).filter((f) => !matchedItems.has(f));
  return { results, watching, versionCheckUnavailable };
}

/** Change events for these vulns since a given time, newest first. */
export async function changesFor(store: Store, vulnIds: string[], since: string): Promise<ChangeEvent[]> {
  const rows = await allForKeys<{ vuln_id: string; type: ChangeEvent['type']; occurred_at: string; detail: string }>(
    store,
    `SELECT vuln_id, type, occurred_at, detail FROM events
     WHERE vuln_id IN (SELECT value FROM json_each(?)) AND occurred_at >= '${since}'`,
    vulnIds,
  );
  return rows
    .map((r) => ({ vulnId: r.vuln_id, type: r.type, occurredAt: r.occurred_at, detail: parseJson<Record<string, unknown>>(r.detail, {}) }))
    .sort((a, b) => (a.occurredAt === b.occurredAt ? a.vulnId.localeCompare(b.vulnId) : b.occurredAt.localeCompare(a.occurredAt)));
}

export function tierOf(v: { kev_added_at: string | null; epss: number | null }): Tier {
  if (v.kev_added_at) return 'exploited';
  if (v.epss !== null && v.epss >= EPSS_HIGH - 1e-9) return 'likely';
  return 'backlog';
}

function toResult(v: VulnRow, confidence: Confidence, matched: string[], fixedVersions: string[]): MatchedVuln {
  const refs = parseJson<Ref[]>(v.refs, []);
  return {
    id: v.id,
    aliases: parseJson<string[]>(v.aliases, []),
    title: v.title,
    summary: v.summary,
    publishedAt: v.published_at,
    modifiedAt: v.modified_at,
    tier: tierOf(v),
    evidence: {
      kevAddedAt: v.kev_added_at,
      kevDueDate: v.kev_due_date,
      knownRansomware: v.kev_ransomware === 1,
      epss: v.epss,
      epssPercentile: v.epss_percentile,
      epssDate: v.epss_date,
    },
    confidence,
    matched,
    fixedVersions,
    cvss: v.cvss_score !== null ? { score: v.cvss_score, vector: v.cvss_vector } : null,
    cwe: parseJson<string[]>(v.cwe, []),
    ssvc: v.ssvc ? parseJson<Ssvc | null>(v.ssvc, null) : null,
    links: pickLinks(v.id, refs),
  };
}

/**
 * The advisory and patch links to show. Prefers the vendor or GitHub advisory
 * and a commit or release link; NVD is only a last resort for the advisory.
 */
export function pickLinks(id: string, refs: Ref[]): { advisory: string | null; patch: string | null } {
  const isNvd = (u: string) => /(^|\/\/)nvd\.nist\.gov\//.test(u);
  const tagged = (tag: string) => refs.find((r) => r.tags?.some((t) => t.toLowerCase() === tag) && !isNvd(r.url))?.url ?? null;
  const advisory =
    tagged('advisory') ??
    tagged('vendor-advisory') ??
    refs.find((r) => /github\.com\/(advisories|[^/]+\/[^/]+\/security\/advisories)\//.test(r.url))?.url ??
    refs.find((r) => !isNvd(r.url) && !/\/commit\/|\/pull\/|\/releases\/tag\//.test(r.url))?.url ??
    (id.startsWith('CVE-') ? `https://www.cve.org/CVERecord?id=${id}` : null);
  const patch = tagged('patch') ?? refs.find((r) => /\/commit\/[0-9a-f]{7,}|\/pull\/\d+|\/releases\/tag\//.test(r.url))?.url ?? null;
  return { advisory, patch };
}

function compareResults(a: MatchedVuln, b: MatchedVuln): number {
  return (
    TIER_RANK[a.tier] - TIER_RANK[b.tier] ||
    (b.evidence.kevAddedAt ?? '').localeCompare(a.evidence.kevAddedAt ?? '') ||
    (b.evidence.epss ?? 0) - (a.evidence.epss ?? 0) ||
    (b.publishedAt ?? '').localeCompare(a.publishedAt ?? '') ||
    a.id.localeCompare(b.id)
  );
}

function parseJson<T>(text: string | null, fallback: T): T {
  if (!text) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}
