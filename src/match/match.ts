import { EPSS_HIGH } from '../config';
import { lev } from '../lib/lev';
import { addDays } from '../lib/time';
import { allForKeys, type Store } from '../ingest/store';
import { parseSeverityLabel, type Ref, type Ssvc } from '../ingest/types';
import { formatItem, type StackItem } from '../stack/format';
import { FEED_CHUNK, itemKey, loadComponents, rowKey, type AffectedRow, type ComponentCache, type VulnRow } from './components';
import { queryKey, type OsvClient, type OsvQuery } from './osv';
import { assess, comparePriority, fixFirst, type FixItem, type Priority, type Why } from './priority';

/**
 * Matches a confirmed stack against stored vulnerabilities.
 *
 * Tiers come from exploitation signals only: KEV is "exploited", EPSS at or
 * above 0.10 is "likely", everything else is "backlog". Results are ordered by
 * priority and score (priority.ts), which add severity and CISA's SSVC data but
 * never let severity outrank evidence of exploitation.
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
    /** NIST LEV: lower-bound chance it has already been exploited, from EPSS history. */
    lev: number | null;
  };
  confidence: Confidence;
  /** 'exact' when a stack item named it outright; 'close' when only a close match (a '?' item) did. */
  match: 'exact' | 'close';
  /** Stack items (canonical form) that matched. */
  matched: string[];
  fixedVersions: string[];
  cvss: { score: number; vector: string | null } | null;
  cwe: string[];
  ssvc: Ssvc | null;
  links: { advisory: string | null; patch: string | null };
  /** What to do about it: act, attend, watch or track. */
  priority: Priority;
  /** 0–100, for ordering within a priority and ranking components. */
  score: number;
  /** Why it got this priority, most important first. */
  reasons: string[];
  /**
   * Its family's id (similar CVEs in the same product), when this feed shows other members (`related`) or
   * a member is exploited; otherwise null.
   */
  family: string | null;
  /** Other results here in the same family, in feed order. */
  related: string[];
  /** The reasons, structured: the one that decided the band, the rest, and missing data. */
  why: Why;
  /** Suggested time to fix or mitigate, in hours (guidance); null for Track. */
  respondWithinHours: number | null;
  /**
   * For Act now and Attend with no fixed version known: what to do meanwhile
   * (CISA's required action, when on KEV) and where to read more. Null otherwise.
   */
  mitigation: { action: string | null; advisory: string | null } | null;
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
  /** Matched stack items in the order to fix them. */
  fixFirst: FixItem[];
}

export interface MatchOptions {
  now: Date;
  days: number;
  osv: OsvClient;
  /** Components kept between requests; without it, every component is read from D1. */
  components?: ComponentCache;
}

/*
 * Event queries. `since` is an ISO time computed by the caller, never user text.
 * The first searches the vuln_id index per key (test/query-plans.test.ts);
 * the second reads every recent event in time order, which costs less once
 * a stack has more results than there were recent events.
 */
export const eventsSinceSql = (since: string) =>
  `SELECT vuln_id, type, occurred_at, detail FROM events
   WHERE vuln_id IN (SELECT value FROM json_each(?)) AND occurred_at >= '${since}'`;
export const RECENT_EVENTS_SQL = 'SELECT vuln_id, type, occurred_at, detail FROM events WHERE occurred_at >= ?';
/** Events a day across the whole database, generously (about 400 in October 2026). */
const EVENTS_PER_DAY = 500;
/** Rows a per-vuln event lookup reads: the key, the index entry, the row and the next index entry. */
const ROWS_PER_EVENT_LOOKUP = 4;

const inWindow = (v: VulnRow, since: string) => (v.published_at !== null && v.published_at >= since) || (v.last_event_at !== null && v.last_event_at >= since);

export async function matchStack(store: Store, items: StackItem[], opts: MatchOptions): Promise<MatchResult> {
  const since = addDays(opts.now, -opts.days).toISOString();
  const byKey = new Map<string, StackItem[]>();
  for (const item of items) {
    const k = itemKey(item);
    if (!byKey.has(k)) byKey.set(k, []);
    byKey.get(k)!.push(item);
  }

  // 1. Each component's affected rows and vulns (cached per component), and
  // 2. the vulns among those that are inside the window.
  const components = await loadComponents(store, items, opts.components);
  const affected = components.flatMap((d) => d.affected);
  const vulns = new Map(components.flatMap((d) => d.vulns.filter((v) => inWindow(v, since)).map((v) => [v.id, v] as const)));
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

  // Exploited members of these vulns' families (src/ingest/families.ts), in or
  // out of the window: a similar CVE being exploited is a reason to attend to the rest.
  const exploitedIn = new Map<string, Set<string>>();
  for (const r of components.flatMap((d) => d.exploited)) {
    if (!exploitedIn.has(r.family_id)) exploitedIn.set(r.family_id, new Set());
    exploitedIn.get(r.family_id)!.add(r.id);
  }
  const exploitedSibling = (v: VulnRow) =>
    [...(v.family_id ? (exploitedIn.get(v.family_id) ?? []) : [])].filter((id) => id !== v.id).sort()[0] ?? null;

  // 4. Decide confidence per vuln.
  const results: MatchedVuln[] = [];
  const matchedItems = new Set<string>();
  for (const [vulnId, rows] of rowsByVuln) {
    const v = vulns.get(vulnId)!;
    const ids = new Set([v.id, ...parseJson<string[]>(v.aliases, [])]);
    let confirmed = false;
    let unverified = false;
    const matched = new Set<string>();
    let exact = false;
    let exposed = false;
    const fixes = new Set<string>();

    for (const r of rows) {
      for (const item of byKey.get(rowKey(r)) ?? []) {
        if (item.kind === 'package' && item.version && r.source === 'ghsa' && osvResults) {
          const affecting = osvResults.get(queryKey({ ecosystem: item.ecosystem, name: item.name, version: item.version }));
          if (affecting && [...affecting].some((id) => ids.has(id))) {
            confirmed = true;
            matched.add(formatItem(item));
            if (!item.close) exact = true;
            if (item.exposed) exposed = true;
            if (r.fixed_version) fixes.add(r.fixed_version);
          }
          // Checked and not affected: this row does not count as a match.
          continue;
        }
        unverified = true;
        matched.add(formatItem(item));
        if (!item.close) exact = true;
        if (item.exposed) exposed = true;
        if (r.fixed_version) fixes.add(r.fixed_version);
      }
    }
    if (!confirmed && !unverified) continue;
    for (const m of matched) matchedItems.add(m);
    results.push(
      toResult(v, confirmed ? 'version_confirmed' : 'product_match', exact ? 'exact' : 'close', [...matched].sort(), [...fixes].sort(), exposed, opts.now, exploitedSibling(v)),
    );
  }

  results.sort(compareResults);
  linkFamilies(results, (id) => vulns.get(id)?.family_id ?? null);
  const watching = items.map(formatItem).filter((f) => !matchedItems.has(f));
  const ranked = fixFirst(results.map((r) => ({ ...r, assessment: r })));
  return { results, watching, versionCheckUnavailable, fixFirst: ranked };
}

/**
 * Change events for these vulns in the last `days` days (since `since`), newest
 * first. Looked up per vuln, unless reading every recent event would read fewer rows.
 */
export async function changesFor(store: Store, vulnIds: string[], since: string, days: number): Promise<ChangeEvent[]> {
  type Row = { vuln_id: string; type: ChangeEvent['type']; occurred_at: string; detail: string };
  const ids = new Set(vulnIds);
  const rows =
    days * EVENTS_PER_DAY < ids.size * ROWS_PER_EVENT_LOOKUP
      ? (await store.all<Row>(RECENT_EVENTS_SQL, [since])).filter((r) => ids.has(r.vuln_id))
      : await allForKeys<Row>(store, eventsSinceSql(since), [...ids], FEED_CHUNK);
  return rows
    .map((r) => ({ vulnId: r.vuln_id, type: r.type, occurredAt: r.occurred_at, detail: parseJson<Record<string, unknown>>(r.detail, {}) }))
    .sort((a, b) => (a.occurredAt === b.occurredAt ? a.vulnId.localeCompare(b.vulnId) : b.occurredAt.localeCompare(a.occurredAt)));
}

export function tierOf(v: { kev_added_at: string | null; epss: number | null }): Tier {
  if (v.kev_added_at) return 'exploited';
  if (v.epss !== null && v.epss >= EPSS_HIGH - 1e-9) return 'likely';
  return 'backlog';
}

function toResult(
  v: VulnRow,
  confidence: Confidence,
  match: 'exact' | 'close',
  matched: string[],
  fixedVersions: string[],
  exposed: boolean,
  now: Date,
  exploitedSibling: string | null,
): MatchedVuln {
  const refs = parseJson<Ref[]>(v.refs, []);
  const links = pickLinks(v.id, refs);
  const ssvc = v.ssvc ? parseJson<Ssvc | null>(v.ssvc, null) : null;
  const levNow = lev(v.lev_log ?? 0, v.epss, v.epss_date, now);
  const { priority, score, reasons, why, respondWithinHours } = assess({
    kevAddedAt: v.kev_added_at,
    knownRansomware: v.kev_ransomware === 1,
    epss: v.epss,
    lev: levNow,
    exploitedSibling,
    cvss: v.cvss_score,
    cvssVector: v.cvss_vector,
    severityLabel: parseSeverityLabel(v.severity_label),
    exposed,
    ssvc,
  });
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
      lev: levNow === null ? null : Math.round(levNow * 1e4) / 1e4,
    },
    confidence,
    match,
    matched,
    fixedVersions,
    cvss: v.cvss_score !== null ? { score: v.cvss_score, vector: v.cvss_vector } : null,
    cwe: parseJson<string[]>(v.cwe, []),
    ssvc,
    links,
    priority,
    score,
    reasons,
    // A family id only means something next to its siblings: linkFamilies fills these in.
    family: exploitedSibling ? v.family_id : null,
    related: [],
    why,
    respondWithinHours,
    mitigation: mitigationFor(priority, fixedVersions, v.kev_required_action, links.advisory),
  };
}

/**
 * Exploitation now often comes before the patch, so an urgent CVE with no
 * fixed version known needs something to do meanwhile: CISA's required action
 * when it's on KEV, and the advisory. "Known" matters: product records often
 * name no fixed version even when the vendor has shipped one.
 */
export function mitigationFor(
  priority: Priority,
  fixedVersions: string[],
  requiredAction: string | null,
  advisory: string | null,
): { action: string | null; advisory: string | null } | null {
  if ((priority !== 'act' && priority !== 'attend') || fixedVersions.length > 0) return null;
  return { action: requiredAction?.trim() || null, advisory };
}

/**
 * Links results in the same family: `related` lists the others, in
 * feed order, and `family` names it. Nothing is folded away here.
 */
export function linkFamilies(results: MatchedVuln[], familyOf: (id: string) => string | null): void {
  const members = new Map<string, MatchedVuln[]>();
  for (const r of results) {
    const f = familyOf(r.id);
    if (!f) continue;
    if (!members.has(f)) members.set(f, []);
    members.get(f)!.push(r);
  }
  for (const [f, group] of members) {
    if (group.length < 2) continue;
    for (const r of group) {
      r.family = f;
      r.related = group.filter((o) => o !== r).map((o) => o.id);
    }
  }
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
    comparePriority(a, b) ||
    (a.match === b.match ? 0 : a.match === 'exact' ? -1 : 1) ||
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
