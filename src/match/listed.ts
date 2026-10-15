import { CVE_INDEX_BY_ID_SQL } from '../ingest/cve-index';
import { allForKeys, type Store } from '../ingest/store';
import type { Ecosystem } from '../lib/normalize';
import { formatItem, identity, parseStack, PREFIXES, type CveItem } from '../stack/format';
import { EXPLOITED_IN_FAMILIES_SQL, FEED_CHUNK, loadExploits, VULNS_BY_ID_SQL, type ExploitRef, type VulnRow } from './components';

/**
 * A pasted list of CVEs (`cve:` items), looked up by ID whatever their age.
 * vulns holds the window and the safety net with everything Vulnder knows;
 * cve_index (src/ingest/cve-index.ts) holds every CVE ever assigned with what
 * ranking needs. Both are read by primary key, so a list costs about two rows
 * per ID. A CVE rejected as a duplicate is replaced by the CVEs it names, read
 * the same way; every ID in the list ends up ranked, rejected or not found.
 */

/** One row of cve_index. */
export interface IndexRow {
  id: string;
  state: 'published' | 'rejected';
  replaced_by: string | null;
  published_at: string | null;
  title: string | null;
  product: string | null;
  product_label: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  severity_label: string | null;
  ssvc: string | null;
  kev_added_at: string | null;
  kev_ransomware: number;
  kev_due_date: string | null;
  kev_required_action: string | null;
  epss: number | null;
  epss_percentile: number | null;
  epss_date: string | null;
  /** The record's first exploit-tagged reference; absent before migration 0010. */
  exploit_ref?: string | null;
}

/** What a list held besides CVEs to rank. */
export interface Listed {
  /** Rejected CVEs, each with the CVEs its rejection points to (none when it names no replacement). */
  rejected: { id: string; replacedBy: string[] }[];
  /** IDs neither table has: reserved and never published, or mistyped. */
  notFound: string[];
}

/** A CVE to rank: its row, the list items it answers for, and the rejected IDs it replaces. */
export interface ListedVuln {
  row: VulnRow;
  matched: string[];
  replaces: string[];
  /** Where it groups in Fix first: its product as a stack item, or null to stand alone. */
  product: { item: string; label: string | null } | null;
  /** An exploited member of its family, when vulns knows the family. */
  exploitedSibling: string | null;
  /** Metasploit modules and Nuclei templates naming it. */
  exploits: ExploitRef[];
}

export interface ListedMatch {
  vulns: ListedVuln[];
  listed: Listed;
}

/** Most replacements read for one rejected CVE; the index keeps at most five. */
const MAX_REPLACEMENTS = 5;

export async function matchListed(store: Store, items: CveItem[]): Promise<ListedMatch> {
  const asked = [...new Set(items.map((i) => i.id))].sort();
  const found = await lookup(store, asked);

  const rejected: Listed['rejected'] = [];
  const notFound: string[] = [];
  const replacing = new Map<string, Set<string>>();
  for (const id of asked) {
    const f = found.get(id);
    if (!f) {
      notFound.push(id);
      continue;
    }
    if (f.rejected) {
      const replacedBy = f.rejected.filter((r) => r !== id).slice(0, MAX_REPLACEMENTS);
      rejected.push({ id, replacedBy });
      for (const r of replacedBy) {
        if (!replacing.has(r)) replacing.set(r, new Set());
        replacing.get(r)!.add(id);
      }
    }
  }
  // Replacements not in the list: one more round of the same lookups.
  const extra = [...replacing.keys()].filter((id) => !found.has(id));
  for (const [id, f] of await lookup(store, extra)) found.set(id, f);

  const ranked = new Map<string, ListedVuln>();
  const add = (id: string, matched: string | null) => {
    const f = found.get(id);
    if (!f?.row) return;
    let v = ranked.get(id);
    if (!v) {
      v = { row: f.row, matched: [], replaces: [...(replacing.get(id) ?? [])].sort(), product: f.product, exploitedSibling: null, exploits: [] };
      ranked.set(id, v);
    }
    if (matched) v.matched.push(matched);
  };
  for (const id of asked) add(id, identity({ kind: 'cve', id }));
  for (const id of replacing.keys()) add(id, null);

  // Exploited members of their families, as for a component's CVEs.
  const families = [...new Set([...ranked.values()].map((v) => v.row.family_id).filter((f): f is string => !!f))];
  if (families.length > 0) {
    const exploited = await allForKeys<{ id: string; family_id: string }>(store, EXPLOITED_IN_FAMILIES_SQL, families, FEED_CHUNK);
    for (const v of ranked.values()) {
      v.exploitedSibling = exploited.filter((e) => e.family_id === v.row.family_id && e.id !== v.row.id).map((e) => e.id).sort()[0] ?? null;
    }
  }

  // Metasploit modules and Nuclei templates, read by ID like the rest.
  const exploits = await loadExploits(store, [...ranked.keys()]);
  for (const e of exploits) ranked.get(e.cve_id)?.exploits.push(e);
  return { vulns: [...ranked.values()], listed: { rejected, notFound } };
}

interface Found {
  /** The row to rank, or null for a rejected CVE. */
  row: VulnRow | null;
  /** For a rejected CVE, the IDs its rejection names. */
  rejected: string[] | null;
  product: { item: string; label: string | null } | null;
}

/** Each ID's data: from vulns where it's there (full data), else from cve_index. */
async function lookup(store: Store, ids: string[]): Promise<Map<string, Found>> {
  const out = new Map<string, Found>();
  if (ids.length === 0) return out;
  const [full, index] = await Promise.all([
    allForKeys<VulnRow>(store, VULNS_BY_ID_SQL, ids, FEED_CHUNK),
    allForKeys<IndexRow>(store, CVE_INDEX_BY_ID_SQL, ids, FEED_CHUNK),
  ]);
  const inVulns = new Map(full.map((v) => [v.id, v]));
  for (const r of index) {
    const product = productItem(r.product, r.product_label);
    if (r.state === 'rejected') {
      // A rejection the index has wins: vulns drops rejected records, but may not have yet.
      out.set(r.id, { row: null, rejected: parseIds(r.replaced_by), product });
      continue;
    }
    out.set(r.id, { row: inVulns.get(r.id) ?? indexToVuln(r), rejected: null, product });
  }
  for (const [id, v] of inVulns) if (!out.has(id)) out.set(id, { row: v, rejected: null, product: null });
  return out;
}

/** An index row in the shape ranking reads, with what the index doesn't keep left empty. */
export function indexToVuln(r: IndexRow): VulnRow {
  return {
    id: r.id,
    aliases: '[]',
    title: r.title,
    summary: null,
    published_at: r.published_at,
    modified_at: null,
    cvss_score: r.cvss_score,
    cvss_vector: r.cvss_vector,
    severity_label: r.severity_label,
    cwe: '[]',
    epss: r.epss,
    epss_percentile: r.epss_percentile,
    epss_date: r.epss_date,
    lev_log: 0,
    kev_added_at: r.kev_added_at,
    kev_ransomware: r.kev_ransomware,
    kev_due_date: r.kev_due_date,
    kev_required_action: r.kev_required_action,
    ssvc: r.ssvc,
    refs: '[]',
    family_id: null,
    last_event_at: null,
    exploit_ref: r.exploit_ref ?? null,
  };
}

const ECOSYSTEMS = new Set<string>(Object.values(PREFIXES));

/**
 * The index's product key as a stack item: `vendor/product` is `p:vendor/product`,
 * `npm:express` (an ecosystem, then the package) is `npm:express`. Null when
 * there's none, or it wouldn't read back as an item.
 */
export function productItem(key: string | null, label: string | null): { item: string; label: string | null } | null {
  if (!key) return null;
  const colon = key.indexOf(':');
  const ecosystem = colon > 0 ? key.slice(0, colon) : '';
  const item = ECOSYSTEMS.has(ecosystem)
    ? formatItem({ kind: 'package', ecosystem: ecosystem as Ecosystem, name: key.slice(colon + 1), version: null })
    : `p:${key}`;
  try {
    const [parsed] = parseStack(item);
    return parsed && parsed.kind !== 'cve' ? { item: formatItem(parsed), label: label?.trim() || null } : null;
  } catch {
    return null;
  }
}

function parseIds(text: string | null): string[] {
  if (!text) return [];
  try {
    const ids: unknown = JSON.parse(text);
    return Array.isArray(ids) ? ids.filter((i): i is string => typeof i === 'string' && /^CVE-\d{4}-\d{4,7}$/.test(i)) : [];
  } catch {
    return [];
  }
}
