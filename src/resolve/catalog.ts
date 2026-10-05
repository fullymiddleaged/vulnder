import { normalizeKey, normalizePackageName } from '../lib/normalize';
import type { Store } from '../ingest/store';
import { formatItem, parseStack, type StackItem } from '../stack/format';
import { ALIASES } from './aliases';
import type { Candidate } from './types';

/**
 * Turns candidates into chips. Packages from manifests are exact identifiers
 * and always resolve. Product names (from the model or a Dockerfile) are
 * matched against the catalog: curated aliases first, then exact keys, then
 * trigram similarity over catalog entries sharing a prefix.
 */

export type ChipStatus = 'resolved' | 'ambiguous' | 'unrecognised';

export interface Alternative {
  item: string;
  label: string;
}

export interface Chip {
  /** What the user wrote or the manifest named. */
  input: string;
  status: ChipStatus;
  /** Canonical stack item when resolved. */
  item?: string;
  label?: string;
  /** True when the catalog has vulnerabilities for it in the retention window. */
  known?: boolean;
  alternatives?: Alternative[];
}

export interface ResolveResult {
  chips: Chip[];
  /** Transitive lockfile dependencies left out because nothing is known about them. */
  droppedTransitive: number;
}

interface CatalogRow {
  kind: 'package' | 'product';
  key: string;
  ecosystem: string | null;
  name: string | null;
  vendor: string | null;
  product: string | null;
  normalized: string;
  label: string | null;
  count: number;
}

const RESOLVE_SCORE = 0.8;
const SUGGEST_SCORE = 0.45;
const CLEAR_LEAD = 0.1;
const MAX_ALTERNATIVES = 5;
const MAX_PREFIX_ROWS = 4000;

export async function resolveCandidates(store: Store, candidates: Candidate[]): Promise<ResolveResult> {
  // Exact catalog lookups for every package, in one query.
  const packageKeys = candidates.flatMap((c) => (c.kind === 'package' ? [`${c.ecosystem}:${normalizePackageName(c.ecosystem, c.name)}`] : []));
  const knownPackages = new Set(
    packageKeys.length === 0
      ? []
      : (
          await store.all<{ key: string }>(
            "SELECT key FROM catalog WHERE kind = 'package' AND key IN (SELECT value FROM json_each(?))",
            [JSON.stringify([...new Set(packageKeys)])],
          )
        ).map((r) => r.key),
  );

  // Product names: aliases need no query; the rest go to the catalog together.
  const products = candidates.filter((c): c is Extract<Candidate, { kind: 'product' }> => c.kind === 'product');
  const queries = [...new Set(products.map((p) => normalizeKey(p.name)).filter((k): k is string => !!k && !ALIASES[k]))];
  const rows = queries.length === 0 ? [] : await productCandidates(store, queries);
  // "Cisco switches": when the name matches nothing, a known vendor still narrows it down.
  const vendors = [...new Set(products.map((p) => normalizeKey(p.vendor)).filter((v): v is string => !!v))];
  const byVendor = vendors.length === 0 ? [] : await topProductsByVendor(store, vendors);

  const aliasItems = [...new Set(candidates.flatMap((c) => ALIASES[normalizeKey(c.name) ?? ''] ?? []))];
  const knownAliasProducts = await knownItems(store, aliasItems);

  const chips: Chip[] = [];
  let droppedTransitive = 0;
  for (const c of candidates) {
    if (c.kind === 'package') {
      let name = normalizePackageName(c.ecosystem, c.name);
      let known = knownPackages.has(`${c.ecosystem}:${name}`);
      if (!known) {
        // "Next.js" from the model means the npm package `next`. Only an alias in
        // the same ecosystem applies, so real manifest names are never rewritten.
        const alias = (ALIASES[normalizeKey(c.name) ?? ''] ?? []).map((a) => parseStack(a)[0]!).find((a) => a.kind === 'package' && a.ecosystem === c.ecosystem);
        if (alias && alias.kind === 'package') {
          name = alias.name;
          known = knownAliasProducts.has(formatItem(alias));
        }
      }
      if (!c.direct && !known) {
        droppedTransitive++;
        continue;
      }
      const item: StackItem = { kind: 'package', ecosystem: c.ecosystem, name, version: c.version };
      chips.push({ input: c.version ? `${c.name} ${c.version}` : c.name, status: 'resolved', item: formatItem(item), label: c.name, known });
      continue;
    }
    chips.push(resolveProduct(c, rows, byVendor, knownAliasProducts));
  }
  return { chips: dedupeChips(chips), droppedTransitive };
}

function resolveProduct(
  c: Extract<Candidate, { kind: 'product' }>,
  rows: CatalogRow[],
  byVendor: CatalogRow[],
  knownAlias: Set<string>,
): Chip {
  const input = [c.vendor, c.name, c.version].filter(Boolean).join(' ');
  const key = normalizeKey(c.name);
  if (!key) return { input, status: 'unrecognised' };
  const withVersion = (item: string) => {
    const parsed = parseStack(item)[0]!;
    return formatItem({ ...parsed, version: c.version });
  };

  const aliased = ALIASES[key];
  if (aliased) {
    const alts = aliased.map((item) => ({ item: withVersion(item), label: labelFor(item) }));
    if (alts.length === 1) return { input, status: 'resolved', item: alts[0]!.item, label: alts[0]!.label, known: knownAlias.has(aliased[0]!) };
    return { input, status: 'ambiguous', alternatives: alts };
  }

  const vendorKey = normalizeKey(c.vendor);
  const scored = rows
    .map((r) => ({ r, score: similarity(key, r.normalized) + (vendorKey && r.vendor === vendorKey ? 0.15 : 0) + (r.product === key ? 0.1 : 0) }))
    .filter((s) => s.score >= SUGGEST_SCORE)
    .sort((a, b) => b.score - a.score || b.r.count - a.r.count);
  const unique = [...new Map(scored.map((s) => [s.r.key, s])).values()];
  const itemOf = (r: CatalogRow) =>
    r.kind === 'product' ? `p:${r.vendor}/${r.product}` : formatItem({ kind: 'package', ecosystem: r.ecosystem as never, name: r.name!, version: null });
  const best = unique[0];
  if (!best) {
    const vendorRows = vendorKey ? byVendor.filter((r) => r.vendor === vendorKey).slice(0, MAX_ALTERNATIVES) : [];
    if (vendorRows.length === 0) return { input, status: 'unrecognised' };
    return { input, status: 'ambiguous', alternatives: vendorRows.map((r) => ({ item: withVersion(itemOf(r)), label: r.label ?? r.key })) };
  }
  const second = unique[1];
  if (best.score >= RESOLVE_SCORE && (!second || second.score <= best.score - CLEAR_LEAD)) {
    return { input, status: 'resolved', item: withVersion(itemOf(best.r)), label: best.r.label ?? best.r.key, known: true };
  }
  return {
    input,
    status: 'ambiguous',
    alternatives: unique.slice(0, MAX_ALTERNATIVES).map((s) => ({ item: withVersion(itemOf(s.r)), label: s.r.label ?? s.r.key })),
  };
}

/** Catalog rows whose normalized name shares a prefix with any query. */
async function productCandidates(store: Store, queries: string[]): Promise<CatalogRow[]> {
  const ranges = queries.map((q) => {
    const prefix = q.slice(0, q.length >= 6 ? 4 : 3);
    return [prefix, `${prefix}\u{10FFFF}`];
  });
  return store.all<CatalogRow>(
    `SELECT DISTINCT c.kind, c.key, c.ecosystem, c.name, c.vendor, c.product, c.normalized, c.label, c.count
     FROM json_each(?) j
     JOIN catalog c ON c.normalized >= json_extract(j.value, '$[0]') AND c.normalized < json_extract(j.value, '$[1]')
     LIMIT ${MAX_PREFIX_ROWS}`,
    [JSON.stringify(ranges)],
  );
}

/** The most-affected products of each vendor, for names that match nothing. */
async function topProductsByVendor(store: Store, vendors: string[]): Promise<CatalogRow[]> {
  return store.all<CatalogRow>(
    `SELECT kind, key, ecosystem, name, vendor, product, normalized, label, count FROM (
       SELECT c.*, ROW_NUMBER() OVER (PARTITION BY c.vendor ORDER BY c.count DESC, c.key) AS rn
       FROM catalog c WHERE c.kind = 'product' AND c.vendor IN (SELECT value FROM json_each(?))
     ) WHERE rn <= ${MAX_ALTERNATIVES}`,
    [JSON.stringify(vendors)],
  );
}

/** The subset of stack items that have catalog entries. */
async function knownItems(store: Store, items: string[]): Promise<Set<string>> {
  if (items.length === 0) return new Set();
  const keyed = items.map((item) => {
    const p = parseStack(item)[0]!;
    return [item, p.kind === 'package' ? `${p.ecosystem}:${p.name}` : `${p.vendor}/${p.product}`] as const;
  });
  const rows = await store.all<{ key: string }>('SELECT key FROM catalog WHERE key IN (SELECT value FROM json_each(?))', [
    JSON.stringify(keyed.map(([, k]) => k)),
  ]);
  const found = new Set(rows.map((r) => r.key));
  return new Set(keyed.filter(([, k]) => found.has(k)).map(([item]) => item));
}

function labelFor(item: string): string {
  const parsed = parseStack(item)[0]!;
  return parsed.kind === 'package' ? parsed.name : `${parsed.vendor} ${parsed.product}`.replace(/_/g, ' ');
}

/** Sørensen–Dice coefficient over character trigrams (with padding). */
export function similarity(a: string, b: string): number {
  if (a === b) return 1;
  const grams = (s: string) => {
    const padded = `  ${s} `;
    const out = new Map<string, number>();
    for (let i = 0; i < padded.length - 2; i++) {
      const g = padded.slice(i, i + 3);
      out.set(g, (out.get(g) ?? 0) + 1);
    }
    return out;
  };
  const ga = grams(a);
  const gb = grams(b);
  let shared = 0;
  let total = 0;
  for (const [g, n] of ga) {
    shared += Math.min(n, gb.get(g) ?? 0);
    total += n;
  }
  for (const n of gb.values()) total += n;
  return total === 0 ? 0 : (2 * shared) / total;
}

function dedupeChips(chips: Chip[]): Chip[] {
  const seen = new Set<string>();
  return chips.filter((c) => {
    const k = c.item ?? `${c.status}:${c.input}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
