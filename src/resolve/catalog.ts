import { normalizeKey, normalizePackageName, ownValue, type Ecosystem } from '../lib/normalize';
import type { Store } from '../ingest/store';
import { formatItem, isStackVersion, parseStack, type StackItem } from '../stack/format';
import { productLabel } from '../ingest/sources/cve-record';
import { ALIASES, CATEGORIES } from './aliases';
import { classifyProfile, MIN_RANK_CONFIDENCE, rankByProfile, type Profile, type ProfileClassifier, type ProfileGuess } from './profile';
import type { Candidate } from './types';

/**
 * Turns candidates into chips without asking the user to choose. A name that
 * clearly identifies one thing resolves to an exact item. A vague one ("nginx",
 * "Cisco switches") expands to every product it plausibly means, each marked as
 * a close match, so results show everything relevant and say how sure they are.
 *
 * Order: curated aliases, product categories, exact keys, then trigram
 * similarity over catalog entries sharing a prefix, then the vendor's
 * best-known products. Close matches are then ordered by the stack's likely
 * profile (see profile.ts).
 */

export interface ChipItem {
  /** Canonical stack item (with a leading '?' when close). */
  item: string;
  label: string;
  close: boolean;
  /** True when the catalog has vulnerabilities for it in the retention window. */
  known: boolean;
}

export interface Chip {
  /** What the user wrote or the manifest named. */
  input: string;
  status: 'resolved' | 'unrecognised';
  items: ChipItem[];
}

export interface ResolveResult {
  chips: Chip[];
  /** Transitive lockfile dependencies left out because nothing is known about them. */
  droppedTransitive: number;
  profile: ProfileGuess;
}

export interface ResolveOptions {
  /** The extraction model's view of who runs the stack; null for manifests. */
  modelHint?: Profile | null;
  classifier?: ProfileClassifier;
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
/** Fuzzy guesses get noisy past this many. Category expansion is not capped. */
const MAX_FUZZY = 8;
/** "Cisco" alone: the vendor's most-affected products. */
const MAX_VENDOR_ONLY = 8;
const MAX_PREFIX_ROWS = 4000;

type ProductCandidate = Extract<Candidate, { kind: 'product' }>;

export async function resolveCandidates(store: Store, input: Candidate[], options: ResolveOptions = {}): Promise<ResolveResult> {
  const candidates = input.map(asResolvable);
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

  const products = candidates.filter((c): c is ProductCandidate => c.kind === 'product');
  const queries = [...new Set(products.map((p) => normalizeKey(p.name)).filter((k): k is string => !!k && !ownValue(ALIASES, k)))];
  const rows = queries.length === 0 ? [] : await productCandidates(store, queries);
  // Every product of each vendor named (or implied by the first word), for categories and vendor-only input.
  const vendors = [...new Set(products.flatMap((p) => vendorGuesses(p)))];
  const byVendor = vendors.length === 0 ? [] : await productsByVendor(store, vendors);

  const aliasItems = [...new Set(candidates.flatMap((c) => ownValue(ALIASES, normalizeKey(c.name) ?? '') ?? []))];
  const knownAlias = await knownItems(store, aliasItems);

  const chips: Chip[] = [];
  let droppedTransitive = 0;
  for (const c of candidates) {
    if (c.kind === 'package') {
      let name = normalizePackageName(c.ecosystem, c.name);
      let known = knownPackages.has(`${c.ecosystem}:${name}`);
      if (!known) {
        // "Next.js" from the model means the npm package `next`. Only an alias in
        // the same ecosystem applies, so real manifest names are never rewritten.
        const alias = (ownValue(ALIASES, normalizeKey(c.name) ?? '') ?? []).map((a) => parseStack(a)[0]!).find((a) => a.kind === 'package' && a.ecosystem === c.ecosystem);
        if (alias && alias.kind === 'package') {
          name = alias.name;
          known = knownAlias.has(formatItem(alias));
        }
      }
      if (!c.direct && !known) {
        droppedTransitive++;
        continue;
      }
      const item: StackItem = { kind: 'package', ecosystem: c.ecosystem, name, version: c.version };
      chips.push({
        input: c.version ? `${c.name} ${c.version}` : c.name,
        status: 'resolved',
        items: [{ item: formatItem(item), label: c.name, close: false, known }],
      });
      continue;
    }
    chips.push(resolveProduct(c, rows, byVendor, knownAlias));
  }

  const profile = await classifyProfile(profileSignals(candidates, chips, options.modelHint ?? null), options.classifier);
  if (profile.profile && profile.confidence >= MIN_RANK_CONFIDENCE) {
    for (const chip of chips) {
      if (chip.items.length > 1 && chip.items.every((i) => i.close)) chip.items = rankByProfile(chip.items, profile.profile, productOf);
    }
  }
  return { chips, droppedTransitive, profile };
}

/** Exact products, the vendors behind close-only chips, and direct packages. */
function profileSignals(candidates: Candidate[], chips: Chip[], modelHint: Profile | null) {
  const products: { vendor: string; product: string }[] = [];
  const vendors = new Set<string>();
  for (const chip of chips) {
    const exact = chip.items.filter((i) => !i.close).map(productOf);
    for (const p of exact) if (p) products.push(p);
    if (exact.length > 0) continue;
    const closeVendors = new Set(chip.items.map((i) => productOf(i)?.vendor));
    const [only] = closeVendors;
    if (closeVendors.size === 1 && only) vendors.add(only);
  }
  const directPackages = candidates.filter((c) => c.kind === 'package' && c.direct).length;
  return { products, vendors: [...vendors], directPackages, modelHint };
}

function productOf(i: ChipItem): { vendor: string; product: string } | null {
  const parsed = parseStack(i.item.replace(/^\?/, ''))[0]!;
  return parsed.kind === 'product' ? { vendor: parsed.vendor, product: parsed.product } : null;
}

/**
 * Makes any candidate safe to turn into stack items, whatever the model or a
 * client sent. A version that can't appear in a stack item ("1.0 beta", a
 * newline) is dropped, as ranges are. A "package" whose item wouldn't read
 * back as itself ("Fast API", "a@b") is really a name, so it's looked up like
 * a product instead of becoming an item the feed would reject.
 */
function asResolvable(c: Candidate): Candidate {
  const v = c.version?.trim();
  const version = v && isStackVersion(v) ? v : null;
  if (c.kind === 'product') return { ...c, version };
  if (roundTrips(c.ecosystem, c.name, version)) return { ...c, version };
  return { kind: 'product', name: c.name, vendor: null, version, direct: c.direct };
}

function roundTrips(ecosystem: Ecosystem, rawName: string, version: string | null): boolean {
  const name = normalizePackageName(ecosystem, rawName);
  try {
    const [parsed] = parseStack(formatItem({ kind: 'package', ecosystem, name, version }));
    return parsed?.kind === 'package' && parsed.name === name && parsed.version === version;
  } catch {
    return false;
  }
}

function resolveProduct(c: ProductCandidate, rows: CatalogRow[], byVendor: CatalogRow[], knownAlias: Set<string>): Chip {
  const input = [productLabel(c.vendor, c.name), c.version].filter(Boolean).join(' ');
  const key = normalizeKey(c.name);
  if (!key) return { input, status: 'unrecognised', items: [] };
  const make = (item: string, label: string, close: boolean, known: boolean): ChipItem => {
    const parsed = parseStack(item.replace(/^\?/, ''))[0]!;
    return { item: formatItem({ ...parsed, version: c.version, close: close || undefined }), label, close, known };
  };
  const resolved = (items: ChipItem[]): Chip => ({ input, status: items.length > 0 ? 'resolved' : 'unrecognised', items });

  // 1. Curated aliases: one target is exact, several are all close.
  const aliased = ownValue(ALIASES, key);
  if (aliased) {
    const close = aliased.length > 1;
    return resolved(aliased.map((item) => make(item, labelFor(item), close, knownAlias.has(item))));
  }

  // 2. Categories: "Cisco switches" means every Cisco switch product.
  const category = CATEGORIES.find((cat) => cat.words.test(c.name));
  const vendorKey = vendorGuesses(c).find((v) => byVendor.some((r) => r.vendor === v)) ?? null;
  if (category && vendorKey) {
    const pattern = ownValue(category.byVendor, vendorKey) ?? category.generic;
    const fitting = byVendor.filter((r) => r.vendor === vendorKey && pattern.test(stripVendor(r.product!, vendorKey)));
    if (fitting.length > 0) return resolved(fitting.map((r) => make(itemOf(r), r.label ?? r.key, true, true)));
  }

  // 3. Exact key or clear fuzzy winner; otherwise every plausible guess as close.
  const scored = rows
    .map((r) => ({ r, score: similarity(key, r.normalized) + (vendorKey && r.vendor === vendorKey ? 0.15 : 0) + (r.product === key ? 0.1 : 0) }))
    .filter((s) => s.score >= SUGGEST_SCORE)
    .sort((a, b) => b.score - a.score || b.r.count - a.r.count);
  const unique = [...new Map(scored.map((s) => [s.r.key, s])).values()];
  const best = unique[0];
  if (best) {
    const second = unique[1];
    if (best.score >= RESOLVE_SCORE && (!second || second.score <= best.score - CLEAR_LEAD)) {
      return resolved([make(itemOf(best.r), best.r.label ?? best.r.key, false, true)]);
    }
    return resolved(unique.slice(0, MAX_FUZZY).map((s) => make(itemOf(s.r), s.r.label ?? s.r.key, true, true)));
  }

  // 4. Only a vendor: its most-affected products, as close matches.
  if (vendorKey) {
    const top = byVendor.filter((r) => r.vendor === vendorKey).slice(0, MAX_VENDOR_ONLY);
    return resolved(top.map((r) => make(itemOf(r), r.label ?? r.key, true, true)));
  }
  return { input, status: 'unrecognised', items: [] };
}

/** The vendor given, or else the first word of the name ("Cisco switches"). */
function vendorGuesses(c: ProductCandidate): string[] {
  const given = normalizeKey(c.vendor);
  const firstWord = normalizeKey(c.name.trim().split(/\s+/)[0]);
  return [given, firstWord].filter((v, i, a): v is string => !!v && a.indexOf(v) === i);
}

/** `cisco_ios_xe_software` → `ios_xe_software`, so patterns need not repeat the vendor. */
function stripVendor(product: string, vendor: string): string {
  return product.startsWith(`${vendor}_`) ? product.slice(vendor.length + 1) : product;
}

function itemOf(r: CatalogRow): string {
  return r.kind === 'product' ? `p:${r.vendor}/${r.product}` : formatItem({ kind: 'package', ecosystem: r.ecosystem as never, name: r.name!, version: null });
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

/** All products of the given vendors, most-affected first. */
async function productsByVendor(store: Store, vendors: string[]): Promise<CatalogRow[]> {
  return store.all<CatalogRow>(
    `SELECT kind, key, ecosystem, name, vendor, product, normalized, label, count FROM catalog
     WHERE kind = 'product' AND vendor IN (SELECT value FROM json_each(?))
     ORDER BY count DESC, key LIMIT ${MAX_PREFIX_ROWS}`,
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
