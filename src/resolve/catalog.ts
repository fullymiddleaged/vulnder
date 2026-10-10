import { normalizeKey, normalizePackageName, ownValue, type Ecosystem } from '../lib/normalize';
import type { Store } from '../ingest/store';
import { formatItem, isStackVersion, MAX_ITEMS, parseStack, type StackItem, type Team } from '../stack/format';
import { productLabel } from '../ingest/sources/cve-record';
import { ALIASES, CATEGORIES, vendorFamily, vendorSpellings } from './aliases';
import { fallbackKey, forVersion, inLine, lineFor, lineRanges, perRelease, type LineMatch } from './lines';
import type { Candidate } from './types';

/**
 * Turns candidates into chips without asking the user to choose. A name that
 * clearly identifies one thing resolves to an exact item. A vague one ("nginx",
 * "Cisco switches") expands to every product it plausibly means, each marked as
 * a close match, so results show everything relevant and say how sure they are.
 *
 * Order: curated aliases, product categories, exact keys, then trigram
 * similarity over catalog entries sharing a prefix, then the vendor's
 * best-known products. Close matches come out in catalog order (most-affected
 * first); for free text, the route may reorder them by fit (see profile.ts).
 */

export interface ChipItem {
  /** Canonical stack item (with a leading '?' when close, and a trailing ';team' for enterprise stacks). */
  item: string;
  label: string;
  close: boolean;
  /** True when the catalog has vulnerabilities for it in the retention window. */
  known: boolean;
  /** Set for an enterprise stack when Jev or the fixed table named a team; the item carries it too. */
  team?: Team;
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
/** Added to a fuzzy score when the row's vendor is the one named, or its product is the exact name. */
const VENDOR_BONUS = 0.15;
const PRODUCT_BONUS = 0.1;
const MAX_BONUS = VENDOR_BONUS + PRODUCT_BONUS;
/** Fuzzy guesses get noisy past this many. Category expansion is not capped. */
const MAX_FUZZY = 8;
/** "Cisco" alone: the vendor's most-affected products. */
const MAX_VENDOR_ONLY = 8;
const MAX_PREFIX_ROWS = 4000;
/**
 * Distinct product names one request may look up (and twice as many vendors). The vendor
 * query reads every product of every vendor named, so 5,000 names read 30,000
 * rows; and a stack holds at most MAX_ITEMS items anyway.
 */
export const MAX_PRODUCT_LOOKUPS = MAX_ITEMS;

/**
 * Matches one request may return in all: ten per allowed lookup. A lookup
 * returns at most 8 fuzzy or vendor matches, and the largest category seen
 * ("Cisco switches" and the like) is under 30; a stack holds MAX_ITEMS anyway.
 * So only input built to multiply matches reaches this: 5,000 copies of a
 * category with different versions would otherwise be 1.5 million items.
 */
export const MAX_RESOLVED_ITEMS = 10 * MAX_PRODUCT_LOOKUPS;

/** More distinct products or vendors than MAX_PRODUCT_LOOKUPS, or more matches than MAX_RESOLVED_ITEMS. */
export class TooManyProducts extends Error {
  constructor(message = `at most ${MAX_PRODUCT_LOOKUPS} different products can be looked up at once`) {
    super(message);
    this.name = 'TooManyProducts';
  }
}

/** What resolveProduct shares across one request's candidates. */
interface Lookup {
  byVendor: CatalogRow[];
  /** Every catalog product in the requested product lines' key ranges, most-affected first. */
  lineRows: CatalogRow[];
  knownAlias: Set<string>;
  /** The fetched rows in one prefix's range, with their trigram index; built once per prefix. */
  scope: (prefix: string) => { rows: CatalogRow[]; index: GramIndex };
  /** Each category's products for a vendor, by `category index|vendor`. */
  categories: Map<string, ChipItem[]>;
}

type ProductCandidate = Extract<Candidate, { kind: 'product' }>;

export async function resolveCandidates(store: Store, input: Candidate[]): Promise<ResolveResult> {
  const candidates = input.map(asResolvable);
  const packageKeys = candidates.flatMap((c) => (c.kind === 'package' ? [`${c.ecosystem}:${normalizePackageName(c.ecosystem, c.name)}`] : []));
  const aliasItems = [...new Set(candidates.flatMap((c) => ownValue(ALIASES, normalizeKey(c.name) ?? '') ?? []))];
  const products = candidates.filter((c): c is ProductCandidate => c.kind === 'product');
  const lines = products.map((p) => lineFor(p.name, p.vendor));
  const queries = [...new Set(products.flatMap((p, i) => (lines[i] ? [] : [normalizeKey(p.name)])).filter((k): k is string => !!k && !ownValue(ALIASES, k)))];
  const ranges = [...new Map(lines.flatMap((m) => (m ? lineRanges(m.line) : [])).map((r) => [r.join('\n'), r])).values()];
  // Each vendor named (or implied by the first word). Most names only need to
  // know the vendor exists, plus its top few products for vendor-only input;
  // only a category ("Cisco switches") needs every product of its vendor.
  const vendors = [...new Set(products.flatMap((p) => vendorGuesses(p)))];
  const categoryVendors = [...new Set(products.filter((p) => CATEGORIES.some((cat) => cat.words.test(p.name))).flatMap((p) => vendorGuesses(p)))];
  // Read under every key each vendor is stored as ("juniper" is `juniper_networks` in CVE records).
  const spelled = (vs: string[]) => [...new Set(vs.flatMap(vendorSpellings))];
  // Each distinct product is resolved once (duplicates reuse it), and fuzzy
  // scoring costs about rows × lookups, so lookups are capped by what drives
  // resolveProduct, not only by name: 5,000 copies of a name, or one name with
  // 5,000 vendors, would otherwise score the rows 5,000 times.
  // A line's version picks its products, so lines are looked up per version too.
  const lookupKeys = products.map((p, i) => productLookupKey(p, lines[i] ? (p.version ?? lines[i].version) : null));
  // Each product makes up to three vendor guesses.
  if (queries.length > MAX_PRODUCT_LOOKUPS || vendors.length > 3 * MAX_PRODUCT_LOOKUPS || new Set(lookupKeys).size > MAX_PRODUCT_LOOKUPS) {
    throw new TooManyProducts();
  }

  // Independent queries, sent together. Each reads only index ranges: exact keys
  // (packages and alias targets), name prefixes, each vendor's top products,
  // every product of the vendors a category names, and the product lines' keys.
  const [known, rows, top, all, lineHits] = await Promise.all([
    knownKeys(store, [...packageKeys.map((key) => ({ kind: 'package' as const, key })), ...aliasItems.map(catalogKey)]),
    queries.length === 0 ? [] : productCandidates(store, queries),
    vendors.length === 0 ? [] : store.all<CatalogRow>(VENDOR_TOP_SQL, [JSON.stringify(spelled(vendors)), MAX_VENDOR_ONLY]),
    categoryVendors.length === 0 ? [] : productsByVendor(store, spelled(categoryVendors)),
    ranges.length === 0 ? [] : store.all<CatalogRow>(KEY_RANGE_SQL, [JSON.stringify(ranges), MAX_PREFIX_ROWS]),
  ]);
  const byVendor = mergeVendorRows(all, top);
  // Lines can share a key (ASA and FTD), so each row once; then most-affected first, like every other list of close matches.
  const lineRows = [...new Map(lineHits.map((r) => [r.key, r])).values()].sort((a, b) => b.count - a.count || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const knownPackages = new Set(packageKeys.filter((key) => known.has(`package ${key}`)));
  const knownAlias = new Set(aliasItems.filter((item) => {
    const { kind, key } = catalogKey(item);
    return known.has(`${kind} ${key}`);
  }));

  const chips: Chip[] = [];
  let droppedTransitive = 0;
  const lookups = new Map<string, Chip>();
  const scopes = new Map<string, { rows: CatalogRow[]; index: GramIndex }>();
  const scope = (prefix: string) => {
    let s = scopes.get(prefix);
    if (!s) {
      const own = rows.filter((r) => r.normalized.startsWith(prefix));
      scopes.set(prefix, (s = { rows: own, index: gramIndex(own.map((r) => r.normalized)) }));
    }
    return s;
  };
  const lookup: Lookup = { byVendor, lineRows, knownAlias, scope, categories: new Map() };
  let productIndex = 0;
  let itemCount = 0;
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
    const i = productIndex++;
    const lookupKey = lookupKeys[i]!;
    let chip = lookups.get(lookupKey);
    const line = lines[i] ?? null;
    if (!chip) lookups.set(lookupKey, (chip = resolveProduct(line ? { ...c, version: c.version ?? line.version } : { ...c, version: null }, line, lookup)));
    // Counted before forCandidate copies the items, so an oversized request stops early.
    itemCount += chip.items.length;
    if (itemCount > MAX_RESOLVED_ITEMS) throw new TooManyProducts(`these names match more than ${MAX_RESOLVED_ITEMS} products`);
    chips.push(forCandidate(chip, c));
  }

  return { chips, droppedTransitive };
}

/** Everything resolveProduct reads from a candidate, apart from its label (and its version, except for a product line). */
function productLookupKey(c: ProductCandidate, version: string | null): string {
  return JSON.stringify([normalizeKey(c.name), vendorGuesses(c), CATEGORIES.findIndex((cat) => cat.words.test(c.name)), version]);
}

/** A resolved lookup, labelled and versioned for one candidate. */
function forCandidate(chip: Chip, c: ProductCandidate): Chip {
  const input = [productLabel(c.vendor, c.name), c.version].filter(Boolean).join(' ');
  if (!c.version) return { ...chip, input };
  const items = chip.items.map((i) => {
    const parsed = parseStack(i.item.replace(/^\?/, ''))[0]!;
    return { ...i, item: formatItem({ ...parsed, version: c.version, close: i.close || undefined }) };
  });
  return { ...chip, input, items };
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

function resolveProduct(c: ProductCandidate, match: LineMatch | null, { byVendor, lineRows, knownAlias, scope, categories }: Lookup): Chip {
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

  // 2. Product lines: every key a product's CVEs are filed under (lines.ts). A
  // version that picks out one of them ("RHEL 9") makes it exact.
  if (match) {
    const { line } = match;
    const members = lineRows.filter((r) => inLine(line, r.key));
    if (members.length === 0) {
      // Nothing in the window yet: watch its main key, so the feed picks up the first CVE.
      const fallback = fallbackKey(line);
      return resolved(fallback ? [make(`p:${fallback}`, labelFor(`p:${fallback}`), false, false)] : []);
    }
    const picked = forVersion(members, c.version);
    // A release none of the line's per-release products is ("Windows 7", "RHEL 5"): its main key
    // at that version is what was named, rather than every other release as a close match.
    const fallback = picked.length === 0 && c.version && perRelease(members) ? fallbackKey(line) : null;
    if (fallback) return resolved([make(`p:${fallback}`, labelFor(`p:${fallback}`), false, members.some((r) => r.key === fallback))]);
    const shown = picked.length > 0 ? picked : members;
    return resolved(shown.map((r) => make(itemOf(r), r.label ?? r.key, shown.length > 1, true)));
  }

  // 3. Categories: "Cisco switches" means every Cisco switch product.
  const categoryIndex = CATEGORIES.findIndex((cat) => cat.words.test(c.name));
  const category = CATEGORIES[categoryIndex];
  // The vendor as a family, so `juniper` and `juniper_networks` rows both count.
  const ofVendor = (family: string) => (r: CatalogRow) => r.vendor !== null && vendorFamily(r.vendor) === family;
  const vendorKey = vendorGuesses(c).map(vendorFamily).find((f) => byVendor.some(ofVendor(f))) ?? null;
  const isVendor = vendorKey ? ofVendor(vendorKey) : () => false;
  if (category && vendorKey) {
    // The same for every name in this category and vendor ("Cisco switches", "Cisco access switches").
    const cacheKey = `${categoryIndex}|${vendorKey}`;
    let items = categories.get(cacheKey);
    if (!items) {
      const pattern = ownValue(category.byVendor, vendorKey) ?? category.generic;
      const fitting = byVendor.filter((r) => isVendor(r) && pattern.test(stripVendor(r.product!, r.vendor!)));
      categories.set(cacheKey, (items = fitting.map((r) => make(itemOf(r), r.label ?? r.key, true, true))));
    }
    // None of the vendor's products fit ("Sophos firewall" with only Sophos Home in the catalog):
    // say so, rather than offer near-spellings that aren't the thing named.
    return resolved(items);
  }

  // 4. Exact key or clear fuzzy winner; otherwise every plausible guess as close.
  // Only rows in this name's own prefix range count, so a name resolves the
  // same whatever else was asked for alongside it.
  const { rows: own, index } = scope(prefixOf(key));
  // The name is a vendor ("MikroTik", "Check Point") and no product of that name: go
  // straight to its products, before near-spellings of other vendors (mikro_orm).
  const isVendorName = vendorKey !== null && vendorFamily(key) === vendorKey && !own.some((r) => r.product === key);
  if (isVendorName) return resolved(byVendor.filter(isVendor).slice(0, MAX_VENDOR_ONLY).map((r) => make(itemOf(r), r.label ?? r.key, true, true)));
  const sims = similarities(key, index);
  const scored: { r: CatalogRow; score: number }[] = [];
  for (let i = 0; i < own.length; i++) {
    // Most rows share a letter or two and no more: skip them before building anything.
    if (sims[i]! + MAX_BONUS < SUGGEST_SCORE) continue;
    const r = own[i]!;
    const score = sims[i]! + (isVendor(r) ? VENDOR_BONUS : 0) + (r.product === key ? PRODUCT_BONUS : 0);
    if (score >= SUGGEST_SCORE) scored.push({ r, score });
  }
  scored.sort((a, b) => b.score - a.score || b.r.count - a.r.count);
  const unique = [...new Map(scored.map((s) => [s.r.key, s])).values()];
  const best = unique[0];
  if (best) {
    const second = unique[1];
    if (best.score >= RESOLVE_SCORE && (!second || second.score <= best.score - CLEAR_LEAD)) {
      return resolved([make(itemOf(best.r), best.r.label ?? best.r.key, false, true)]);
    }
    // The closest names are kept, then listed most-affected first, like every other close match.
    const closest = unique.slice(0, MAX_FUZZY).sort((a, b) => b.r.count - a.r.count || b.score - a.score);
    return resolved(closest.map((s) => make(itemOf(s.r), s.r.label ?? s.r.key, true, true)));
  }

  // 5. Only a vendor: its most-affected products, as close matches.
  if (vendorKey) {
    const top = byVendor.filter(isVendor).slice(0, MAX_VENDOR_ONLY);
    return resolved(top.map((r) => make(itemOf(r), r.label ?? r.key, true, true)));
  }
  return { input, status: 'unrecognised', items: [] };
}

/** The vendor given, the first word of the name ("Cisco switches"), then the whole name ("Check Point"). */
function vendorGuesses(c: ProductCandidate): string[] {
  const given = normalizeKey(c.vendor);
  const firstWord = normalizeKey(c.name.trim().split(/\s+/)[0]);
  return [given, firstWord, normalizeKey(c.name)].filter((v, i, a): v is string => !!v && a.indexOf(v) === i);
}

/** `cisco_ios_xe_software` → `ios_xe_software`, so patterns need not repeat the vendor. */
function stripVendor(product: string, vendor: string): string {
  return product.startsWith(`${vendor}_`) ? product.slice(vendor.length + 1) : product;
}

function itemOf(r: CatalogRow): string {
  return r.kind === 'product' ? `p:${r.vendor}/${r.product}` : formatItem({ kind: 'package', ecosystem: r.ecosystem as never, name: r.name!, version: null });
}

/** Catalog rows whose normalized name shares a prefix with any query. */
/** Rows each side of each name in PREFIX_SQL, so all names together read at most MAX_PREFIX_ROWS. */
export function prefixShare(names: number): number {
  return Math.max(1, Math.floor(MAX_PREFIX_ROWS / (2 * Math.max(1, names))));
}

/** The start of a name that catalog rows must share to be compared with it. */
function prefixOf(key: string): string {
  return key.slice(0, key.length >= 6 ? 4 : 3);
}

async function productCandidates(store: Store, queries: string[]): Promise<CatalogRow[]> {
  const ranges = queries.map((q) => {
    const prefix = prefixOf(q);
    return [prefix, `${prefix}\u{10FFFF}`, q];
  });
  // Every row of every range, when they fit: the cheap query, and what nearly every request needs.
  const all = await store.all<CatalogRow>(PREFIX_SQL, [JSON.stringify(ranges), MAX_PREFIX_ROWS + 1]);
  if (all.length <= MAX_PREFIX_ROWS) return all;
  // They don't, so later names may have got nothing: give each name an even
  // share of MAX_PREFIX_ROWS instead, half above it and half below.
  return store.all<CatalogRow>(PREFIX_NEAR_SQL, [JSON.stringify(ranges), prefixShare(queries.length)]);
}

/*
 * D1 bills every row a query scans, so each of these must search an index,
 * never scan the catalog; test/query-plans.test.ts checks their plans.
 * CROSS JOIN fixes SQLite's join order, so the json_each list drives index
 * lookups instead of the catalog driving a scan.
 */

/** Catalog rows whose normalized name falls in any [from, to) range. About one row read per row returned. */
export const PREFIX_SQL = `SELECT DISTINCT c.kind, c.key, c.ecosystem, c.name, c.vendor, c.product, c.normalized, c.label, c.count
  FROM json_each(?1) j
  CROSS JOIN catalog c ON c.normalized >= json_extract(j.value, '$[0]') AND c.normalized < json_extract(j.value, '$[1]')
  LIMIT ?2`;

/**
 * For each [from, to, name]: up to ?2 catalog rows either side of the name in
 * [from, to), nearest first. Each name gets its own share, so a busy prefix
 * can't use up a shared limit and leave later names with no rows at all (one
 * LIMIT over every range lost 58 of 200 names that way). Alphabetical
 * neighbours share the longest start with the name, so they're the likeliest
 * matches when a busy prefix has more rows than the share. D1 reads about
 * three rows per row returned here, so it's only the fallback for PREFIX_SQL.
 */
export const PREFIX_NEAR_SQL = `SELECT DISTINCT c.kind, c.key, c.ecosystem, c.name, c.vendor, c.product, c.normalized, c.label, c.count
  FROM json_each(?1) j
  CROSS JOIN catalog c ON c.rowid IN (
    SELECT rowid FROM (SELECT rowid FROM catalog
      WHERE normalized >= json_extract(j.value, '$[2]') AND normalized < json_extract(j.value, '$[1]') ORDER BY normalized LIMIT ?2)
    UNION ALL
    SELECT rowid FROM (SELECT rowid FROM catalog
      WHERE normalized >= json_extract(j.value, '$[0]') AND normalized < json_extract(j.value, '$[2]') ORDER BY normalized DESC LIMIT ?2))`;

/** Products of the given vendors, most-affected first. Product keys are `vendor/product`, and '0' sorts right after '/'. */
export const VENDOR_SQL = `SELECT c.kind, c.key, c.ecosystem, c.name, c.vendor, c.product, c.normalized, c.label, c.count
  FROM json_each(?1) j
  CROSS JOIN catalog c ON c.kind = 'product' AND c.key >= j.value || '/' AND c.key < j.value || '0'
  ORDER BY c.count DESC, c.key LIMIT ?2`;

/** Products with a key in any [from, to) range: the product lines' keys and key prefixes (lines.ts). */
export const KEY_RANGE_SQL = `SELECT c.kind, c.key, c.ecosystem, c.name, c.vendor, c.product, c.normalized, c.label, c.count
  FROM json_each(?1) j
  CROSS JOIN catalog c ON c.kind = 'product' AND c.key >= json_extract(j.value, '$[0]') AND c.key < json_extract(j.value, '$[1]')
  LIMIT ?2`;

/** Which of the given keys the catalog has. Naming both kinds lets the (kind, key) primary key answer it. */
export const KNOWN_KEYS_SQL = `SELECT kind, key FROM catalog
  WHERE kind IN ('package', 'product') AND key IN (SELECT value FROM json_each(?))`;

/**
 * Each vendor's top products, most-affected first. Reads only those rows
 * through catalog_vendor_count (migration 0006); VENDOR_SQL reads every
 * product of every vendor to sort them, about 12,000 rows for 200 big vendors.
 */
export const VENDOR_TOP_SQL = `SELECT c.kind, c.key, c.ecosystem, c.name, c.vendor, c.product, c.normalized, c.label, c.count
  FROM json_each(?1) j
  CROSS JOIN catalog c ON c.rowid IN (
    SELECT rowid FROM catalog WHERE kind = 'product' AND vendor = j.value ORDER BY count DESC, key LIMIT ?2)`;

async function productsByVendor(store: Store, vendors: string[]): Promise<CatalogRow[]> {
  return store.all<CatalogRow>(VENDOR_SQL, [JSON.stringify(vendors), MAX_PREFIX_ROWS]);
}

/**
 * Vendor rows in VENDOR_SQL's order (most-affected first, then key): every
 * product for vendors fetched in full, the top few for the rest.
 */
export function mergeVendorRows(all: CatalogRow[], top: CatalogRow[]): CatalogRow[] {
  const full = new Set(all.map((r) => r.vendor));
  return [...all, ...top.filter((r) => !full.has(r.vendor))].sort((a, b) => b.count - a.count || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

interface CatalogKey {
  kind: 'package' | 'product';
  key: string;
}

function catalogKey(item: string): CatalogKey {
  const p = parseStack(item)[0]!;
  return p.kind === 'package' ? { kind: 'package', key: `${p.ecosystem}:${p.name}` } : { kind: 'product', key: `${p.vendor}/${p.product}` };
}

/** `${kind} ${key}` for each of the given keys the catalog has. */
async function knownKeys(store: Store, keys: CatalogKey[]): Promise<Set<string>> {
  if (keys.length === 0) return new Set();
  const rows = await store.all<CatalogKey>(KNOWN_KEYS_SQL, [JSON.stringify([...new Set(keys.map((k) => k.key))])]);
  return new Set(rows.map((r) => `${r.kind} ${r.key}`));
}

function labelFor(item: string): string {
  const parsed = parseStack(item)[0]!;
  return parsed.kind === 'package' ? parsed.name : `${parsed.vendor} ${parsed.product}`.replace(/_/g, ' ');
}

/** Sørensen–Dice coefficient over character trigrams (with padding). */
export function similarity(a: string, b: string): number {
  return a === b ? 1 : dice(trigrams(a), trigrams(b));
}

type Grams = Map<string, number>;

function trigrams(s: string): Grams {
  const padded = `  ${s} `;
  const out: Grams = new Map();
  for (let i = 0; i < padded.length - 2; i++) {
    const g = padded.slice(i, i + 3);
    out.set(g, (out.get(g) ?? 0) + 1);
  }
  return out;
}

/** Strings by trigram, with each string's trigram total. */
interface GramIndex {
  totals: number[];
  postings: Map<string, [row: number, count: number][]>;
}

function gramIndex(strings: string[]): GramIndex {
  const postings: GramIndex['postings'] = new Map();
  const totals = strings.map((s, row) => {
    let total = 0;
    for (const [g, count] of trigrams(s)) {
      const list = postings.get(g) ?? postings.set(g, []).get(g)!;
      list.push([row, count]);
      total += count;
    }
    return total;
  });
  return { totals, postings };
}

/**
 * similarity(key, s) for every indexed string, touching only strings that
 * share a trigram with the key; the rest score 0. Comparing each name with
 * every row instead cost seconds for 200 names against 4,000 rows.
 */
function similarities(key: string, { totals, postings }: GramIndex): Float64Array {
  const shared = new Float64Array(totals.length);
  let keyTotal = 0;
  for (const [g, n] of trigrams(key)) {
    keyTotal += n;
    for (const [row, count] of postings.get(g) ?? []) shared[row]! += Math.min(n, count);
  }
  for (let row = 0; row < shared.length; row++) {
    const total = keyTotal + totals[row]!;
    shared[row] = total === 0 ? 0 : (2 * shared[row]!) / total;
  }
  return shared;
}

function dice(ga: Grams, gb: Grams): number {
  let shared = 0;
  let total = 0;
  for (const [g, n] of ga) {
    shared += Math.min(n, gb.get(g) ?? 0);
    total += n;
  }
  for (const n of gb.values()) total += n;
  return total === 0 ? 0 : (2 * shared) / total;
}
