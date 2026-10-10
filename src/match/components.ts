import { allForKeys, type Store } from '../ingest/store';
import { eolTarget } from '../stack/eol';
import type { StackItem } from '../stack/format';
import type { CveSupport, EolRelease } from './support';

/**
 * What the feed knows about one component (a package or product): its
 * affected rows, every stored vuln they point to (the whole retention window,
 * so any `days` can be served from it), the exploited members of those
 * vulns' families, and its vendor support dates. Loaded per component rather
 * than per stack, so a component is read from D1 at most once per cache
 * period and data version, however many stacks or windows ask for it.
 */
export interface ComponentData {
  affected: AffectedRow[];
  vulns: VulnRow[];
  exploited: { id: string; family_id: string }[];
  /** Release lines of the endoflife.date product it maps to (src/stack/eol.ts); absent in entries cached before support data. */
  eol?: EolRelease[];
  /** Its latest CVE's "unsupported-when-assigned" tag, when a tagged CVE has named it. */
  cveSupport?: CveSupport | null;
}

/** Where loaded components are kept between requests (the Cache API in the Worker). */
export interface ComponentCache {
  get(key: string): Promise<ComponentData | null>;
  /** May finish in the background; a returned promise is awaited. */
  put(key: string, data: ComponentData): Promise<void> | void;
}

export interface AffectedRow {
  vuln_id: string;
  source: string;
  kind: 'package' | 'product';
  ecosystem: string | null;
  package_name: string | null;
  vendor: string | null;
  product: string | null;
  fixed_version: string | null;
}

export interface VulnRow {
  id: string;
  aliases: string;
  title: string | null;
  summary: string | null;
  published_at: string | null;
  modified_at: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  severity_label: string | null;
  cwe: string;
  epss: number | null;
  epss_percentile: number | null;
  epss_date: string | null;
  lev_log: number;
  kev_added_at: string | null;
  kev_ransomware: number;
  kev_due_date: string | null;
  kev_required_action: string | null;
  ssvc: string | null;
  refs: string;
  family_id: string | null;
  last_event_at: string | null;
}

export const itemKey = (item: StackItem) =>
  item.kind === 'package' ? `pkg:${item.ecosystem}:${item.name}` : `prod:${item.vendor}/${item.product}`;
export const rowKey = (r: AffectedRow) => (r.kind === 'package' ? `pkg:${r.ecosystem}:${r.package_name}` : `prod:${r.vendor}/${r.product}`);

/*
 * Each searches an index by the keys in the json_each list
 * (test/query-plans.test.ts checks this), so a load reads only the rows it uses.
 */
const AFFECTED_COLS = 'vuln_id, source, kind, ecosystem, package_name, vendor, product, fixed_version';
export const AFFECTED_PACKAGES_SQL = `SELECT ${AFFECTED_COLS} FROM affected WHERE kind = 'package'
  AND (ecosystem, package_name) IN (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?))`;
export const AFFECTED_PRODUCTS_SQL = `SELECT ${AFFECTED_COLS} FROM affected WHERE kind = 'product'
  AND (vendor, product) IN (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?))`;
export const VULNS_BY_ID_SQL = `SELECT id, aliases, title, summary, published_at, modified_at, cvss_score, cvss_vector, severity_label, cwe, epss,
    epss_percentile, epss_date, lev_log, kev_added_at, kev_ransomware, kev_due_date, kev_required_action, ssvc, refs, family_id,
    last_event_at
  FROM vulns WHERE id IN (SELECT value FROM json_each(?))`;
/** Members of these families with evidence of exploitation, wherever they are in time. */
export const EXPLOITED_IN_FAMILIES_SQL = `SELECT id, family_id FROM vulns
  WHERE family_id IN (SELECT value FROM json_each(?))
    AND (kev_added_at IS NOT NULL OR lower(json_extract(ssvc, '$.exploitation')) = 'active')`;
/** Release lines of these endoflife.date products: a few dozen rows each. */
export const EOL_RELEASES_SQL = `SELECT slug, release, label, eol_from, is_eol, eoes_from FROM eol_releases
  WHERE slug IN (SELECT value FROM json_each(?))`;
export const EOL_CVE_SQL = `SELECT key, last_cve, last_published, tagged FROM eol_cve WHERE key IN (SELECT value FROM json_each(?))`;
/**
 * Keys per query: 2,000 IDs is about 45 KB of JSON, so the biggest stack stays
 * around 15 D1 queries, well inside Workers Free's 50 per request. Rows read
 * are the same however the keys are chunked.
 */
export const FEED_CHUNK = 2000;

/** The data for each distinct component among `items` (by itemKey), from the cache where it can. */
export async function loadComponents(store: Store, items: StackItem[], cache?: ComponentCache): Promise<Map<string, ComponentData>> {
  const wanted = new Map<string, StackItem>();
  for (const item of items) if (!wanted.has(itemKey(item))) wanted.set(itemKey(item), item);

  const found = new Map<string, ComponentData>();
  if (cache) {
    await Promise.all(
      [...wanted.keys()].map(async (k) => {
        const hit = await cache.get(k);
        if (hit) found.set(k, hit);
      }),
    );
  }
  const missing = [...wanted].filter(([k]) => !found.has(k)).map(([, item]) => item);
  if (missing.length > 0) {
    const loaded = await fetchComponents(store, missing);
    const puts: Promise<void>[] = [];
    for (const [k, data] of loaded) {
      found.set(k, data);
      const put = cache?.put(k, data);
      if (put) puts.push(put);
    }
    await Promise.all(puts);
  }
  return found;
}

/** Reads components from D1: affected rows, their vulns, then exploited family members. */
async function fetchComponents(store: Store, items: StackItem[]): Promise<Map<string, ComponentData>> {
  const packages = items.flatMap((i) => (i.kind === 'package' ? [[i.ecosystem, i.name]] : []));
  const products = items.flatMap((i) => (i.kind === 'product' ? [[i.vendor, i.product]] : []));
  const affected: AffectedRow[] = [];
  if (packages.length > 0) affected.push(...(await store.all<AffectedRow>(AFFECTED_PACKAGES_SQL, [JSON.stringify(packages)])));
  if (products.length > 0) affected.push(...(await store.all<AffectedRow>(AFFECTED_PRODUCTS_SQL, [JSON.stringify(products)])));

  const vulns = new Map(
    (await allForKeys<VulnRow>(store, VULNS_BY_ID_SQL, affected.map((a) => a.vuln_id), FEED_CHUNK)).map((v) => [v.id, v]),
  );
  const familyIds = [...vulns.values()].map((v) => v.family_id).filter((f): f is string => !!f);
  const exploited = familyIds.length === 0 ? [] : await allForKeys<{ id: string; family_id: string }>(store, EXPLOITED_IN_FAMILIES_SQL, familyIds, FEED_CHUNK);

  // Support data: by endoflife.date product, and by product key for the CVE tag.
  const productItems = items.filter((i): i is Extract<StackItem, { kind: 'product' }> => i.kind === 'product');
  const slugOf = new Map(productItems.map((i) => [itemKey(i), eolTarget(i)?.slug ?? null]));
  const slugs = [...new Set([...slugOf.values()].filter((s): s is string => s !== null))];
  const releases = slugs.length === 0 ? [] : await allForKeys<EolRelease>(store, EOL_RELEASES_SQL, slugs, FEED_CHUNK);
  const tags =
    productItems.length === 0 ? [] : await allForKeys<CveSupport>(store, EOL_CVE_SQL, productItems.map((i) => `${i.vendor}/${i.product}`), FEED_CHUNK);
  const tagOf = new Map(tags.map((t) => [`prod:${t.key}`, t]));

  const out = new Map<string, ComponentData>(
    items.map((i) => {
      const k = itemKey(i);
      const slug = slugOf.get(k) ?? null;
      return [k, { affected: [], vulns: [], exploited: [], eol: slug ? releases.filter((r) => r.slug === slug) : [], cveSupport: tagOf.get(k) ?? null }];
    }),
  );
  const vulnsOf = new Map<string, Set<string>>();
  for (const a of affected) {
    const data = out.get(rowKey(a));
    // Pruned between the two reads: nothing to show.
    if (!data || !vulns.has(a.vuln_id)) continue;
    data.affected.push(a);
    if (!vulnsOf.has(rowKey(a))) vulnsOf.set(rowKey(a), new Set());
    vulnsOf.get(rowKey(a))!.add(a.vuln_id);
  }
  for (const [k, ids] of vulnsOf) {
    const data = out.get(k)!;
    data.vulns = [...ids].map((id) => vulns.get(id)!);
    const families = new Set(data.vulns.map((v) => v.family_id).filter(Boolean));
    data.exploited = exploited.filter((e) => families.has(e.family_id));
  }
  return out;
}
