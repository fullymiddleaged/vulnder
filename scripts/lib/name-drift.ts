import { vendorFamily, vendorSpellings } from '../../src/resolve/aliases';
import { inLine, PRODUCT_LINES } from '../../src/resolve/lines';
import { EOL_PRODUCTS, EOL_SLUGS } from '../../src/stack/eol';

export interface CatalogProduct {
  key: string;
  vendor: string;
  product: string;
  /** CVEs in the window. */
  count: number;
}

/** Below this many CVEs a key is too small to be worth a table edit. */
export const DRIFT_MIN_COUNT = 5;

/**
 * Where the curated tables (product lines in src/resolve/lines.ts, vendor
 * spellings in src/resolve/aliases.ts) have fallen behind the catalog. CNAs
 * rename products and vendors without notice, so this runs against real data:
 *
 * - a line with nothing in the catalog;
 * - a product of a line's vendor whose key holds the line's product name but
 *   isn't in the line (a new spelling, or an add-on the line should keep out);
 * - two vendor keys, one the other plus a suffix (`zoom`, `zoom_communications`),
 *   not yet one family;
 * - an endoflife.date product in src/stack/eol.ts that no catalog key maps to.
 *
 * Each is a lead to check by hand, not a verdict.
 */
export function nameDrift(rows: CatalogProduct[]): string[] {
  const out: string[] = [];
  const big = rows.filter((r) => r.count >= DRIFT_MIN_COUNT);

  for (const line of PRODUCT_LINES) {
    if (line.keys.length === 0) continue;
    const name = line.names[0]!;
    const members = rows.filter((r) => inLine(line, r.key));
    if (members.length === 0) out.push(`line "${name}": nothing in the catalog (keys: ${line.keys.join(', ')})`);
    const vendors = new Set(line.keys.flatMap((k) => vendorSpellings(vendorFamily(k.split('/')[0]!))));
    const stems = [...new Set(line.keys.map((k) => k.split('/')[1]!.replace(/\*$/, '').replace(/_$/, '')))];
    const prefixes = line.keys.filter((k) => k.endsWith('*')).map((k) => k.slice(0, -1));
    for (const r of big) {
      if (!vendors.has(r.vendor) || inLine(line, r.key)) continue;
      // Left out on purpose: under a prefix `keep` turned away, or another line's.
      if (prefixes.some((p) => r.key.startsWith(p)) || PRODUCT_LINES.some((other) => other !== line && inLine(other, r.key))) continue;
      if (stems.some((s) => r.product.includes(s))) out.push(`line "${name}": ${r.key} (${r.count}) shares its name but isn't in it`);
    }
  }

  // Support dates (src/stack/eol.ts): a product none of whose keys is in the catalog can't flag anything.
  for (const slug of EOL_SLUGS) {
    const entries = EOL_PRODUCTS.filter((p) => p.slug === slug);
    if (!rows.some((r) => entries.some((p) => p.keys.test(r.key)))) out.push(`support dates "${slug}": no catalog key matches (${entries.map((p) => p.keys.source).join(', ')})`);
  }

  const totals = new Map<string, number>();
  for (const r of rows) totals.set(r.vendor, (totals.get(r.vendor) ?? 0) + r.count);
  const vendors = [...totals.keys()].filter((v) => totals.get(v)! >= DRIFT_MIN_COUNT).sort();
  for (const longer of vendors) {
    for (const shorter of vendors) {
      if (longer === shorter || !longer.startsWith(`${shorter}_`) || vendorFamily(longer) === vendorFamily(shorter)) continue;
      out.push(`vendor "${shorter}" (${totals.get(shorter)}) and "${longer}" (${totals.get(longer)}) may be one vendor`);
    }
  }
  return out;
}
