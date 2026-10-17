import type { Store } from '../ingest/store';
import { addDays, utcDay } from '../lib/time';
import { parseComponent } from '../stack/format';
import type { VulnRow } from './components';

/**
 * Products attackers are working on: CVEs of a stack item that CISA added to
 * KEV in the last TARGETED_DAYS, whatever version they affect. A finding about
 * the component, like support dates. It never changes a CVE's band or score,
 * or Fix first's order.
 *
 * Why only a note (docs/plans/product-pressure.md): in a backtest over 2025–26,
 * a product with a KEV add in the last 90 days had another within 90 days
 * about a third of the time, 12 times the base rate. But lifting its other
 * CVEs made the ranking worse, since the next KEV add is usually a new CVE.
 * So it says "patch this product's next advisory quickly", not "these CVEs
 * matter more".
 *
 * Free: a component's data already holds every stored vuln for it, and ingest
 * keeps every CVE added to KEV within the keep window whatever its age
 * (keptLonger() in src/ingest/retention.ts).
 */
export const TARGETED_DAYS = 90;

export interface KevAdd {
  id: string;
  /** The day CISA added it to KEV, YYYY-MM-DD. */
  addedAt: string;
}

/** The item's CVEs CISA added to KEV in the last TARGETED_DAYS, newest first; empty when none. */
export function recentKev(vulns: readonly Pick<VulnRow, 'id' | 'kev_added_at'>[], now: Date): KevAdd[] {
  const after = utcDay(addDays(now, -TARGETED_DAYS));
  const today = utcDay(now);
  const out: KevAdd[] = [];
  for (const v of vulns) {
    const day = v.kev_added_at?.slice(0, 10);
    if (day && day > after && day <= today) out.push({ id: v.id, addedAt: day });
  }
  return out.sort((a, b) => b.addedAt.localeCompare(a.addedAt) || a.id.localeCompare(b.id));
}

/**
 * Every product row of a CVE CISA added to KEV since a date. For a pasted CVE
 * list, whose CVEs don't load their products' data the way stack items do.
 * CROSS JOIN keeps vulns outer, so it walks vulns_kev_added_at (about 60 CVEs
 * in 90 days) and each one's affected rows: a few hundred rows read, whatever
 * the list's size (test/query-plans.test.ts).
 */
export const RECENT_KEV_PRODUCTS_SQL = `SELECT v.id, v.kev_added_at, a.vendor, a.product FROM vulns v CROSS JOIN affected a ON a.vuln_id = v.id
  WHERE v.kev_added_at >= ? AND a.kind = 'product'`;

/** Recent KEV adds by product key ("ivanti/connect_secure"), each newest first, in one query. */
export async function recentKevByProduct(store: Store, now: Date): Promise<Map<string, KevAdd[]>> {
  type Row = { id: string; kev_added_at: string | null; vendor: string | null; product: string | null };
  const rows = await store.all<Row>(RECENT_KEV_PRODUCTS_SQL, [utcDay(addDays(now, -TARGETED_DAYS))]);
  const byKey = new Map<string, Map<string, Pick<VulnRow, 'id' | 'kev_added_at'>>>();
  for (const r of rows) {
    if (!r.vendor || !r.product) continue;
    const key = `${r.vendor}/${r.product}`;
    if (!byKey.has(key)) byKey.set(key, new Map());
    // A CVE can name a product twice (its CVE record and KEV): once each.
    byKey.get(key)!.set(r.id, r);
  }
  return new Map([...byKey].flatMap(([key, vulns]) => {
    const kev = recentKev([...vulns.values()], now);
    return kev.length > 0 ? [[key, kev] as const] : [];
  }));
}

/** The product's label when it has one (a listed CVE's group), else the first item without version or tags: "ivanti/connect_secure". */
export function targetedName(t: { items: string[]; label?: string }): string {
  if (t.label) return t.label;
  const item = t.items[0] ?? '';
  try {
    const c = parseComponent(item);
    return c.kind === 'product' ? `${c.vendor}/${c.product}` : c.name;
  } catch {
    return item;
  }
}

/** What a notice tells a reader of the Atom feed. Only KEV earns "exploited", and this is KEV. */
export function targetedText(t: { items: string[]; kev: readonly KevAdd[] }): string[] {
  const latest = t.kev[0]!;
  const n = t.kev.length;
  return [
    `CISA added ${n === 1 ? 'one of its CVEs' : `${n} of its CVEs`} to its Known Exploited Vulnerabilities catalog in the last ${TARGETED_DAYS} days, most recently ${latest.id} on ${latest.addedAt}.`,
    'Attackers are exploiting this product. 1 in 3 products with a KEV add get another within 90 days, so patch its next advisory within days and check whether it faces the internet.',
  ];
}
