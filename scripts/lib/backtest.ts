import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import { EPSS_HIGH } from '../../src/config';
import { epssFileUrl, parseEpssLine } from '../../src/ingest/sources/epss';
import { parseSeverityLabel, type SeverityLabel, type Ssvc } from '../../src/ingest/types';
import { daysBetween } from '../../src/lib/lev';
import { assess, comparePriority, reach, type Priority, type Signals } from '../../src/match/priority';
import type { Role } from '../../src/match/roles';
import { isEdgeDevice } from '../../src/stack/teams';

/**
 * Backtest for the ranking (docs/plans/chain-risk-and-cve-roles.md, phase 0):
 * how Vulnder would have ranked CVEs before CISA added them to KEV, using only
 * what was known then. Every ranking goes through the real assess(), so the
 * backtest can't drift from production. Pure apart from loadEpss, which takes
 * its fetch from the caller.
 *
 * Point in time: EPSS from the dated file on or before each date; KEV only once
 * added; age from the date. SSVC "exploitation" is dropped (CISA often sets it
 * to active after KEV, which would leak the answer); exploit code is off unless
 * asked for, since we don't know when it appeared; LEV and families are off.
 */

export const DAY_MS = 86_400_000;
/** EPSS v4 replaced v3 in the daily files from this date. */
export const EPSS_V4_DATE = '2025-03-17';
/** A KEV CVE counts as new when published at most this long before it was added. */
export const NEW_DAYS = 365;
/** The monthly population: CVEs published in the 90 days before a snapshot. */
export const POPULATION_DAYS = 90;
/** How far ahead a monthly snapshot looks for KEV adds. */
export const HORIZON_DAYS = 90;

export function addDays(day: string, n: number): string {
  return new Date(Date.parse(`${day.slice(0, 10)}T00:00:00Z`) + n * DAY_MS).toISOString().slice(0, 10);
}

/** Every Monday from `from` to `to`, inclusive. */
export function mondays(from: string, to: string): string[] {
  const out: string[] = [];
  const start = new Date(`${from}T00:00:00Z`);
  let day = addDays(from, (8 - start.getUTCDay()) % 7);
  while (day <= to) {
    out.push(day);
    day = addDays(day, 7);
  }
  return out;
}

/** The latest of `sorted` on or before `day`, or null. */
export function onOrBefore(sorted: readonly string[], day: string): string | null {
  let lo = 0;
  let hi = sorted.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (sorted[mid]! <= day) lo = mid + 1;
    else hi = mid;
  }
  return lo === 0 ? null : sorted[lo - 1]!;
}

/** How many of `sorted` fall in [from, to). */
export function countIn(sorted: readonly string[], from: string, to: string): number {
  const below = (d: string) => {
    let lo = 0;
    let hi = sorted.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (sorted[mid]! < d) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  };
  return Math.max(0, below(to) - below(from));
}

/** Whole days between two dates, in either order. */
export function apart(a: string, b: string): number {
  return a <= b ? daysBetween(a, b) : daysBetween(b, a);
}

export function median(xs: number[]): number | null {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2;
}

// ---------- CVEs ----------

/** A cve_index row, as the script reads it. */
export interface IndexRow {
  id: string;
  published_at: string | null;
  title: string | null;
  product: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  severity_label: string | null;
  ssvc: string | null;
  kev_added_at: string | null;
  kev_ransomware: number;
}

export interface Cve {
  id: string;
  /** YYYY-MM-DD, or null when the record has no date. */
  published: string | null;
  title: string | null;
  product: string | null;
  cvss: number | null;
  vector: string | null;
  label: SeverityLabel | null;
  /** CISA's SSVC without "exploitation", which would leak the answer. */
  ssvc: Ssvc | null;
  /** YYYY-MM-DD it was added to KEV, or null. */
  kevAdded: string | null;
  ransomware: boolean;
  edge: boolean;
  role: Role;
  /** Today's exploit signals, only when the run asks for them (an upper bound). */
  exploit?: Signals['exploit'];
}

export function toCve(row: IndexRow, role: Role, exploit?: Signals['exploit']): Cve {
  let ssvc: Ssvc | null = null;
  try {
    const s = row.ssvc ? (JSON.parse(row.ssvc) as Partial<Ssvc>) : null;
    if (s) ssvc = { exploitation: null, automatable: s.automatable ?? null, technicalImpact: s.technicalImpact ?? null };
  } catch {
    ssvc = null;
  }
  const slash = row.product?.indexOf('/') ?? -1;
  const edge =
    slash > 0 && isEdgeDevice({ kind: 'product', vendor: row.product!.slice(0, slash), product: row.product!.slice(slash + 1), version: null });
  return {
    id: row.id,
    published: row.published_at?.slice(0, 10) ?? null,
    title: row.title,
    product: row.product,
    cvss: row.cvss_score,
    vector: row.cvss_vector,
    label: parseSeverityLabel(row.severity_label),
    ssvc,
    kevAdded: row.kev_added_at?.slice(0, 10) ?? null,
    ransomware: row.kev_ransomware === 1,
    edge,
    role,
    ...(exploit && { exploit }),
  };
}

/** What assess() would have seen on `day`. `vector` replaces the CVE's own (the chain rule). */
export function signalsAt(c: Cve, day: string, epss: number | null, vector: string | null = c.vector): Signals {
  const onKev = c.kevAdded !== null && c.kevAdded <= day;
  return {
    kevAddedAt: onKev ? c.kevAdded : null,
    knownRansomware: onKev && c.ransomware,
    epss,
    lev: null,
    exploitedSibling: null,
    cvss: c.cvss,
    cvssVector: vector,
    severityLabel: c.label,
    ssvc: c.ssvc,
    edge: c.edge,
    ageDays: c.published ? daysBetween(c.published, day) : null,
    ...(c.exploit && { exploit: c.exploit }),
  };
}

// ---------- Chain rule 1, offline ----------

/** The vector with its login requirement removed. */
export function dropLogin(vector: string): string {
  return vector.replace(/\/PR:[LH](?=\/|$)/, '/PR:N');
}

const needsLogin = (v: string | null) => reach(v)?.barriers.includes('a login') ?? false;
const noLogin = (v: string | null) => {
  const r = reach(v);
  return r !== null && !r.barriers.includes('a login');
};

/** CVEs by product, for the chain rule. */
export function byProduct(cves: readonly Cve[]): Map<string, Cve[]> {
  const out = new Map<string, Cve[]>();
  for (const c of cves) {
    if (!c.product) continue;
    if (!out.has(c.product)) out.set(c.product, []);
    out.get(c.product)!.push(c);
  }
  return out;
}

/**
 * Chain rule 1: a code-exec CVE that needs a login, in a product with an auth
 * bypass anyone can reach published by `day`, counts as needing no login. The
 * vector it would be ranked with, or null when the rule doesn't apply.
 */
export function chainVector(c: Cve, day: string, products: ReadonlyMap<string, readonly Cve[]>): { vector: string; enabler: string } | null {
  if (c.role !== 'code-exec' || !c.product || !c.vector || !needsLogin(c.vector)) return null;
  const enabler = products
    .get(c.product)
    ?.find((e) => e.id !== c.id && e.role === 'auth-bypass' && e.published !== null && e.published <= day && noLogin(e.vector));
  return enabler ? { vector: dropLogin(c.vector), enabler: enabler.id } : null;
}

// ---------- Product KEV, offline ----------

/** How far back another CVE's KEV add in the same product counts. */
export const PRODUCT_KEV_DAYS = 90;
/** The score-only variant's weight: the same as an edge device's. */
export const PRODUCT_KEV_BOOST = 1.25;

export type KevByProduct = Map<string, { id: string; day: string }[]>;

/** KEV adds per product, newest first. */
export function kevByProduct(cves: readonly Cve[]): KevByProduct {
  const out: KevByProduct = new Map();
  for (const c of cves) {
    if (!c.product || !c.kevAdded) continue;
    if (!out.has(c.product)) out.set(c.product, []);
    out.get(c.product)!.push({ id: c.id, day: c.kevAdded });
  }
  for (const list of out.values()) list.sort((a, b) => b.day.localeCompare(a.day) || a.id.localeCompare(b.id));
  return out;
}

/** The latest other CVE in the same product added to KEV in the PRODUCT_KEV_DAYS up to `day`, or null. */
export function productKev(c: Cve, day: string, kev: KevByProduct): string | null {
  if (!c.product) return null;
  const from = addDays(day, -PRODUCT_KEV_DAYS);
  return kev.get(c.product)?.find((k) => k.id !== c.id && k.day <= day && k.day > from)?.id ?? null;
}

// ---------- Rankers ----------

export type Ranker = 'cvss' | 'epss' | 'assess';
export interface Variant {
  name: string;
  ranker: Ranker;
  chain?: boolean;
  /**
   * Another CVE in the product on KEV in the last 90 days: 'attend' counts it
   * like an exploited family sibling (Attend, sibling threat); 'score' only
   * weights the score by PRODUCT_KEV_BOOST.
   */
  productKev?: 'attend' | 'score';
}

export interface Ranked {
  priority: Priority;
  score: number;
  respondWithinHours?: number | null;
}

/**
 * One CVE on one day under a variant. Baselines put what they flag in Attend
 * and the rest in Track, scored by their one signal, so comparePriority orders
 * all three the same way.
 */
export function rankAt(c: Cve, day: string, epss: number | null, v: Variant, products: ReadonlyMap<string, readonly Cve[]>, kev: KevByProduct = new Map()): Ranked {
  if (v.ranker === 'cvss') {
    const flagged = (c.cvss ?? 0) >= 9 || (c.cvss === null && c.label === 'critical');
    return { priority: flagged ? 'attend' : 'track', score: c.cvss ?? (c.label === 'critical' ? 9 : 0) };
  }
  if (v.ranker === 'epss') {
    const flagged = epss !== null && epss >= EPSS_HIGH - 1e-9;
    return { priority: flagged ? 'attend' : 'track', score: (epss ?? 0) * 100 };
  }
  const vector = v.chain ? (chainVector(c, day, products)?.vector ?? c.vector) : c.vector;
  const sibling = v.productKev ? productKev(c, day, kev) : null;
  const signals = signalsAt(c, day, epss, vector);
  const a = assess(v.productKev === 'attend' && sibling ? { ...signals, exploitedSibling: sibling } : signals);
  const score = v.productKev === 'score' && sibling ? Math.min(100, Math.round(a.score * PRODUCT_KEV_BOOST * 10) / 10) : a.score;
  return { priority: a.priority, score, respondWithinHours: a.respondWithinHours };
}

export const isFlagged = (r: Ranked) => r.priority === 'act' || r.priority === 'attend';

// ---------- EPSS files ----------

/**
 * EPSS scores on `day` for the CVEs in `wanted`, from the dated file (cached in
 * `cacheDir`). A day with no file falls back up to three days earlier. Null
 * when none of them has one.
 */
export async function loadEpss(
  day: string,
  wanted: ReadonlySet<string>,
  opts: { fetchFn: typeof fetch; cacheDir: string; log?: (m: string) => void },
): Promise<{ day: string; scores: Map<string, number> } | null> {
  for (let back = 0; back <= 3; back++) {
    const d = addDays(day, -back);
    const file = path.join(opts.cacheDir, `epss_scores-${d}.csv.gz`);
    let gz: Uint8Array;
    if (existsSync(file)) gz = await readFile(file);
    else {
      opts.log?.(`downloading EPSS ${d}`);
      const res = await opts.fetchFn(epssFileUrl(d), { signal: AbortSignal.timeout(120_000) });
      if (res.status === 404 || res.status === 403) continue;
      if (!res.ok) throw new Error(`EPSS ${d}: HTTP ${res.status}`);
      gz = new Uint8Array(await res.arrayBuffer());
      await mkdir(opts.cacheDir, { recursive: true });
      await writeFile(file, gz);
    }
    const scores = new Map<string, number>();
    for (const line of gunzipSync(gz).toString('utf8').split('\n')) {
      const p = parseEpssLine(line);
      if (p && wanted.has(p.cve)) scores.set(p.cve, p.epss);
    }
    return { day: d, scores };
  }
  return null;
}

// ---------- The ranking backtest ----------

export interface BacktestInput {
  cves: Cve[];
  variants: Variant[];
  /** KEV adds from this day count as cases; monthly snapshots start here too. */
  kevFrom: string;
  /** The last day with data. */
  to: string;
  /** The first weekly EPSS snapshot. */
  epssFrom: string;
  loadEpss: (day: string, wanted: ReadonlySet<string>) => Promise<{ day: string; scores: Map<string, number> } | null>;
  log?: (m: string) => void;
}

export interface KevRecall {
  variant: string;
  group: string;
  offsetDays: number;
  /** KEV cases already published at the snapshot. */
  cases: number;
  flagged: number;
  /** Published after the snapshot: a zero-day or close to one, which no ranking could have flagged. */
  notYetPublished: number;
}

export interface MonthlyRow {
  variant: string;
  snapshots: number;
  population: number;
  flagged: number;
  /** CVEs added to KEV within HORIZON_DAYS of a snapshot. */
  positives: number;
  positivesFlagged: number;
  top1: number;
  top1Hits: number;
  top5: number;
  top5Hits: number;
}

export interface LeadRow {
  variant: string;
  cases: number;
  flaggedBefore: number;
  medianLeadDays: number | null;
}

export interface ChainPairs {
  pairs: number;
  liftedAtT7: number;
  examples: string[];
}

export interface BacktestReport {
  kev: KevRecall[];
  monthly: MonthlyRow[];
  lead: LeadRow[];
  chain?: { lifted: number; liftedNeverKev: number; pairs: ChainPairs };
  /** Monthly CVE-snapshots with another CVE of their product on KEV in the last 90 days, and how many were themselves added within 90 days after. */
  productKev?: { lifted: number; liftedPositive: number };
  snapshotsMissing: string[];
}

interface Task {
  kind: 'kev' | 'lead' | 'month';
  cve: Cve;
  offset?: number;
  month?: string;
}

/**
 * Runs every variant over:
 * - KEV recall: each CVE added to KEV from kevFrom, at T-7 and T-30, split by
 *   new and old CVEs and by EPSS model.
 * - Monthly snapshots: CVEs published in the 90 days before each first Monday
 *   of the month, not on KEV yet. Flag volume, KEV adds within 90 days per
 *   1,000 flags, recall, and KEV hits in the top 1% and 5% by comparePriority.
 * - Lead time: for new KEV CVEs, the first weekly snapshot that flagged them.
 * EPSS files load one at a time, oldest first.
 */
export async function runBacktest(input: BacktestInput): Promise<BacktestReport> {
  const { cves, variants } = input;
  const weeks = mondays(input.epssFrom, input.to);
  const products = byProduct(cves);
  const kev = kevByProduct(cves);
  const tasks = new Map<string, Task[]>();
  const push = (day: string | null, t: Task) => {
    if (!day) return;
    if (!tasks.has(day)) tasks.set(day, []);
    tasks.get(day)!.push(t);
  };

  const cases = cves.filter((c) => c.kevAdded !== null && c.kevAdded >= input.kevFrom && c.kevAdded <= input.to);
  const kevTally = new Map<string, KevRecall>();
  const tally = (variant: string, group: string, offsetDays: number) => {
    const key = `${variant}|${group}|${offsetDays}`;
    if (!kevTally.has(key)) kevTally.set(key, { variant, group, offsetDays, cases: 0, flagged: 0, notYetPublished: 0 });
    return kevTally.get(key)!;
  };
  const groupsOf = (c: Cve, snap: string) => [
    'all',
    c.published && daysBetween(c.published, c.kevAdded!) <= NEW_DAYS ? 'new' : 'old',
    snap < EPSS_V4_DATE ? 'EPSS v3' : 'EPSS v4',
  ];

  for (const c of cases) {
    for (const offset of [7, 30]) {
      const snap = onOrBefore(weeks, addDays(c.kevAdded!, -offset));
      if (!snap) continue;
      if (!c.published || c.published > snap) {
        for (const v of variants) for (const g of groupsOf(c, snap)) tally(v.name, g, offset).notYetPublished++;
        continue;
      }
      push(snap, { kind: 'kev', cve: c, offset });
    }
    if (c.published && daysBetween(c.published, c.kevAdded!) <= NEW_DAYS) {
      for (const w of weeks) if (w >= c.published && w < c.kevAdded!) push(w, { kind: 'lead', cve: c });
    }
  }

  const months = weeks.filter((w) => w >= input.kevFrom && Number(w.slice(8)) <= 7 && addDays(w, HORIZON_DAYS) <= input.to);
  for (const m of months) {
    const from = addDays(m, -POPULATION_DAYS);
    for (const c of cves) {
      if (!c.published || c.published < from || c.published > m) continue;
      if (c.kevAdded !== null && c.kevAdded <= m) continue;
      push(m, { kind: 'month', cve: c, month: m });
    }
  }

  const monthly = new Map(variants.map((v) => [v.name, { variant: v.name, snapshots: 0, population: 0, flagged: 0, positives: 0, positivesFlagged: 0, top1: 0, top1Hits: 0, top5: 0, top5Hits: 0 }]));
  const firstFlag = new Map<string, string>();
  const leadCases = new Set<string>();
  let lifted = 0;
  let liftedNeverKev = 0;
  const pk = { lifted: 0, liftedPositive: 0 };
  const missing: string[] = [];

  for (const day of [...tasks.keys()].sort()) {
    const list = tasks.get(day)!;
    const wanted = new Set(list.map((t) => t.cve.id));
    const loaded = await input.loadEpss(day, wanted);
    if (!loaded) missing.push(day);
    const epssOf = (id: string) => loaded?.scores.get(id) ?? null;

    const pop: { cve: Cve; ranks: Ranked[] }[] = [];
    for (const t of list) {
      const ranks = variants.map((v) => rankAt(t.cve, day, epssOf(t.cve.id), v, products, kev));
      if (t.kind === 'kev') {
        variants.forEach((v, i) => {
          for (const g of groupsOf(t.cve, day)) {
            const r = tally(v.name, g, t.offset!);
            r.cases++;
            if (isFlagged(ranks[i]!)) r.flagged++;
          }
        });
      } else if (t.kind === 'lead') {
        leadCases.add(t.cve.id);
        variants.forEach((v, i) => {
          const key = `${v.name}|${t.cve.id}`;
          if (isFlagged(ranks[i]!) && !firstFlag.has(key)) firstFlag.set(key, day);
        });
      } else {
        pop.push({ cve: t.cve, ranks });
        if (variants.some((v) => v.chain) && chainVector(t.cve, day, products)) {
          lifted++;
          if (t.cve.kevAdded === null) liftedNeverKev++;
        }
        if (variants.some((v) => v.productKev) && productKev(t.cve, day, kev)) {
          pk.lifted++;
          if (t.cve.kevAdded !== null && t.cve.kevAdded <= addDays(day, HORIZON_DAYS)) pk.liftedPositive++;
        }
      }
    }

    if (pop.length > 0) {
      const horizon = addDays(day, HORIZON_DAYS);
      const positive = (c: Cve) => c.kevAdded !== null && c.kevAdded > day && c.kevAdded <= horizon;
      const n1 = Math.max(1, Math.ceil(pop.length * 0.01));
      const n5 = Math.max(1, Math.ceil(pop.length * 0.05));
      variants.forEach((v, i) => {
        const row = monthly.get(v.name)!;
        row.snapshots++;
        row.population += pop.length;
        // Ties keep ID order, so a baseline with many equal scores can't look better by luck of input order.
        const sorted = [...pop].sort((a, b) => comparePriority(a.ranks[i]!, b.ranks[i]!) || a.cve.id.localeCompare(b.cve.id));
        sorted.forEach((p, rank) => {
          const pos = positive(p.cve);
          if (isFlagged(p.ranks[i]!)) {
            row.flagged++;
            if (pos) row.positivesFlagged++;
          }
          if (pos) row.positives++;
          if (rank < n1 && pos) row.top1Hits++;
          if (rank < n5 && pos) row.top5Hits++;
        });
        row.top1 += n1;
        row.top5 += n5;
      });
    }
  }

  const kevAddedOf = new Map(cases.map((c) => [c.id, c.kevAdded!]));
  const lead: LeadRow[] = variants.map((v) => {
    const days: number[] = [];
    for (const id of leadCases) {
      const first = firstFlag.get(`${v.name}|${id}`);
      if (first) days.push(daysBetween(first, kevAddedOf.get(id)!));
    }
    return { variant: v.name, cases: leadCases.size, flaggedBefore: days.length, medianLeadDays: median(days) };
  });

  const report: BacktestReport = {
    kev: [...kevTally.values()],
    monthly: [...monthly.values()],
    lead,
    snapshotsMissing: missing,
  };
  if (variants.some((v) => v.chain)) report.chain = { lifted, liftedNeverKev, pairs: chainPairs(cases, weeks, products) };
  if (variants.some((v) => v.productKev)) report.productKev = pk;
  return report;
}

/**
 * Same-product KEV pairs added within 7 days of each other, one an auth
 * bypass anyone can reach and the other a code-exec bug behind a login (the
 * Ivanti case), and how many of those the chain rule would have lifted at T-7.
 */
export function chainPairs(cases: readonly Cve[], weeks: readonly string[], products: ReadonlyMap<string, readonly Cve[]>): ChainPairs {
  const out: ChainPairs = { pairs: 0, liftedAtT7: 0, examples: [] };
  for (const exec of cases) {
    if (exec.role !== 'code-exec' || !needsLogin(exec.vector) || !exec.product) continue;
    const partner = cases.find((b) => b.product === exec.product && b.role === 'auth-bypass' && noLogin(b.vector) && apart(b.kevAdded!, exec.kevAdded!) <= 7);
    if (!partner) continue;
    out.pairs++;
    if (out.examples.length < 10) out.examples.push(`${partner.id} + ${exec.id}`);
    const t7 = onOrBefore(weeks, addDays(exec.kevAdded!, -7));
    if (t7 && chainVector(exec, t7, products)) out.liftedAtT7++;
  }
  return out;
}

// ---------- Product pressure (the trend hypothesis), offline ----------

export interface TrendRow {
  product: string;
  published: string | null;
  /** CVSS 7.0+, or rated high or critical when there's no score. */
  high: boolean;
  kevAdded: string | null;
}

/** The previous window a product's recent rate is compared with. */
export const TREND_PRIOR_DAYS = 365;
export const TREND_RECENT_DAYS = 90;
export const TREND_MIN_CVES = 10;
export const TREND_MIN_RECENT = 3;

/**
 * A product's high and critical filings are rising when the last 90 days hold
 * at least TREND_MIN_RECENT and sit two standard deviations (Poisson) above
 * what the previous year's rate predicts.
 */
export function rising(recent: number, prior: number): boolean {
  const expected = (prior * TREND_RECENT_DAYS) / TREND_PRIOR_DAYS;
  return recent >= TREND_MIN_RECENT && recent > expected + 2 * Math.sqrt(Math.max(expected, 1));
}

export interface TrendGroup {
  group: string;
  productMonths: number;
  /** Product-months followed by a KEV add for that product within 90 days. */
  hits: number;
}

/**
 * Does a rise in a product's high and critical CVEs predict a KEV add for that
 * product in the next 90 days, beyond what its KEV history already says? At the
 * first of each month, for products with at least TREND_MIN_CVES CVEs in the
 * previous 455 days.
 */
export function runTrend(rows: readonly TrendRow[], from: string, to: string): TrendGroup[] {
  const per = new Map<string, { all: string[]; high: string[]; kev: string[] }>();
  for (const r of rows) {
    if (!per.has(r.product)) per.set(r.product, { all: [], high: [], kev: [] });
    const p = per.get(r.product)!;
    if (r.published) {
      p.all.push(r.published);
      if (r.high) p.high.push(r.published);
    }
    if (r.kevAdded) p.kev.push(r.kevAdded);
  }
  for (const p of per.values()) {
    p.all.sort();
    p.high.sort();
    p.kev.sort();
  }

  const names = ['all eligible', 'filings rising', 'KEV add in last 90 days', 'KEV add in last 365 days', 'no KEV add in last 365 days', 'filings rising, no KEV add in last 365 days'];
  const groups = new Map(names.map((g) => [g, { group: g, productMonths: 0, hits: 0 }]));
  const add = (g: string, hit: boolean) => {
    const row = groups.get(g)!;
    row.productMonths++;
    if (hit) row.hits++;
  };

  for (let m = `${from.slice(0, 7)}-01`; addDays(m, TREND_RECENT_DAYS) <= to; m = nextMonth(m)) {
    const recentFrom = addDays(m, -TREND_RECENT_DAYS);
    const priorFrom = addDays(recentFrom, -TREND_PRIOR_DAYS);
    const horizon = addDays(m, TREND_RECENT_DAYS);
    for (const p of per.values()) {
      if (countIn(p.all, priorFrom, m) < TREND_MIN_CVES) continue;
      const up = rising(countIn(p.high, recentFrom, m), countIn(p.high, priorFrom, recentFrom));
      const kev90 = countIn(p.kev, recentFrom, m) > 0;
      const kev365 = countIn(p.kev, addDays(m, -365), m) > 0;
      const hit = countIn(p.kev, m, horizon) > 0;
      add('all eligible', hit);
      if (up) add('filings rising', hit);
      if (kev90) add('KEV add in last 90 days', hit);
      if (kev365) add('KEV add in last 365 days', hit);
      else add('no KEV add in last 365 days', hit);
      if (up && !kev365) add('filings rising, no KEV add in last 365 days', hit);
    }
  }
  return [...groups.values()];
}

function nextMonth(m: string): string {
  const d = new Date(`${m}T00:00:00Z`);
  d.setUTCMonth(d.getUTCMonth() + 1);
  return d.toISOString().slice(0, 10);
}

// ---------- Output ----------

export function table(headers: string[], rows: (string | number | null)[][]): string {
  const cell = (v: string | number | null) => (v === null ? '–' : String(v));
  return [`| ${headers.join(' | ')} |`, `| ${headers.map(() => '---').join(' | ')} |`, ...rows.map((r) => `| ${r.map(cell).join(' | ')} |`)].join('\n');
}

export const pct = (n: number, d: number) => (d === 0 ? null : `${((100 * n) / d).toFixed(1)}%`);
export const perThousand = (n: number, d: number) => (d === 0 ? null : ((1000 * n) / d).toFixed(1));

export function formatReport(r: BacktestReport, trend: TrendGroup[] | null): string {
  const out: string[] = [];
  out.push('## Monthly snapshots (CVEs published in the previous 90 days, not on KEV yet)', '');
  out.push(
    table(
      ['Variant', 'Snapshots', 'Population', 'Act+Attend', 'KEV in 90d per 1,000 flags', 'KEV recall', 'Top 1% hits', 'Top 5% hits', 'KEV adds'],
      r.monthly.map((m) => [m.variant, m.snapshots, m.population, m.flagged, perThousand(m.positivesFlagged, m.flagged), pct(m.positivesFlagged, m.positives), `${m.top1Hits} of ${m.top1}`, `${m.top5Hits} of ${m.top5}`, m.positives]),
    ),
  );
  out.push('', '## KEV recall in Act+Attend before CISA added them', '');
  const kev = [...r.kev].sort((a, b) => a.offsetDays - b.offsetDays || a.group.localeCompare(b.group) || a.variant.localeCompare(b.variant));
  out.push(table(['Before KEV', 'Group', 'Variant', 'Cases', 'Flagged', 'Recall', 'Not yet published'], kev.map((k) => [`T-${k.offsetDays}`, k.group, k.variant, k.cases, k.flagged, pct(k.flagged, k.cases), k.notYetPublished])));
  out.push('', '## Lead time (new KEV CVEs, weekly snapshots)', '');
  out.push(table(['Variant', 'Cases', 'Flagged before KEV', 'Median days ahead'], r.lead.map((l) => [l.variant, l.cases, `${l.flaggedBefore} (${pct(l.flaggedBefore, l.cases) ?? '–'})`, l.medianLeadDays])));
  if (r.chain) {
    out.push('', '## Chain rule 1', '');
    out.push(`- Lifted in monthly snapshots: ${r.chain.lifted} (${r.chain.liftedNeverKev} never on KEV)`);
    out.push(`- Same-product KEV pairs within 7 days: ${r.chain.pairs.pairs}, lifted at T-7: ${r.chain.pairs.liftedAtT7}`);
    if (r.chain.pairs.examples.length > 0) out.push(`- Examples: ${r.chain.pairs.examples.join(', ')}`);
  }
  if (r.productKev) {
    out.push('', '## Product KEV (another CVE of the product added in the last 90 days)', '');
    out.push(`- Lifted in monthly snapshots: ${r.productKev.lifted}, of which added to KEV within 90 days: ${r.productKev.liftedPositive} (${perThousand(r.productKev.liftedPositive, r.productKev.lifted) ?? '–'} per 1,000)`);
  }
  if (trend) {
    const base = trend.find((t) => t.group === 'all eligible');
    out.push('', '## Product pressure: KEV add for the product within 90 days', '');
    out.push(
      table(
        ['Group', 'Product-months', 'Followed by a KEV add', 'Rate', 'Lift over all'],
        trend.map((t) => [t.group, t.productMonths, t.hits, pct(t.hits, t.productMonths), base && base.hits > 0 && t.productMonths > 0 ? ((t.hits / t.productMonths) / (base.hits / base.productMonths)).toFixed(2) : null]),
      ),
    );
  }
  if (r.snapshotsMissing.length > 0) out.push('', `EPSS files missing (ranked with no EPSS): ${r.snapshotsMissing.join(', ')}`);
  return out.join('\n');
}
