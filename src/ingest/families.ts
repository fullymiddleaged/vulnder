import { normalizeKey } from '../lib/normalize';
import { addUsageStatement, usageToday } from '../lib/quota';
import type { Budget } from './budget';
import { chunkByJsonSize, stmt, type Statement, type Store } from './store';

/**
 * Families: CVEs in the same product whose descriptions are nearly the same.
 * That catches one flaw filed twice (by a CNA and in a GitHub advisory),
 * variants of one flaw (an XSS through two preview paths), and a vendor
 * bulletin's batch (a run of "Windows Biometric Service" or Chrome
 * use-after-free bugs, which usually share a fix). It can't tell a variant from
 * a batch: templated bulletins differ by one component word, and the model
 * scores those as close as true variants. So the feed calls them "similar", folds
 * each family together, and treats a member's exploitation as a reason to
 * attend to the rest, never as evidence about them.
 *
 * Ingest embeds each vuln's text once, with a Workers AI embedding model, and
 * compares it with the leaders of the families in its blocks (its package or
 * product keys). It joins the most similar leader's family at FAMILY_SIM or
 * more; otherwise it leads a new one. Comparing only with leaders keeps
 * families tight: a chain of near neighbours can't drift into unrelated bugs.
 *
 * The model only measures similarity; the threshold, the blocking and what a
 * family changes are all decided here.
 */

export const EMBED_MODEL = '@cf/qwen/qwen3-embedding-0.6b';
/** Matryoshka truncation: the model's first 256 of 1,024 dimensions carry most of the meaning. */
export const EMBED_DIMS = 256;
/**
 * Calibrated on 20 labelled pairs of real CVE titles, run through familyText
 * (test/fixtures/families/calibration.json): variants of one flaw scored 0.905
 * to 1.0, different bugs in one product at most 0.854 (Windows Imaging vs
 * Graphics Component). This sits in the middle of that gap.
 */
export const FAMILY_SIM = 0.88;
/** A key with at least this many vulns blocks on the title's first words too, so a lookup stays small. */
export const BIG_KEY = 150;
const MAX_BLOCKS = 8;
const BATCH = 50;
const MAX_BATCHES = 20;
/** Daily cap on embedded tokens: about 1,075 neurons, beside the 10,000-a-day free allowance. */
export const EMBED_DAILY_TOKENS = 1_000_000;
const USAGE_BUCKET = 'embed';
const ASSIGNED_BUCKET = 'family';
/**
 * Default daily cap on vulns assigned from Node ingest, which is how Workers
 * Free runs it. Assigning one writes about five D1 rows (its family id and
 * index, and a leader's vector and indexes), so the first pass over a fresh
 * database would otherwise write about 120,000 a day, over Free's 100,000.
 * 8,000 a day is about 40,000 rows, leaving room for the rest of ingest.
 */
export const FREE_PLAN_FAMILY_DAILY = 8000;
const MAX_TEXT = 600;

export type Embedder = (texts: string[]) => Promise<number[][]>;

/** Workers AI over its REST API, for ingest from Node. The token needs Workers AI read and edit. */
export function restEmbedder(fetchFn: typeof fetch, accountId: string, token: string): Embedder {
  const url = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/ai/run/${EMBED_MODEL}`;
  return async (texts) => {
    const res = await fetchFn(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: texts }),
      signal: AbortSignal.timeout(60_000),
    });
    if (!res.ok) throw new Error(`Workers AI: HTTP ${res.status}`);
    const body = (await res.json()) as { result?: { data?: number[][] } };
    return checkVectors(body.result?.data, texts.length);
  };
}

/** The embedding rows, or an error when the model returned something else. */
export function checkVectors(data: unknown, expected: number): number[][] {
  if (!Array.isArray(data) || data.length !== expected) throw new Error('Workers AI: unexpected embedding response');
  for (const v of data) {
    if (!Array.isArray(v) || v.length < EMBED_DIMS || !v.every((x) => typeof x === 'number' && Number.isFinite(x))) {
      throw new Error('Workers AI: unexpected embedding response');
    }
  }
  return data as number[][];
}

// ---------- Vectors ----------

/** First EMBED_DIMS dimensions, renormalised and quantised to int8, as base64. */
export function encodeVector(v: number[]): string {
  const head = v.slice(0, EMBED_DIMS);
  const norm = Math.hypot(...head) || 1;
  const bytes = new Uint8Array(Int8Array.from(head, (x) => Math.round((x / norm) * 127)).buffer);
  return btoa(String.fromCharCode(...bytes));
}

export function decodeVector(s: string): Int8Array | null {
  try {
    const bin = atob(s);
    if (bin.length !== EMBED_DIMS) return null;
    return new Int8Array(Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer);
  } catch {
    return null;
  }
}

export function similarity(a: Int8Array, b: Int8Array): number {
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i]! * b[i]!;
    na += a[i]! * a[i]!;
    nb += b[i]! * b[i]!;
  }
  return na === 0 || nb === 0 ? 0 : dot / Math.sqrt(na * nb);
}

// ---------- Text and blocks ----------

const KERNEL_PREAMBLE = /^In the Linux kernel, the following vulnerability has been resolved:\s*/i;
/** Words every title on a platform shares ("WordPress X plugin <= 1.2 - ... vulnerability"). */
const BOILERPLATE = new Set(['wordpress', 'plugin', 'theme', 'vulnerability', 'vulnerabilities']);
/** Version bounds and separators: "<=", "4.1.25", "v2.0", "-". */
const VERSIONISH = /^(?:[<>=≤≥]+|v?\d+(?:\.\d+)+[a-z0-9.-]*|[-–—|]+)$/i;

/**
 * What gets embedded: the title, or the summary when there is none, without
 * the product's own name. Every CVE of a product shares its name, so left in
 * it pulls them together: "Mitel MiVoice Office 400 stored XSS" would sit
 * next to "Mitel MiVoice Office 400 path traversal". So a leading "n8n: " goes,
 * and so does any word of the vendor, product or label, unless that would
 * leave fewer than two words.
 */
export function familyText(title: string | null, summary: string | null, productNames: string[]): string | null {
  const names = new Set(productNames.map(normalizeKey).filter((k): k is string => !!k));
  const nameWords = new Set([...names].flatMap((n) => n.split('_')).filter((w) => w.length > 1));
  // A word goes when every part of it is a name ("monta.app"), or it is shared boilerplate.
  const noise = (w: string) => {
    if (VERSIONISH.test(w)) return true;
    const parts = normalizeKey(w)?.split('_') ?? [];
    return parts.length > 0 && parts.every((p) => nameWords.has(p) || BOILERPLATE.has(p));
  };
  const strip = (s: string) => {
    const m = /^([^:]{1,60}):\s+(?=\S)/.exec(s);
    const rest = m && names.has(normalizeKey(m[1]) ?? '') ? s.slice(m[0].length) : s;
    const kept = rest.split(/\s+/).filter((w) => w && !noise(w));
    return kept.length >= 2 ? kept.join(' ') : rest;
  };
  const text = title?.trim() ? strip(title.trim()) : summary?.trim() ? strip(summary.trim().replace(KERNEL_PREAMBLE, '')) : '';
  return text ? text.slice(0, MAX_TEXT) : null;
}

/** The title's first two words, e.g. "windows biometric" or "staging rtl8723bs". */
export function titleStem(text: string): string {
  return (text.toLowerCase().match(/[a-z0-9]+/g) ?? []).slice(0, 2).join(' ');
}

export interface FamilyKey {
  kind: 'package' | 'product';
  key: string;
  /** Vulns the catalog counts for it (0 when it isn't counted yet). */
  count: number;
}

/** Where a vuln looks for families: each of its keys, plus the title stem on big ones. */
export function blocksFor(keys: FamilyKey[], text: string): string[] {
  const stem = titleStem(text);
  const blocks = keys.map((k) => (k.count >= BIG_KEY ? `${k.kind}:${k.key}|${stem}` : `${k.kind}:${k.key}`));
  return [...new Set(blocks)].sort().slice(0, MAX_BLOCKS);
}

// ---------- Assignment ----------

export interface FamilyCandidate {
  id: string;
  vector: Int8Array;
  blocks: string[];
}

export interface Leader {
  block: string;
  leader: string;
  vector: Int8Array;
}

/**
 * Assigns each vuln a family, in order: the most similar leader in its blocks
 * at FAMILY_SIM or more, else itself. A vuln that leads joins the leaders the
 * rest of the batch compares with.
 */
export function assign(batch: FamilyCandidate[], existing: Leader[]): { familyOf: Map<string, string>; newLeaders: Leader[] } {
  const byBlock = new Map<string, Leader[]>();
  const addLeader = (l: Leader) => {
    if (!byBlock.has(l.block)) byBlock.set(l.block, []);
    byBlock.get(l.block)!.push(l);
  };
  existing.forEach(addLeader);
  const familyOf = new Map<string, string>();
  const newLeaders: Leader[] = [];
  for (const c of batch) {
    let best: { leader: string; sim: number } | null = null;
    for (const block of c.blocks) {
      for (const l of byBlock.get(block) ?? []) {
        if (l.leader === c.id) continue;
        const sim = similarity(c.vector, l.vector);
        if (sim >= FAMILY_SIM && (!best || sim > best.sim || (sim === best.sim && l.leader < best.leader))) best = { leader: l.leader, sim };
      }
    }
    if (best) {
      familyOf.set(c.id, best.leader);
      continue;
    }
    familyOf.set(c.id, c.id);
    for (const block of c.blocks) {
      const l = { block, leader: c.id, vector: c.vector };
      newLeaders.push(l);
      addLeader(l);
    }
  }
  return { familyOf, newLeaders };
}

// ---------- The ingest stage ----------

/**
 * Vulns without a family yet, newest first. Left to itself SQLite reads every
 * unassigned row through vulns_family and sorts them (38,000 rows a batch during
 * backfill), so this names the partial index, which yields them in order.
 */
export const UNASSIGNED_SQL = `SELECT id, title, summary, published_at FROM vulns INDEXED BY vulns_unassigned
  WHERE family_id IS NULL ORDER BY published_at DESC LIMIT ?`;
export const AFFECTED_KEYS_SQL = `SELECT vuln_id, kind, ecosystem, package_name, vendor, product, label FROM affected
  WHERE vuln_id IN (SELECT value FROM json_each(?))`;
export const CATALOG_COUNTS_SQL = `SELECT kind, key, count FROM catalog
  WHERE kind IN ('package', 'product') AND key IN (SELECT value FROM json_each(?))`;
export const LEADERS_SQL = 'SELECT block, leader, vector FROM families WHERE block IN (SELECT value FROM json_each(?))';
const SET_FAMILIES = `UPDATE vulns SET family_id = json_extract(j.value, '$[1]')
  FROM json_each(?) j WHERE vulns.id = json_extract(j.value, '$[0]')`;
const INSERT_LEADERS = `INSERT INTO families (block, leader, vector)
  SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]') FROM json_each(?) WHERE true
  ON CONFLICT (block, leader) DO NOTHING`;

export interface FamilyReport {
  assigned: number;
  /** Vulns that joined an existing family: the only change the feed can see. */
  joined: number;
  tokens: number;
  stopped?: string;
}

export interface FamilyOptions {
  store: Store;
  budget: Budget;
  embed: Embedder;
  now: () => Date;
  log: (message: string) => void;
  /** Most vulns to assign in a UTC day; no cap when left out. */
  dailyVulns?: number;
}

interface Row {
  id: string;
  title: string | null;
  summary: string | null;
}

interface AffectedKeyRow {
  vuln_id: string;
  kind: 'package' | 'product';
  ecosystem: string | null;
  package_name: string | null;
  vendor: string | null;
  product: string | null;
  label: string | null;
}

/** Assigns families to unassigned vulns in batches, as far as the budget and the daily token cap allow. */
export async function assignFamilies(opts: FamilyOptions): Promise<FamilyReport> {
  const { store, budget, log } = opts;
  const report: FamilyReport = { assigned: 0, joined: 0, tokens: 0 };
  for (let n = 0; n < MAX_BATCHES; n++) {
    if (!budget.has(10)) return { ...report, stopped: 'budget' };
    const spent = await usageToday(store, USAGE_BUCKET, opts.now());
    if (spent >= EMBED_DAILY_TOKENS) return { ...report, stopped: 'daily token cap' };
    let size = BATCH;
    if (opts.dailyVulns !== undefined) {
      const left = opts.dailyVulns - (await usageToday(store, ASSIGNED_BUCKET, opts.now()));
      if (left <= 0) return { ...report, stopped: 'daily cap' };
      size = Math.min(BATCH, left);
    }

    const rows = await store.all<Row>(UNASSIGNED_SQL, [size]);
    if (rows.length === 0) break;
    const ids = rows.map((r) => r.id);
    const affected = await store.all<AffectedKeyRow>(AFFECTED_KEYS_SQL, [JSON.stringify(ids)]);
    const keysOf = new Map<string, { kind: 'package' | 'product'; key: string }[]>();
    const namesOf = new Map<string, string[]>();
    for (const a of affected) {
      const key = a.kind === 'package' ? (a.ecosystem && a.package_name ? `${a.ecosystem}:${a.package_name}` : null) : a.vendor && a.product ? `${a.vendor}/${a.product}` : null;
      if (!key) continue;
      if (!keysOf.has(a.vuln_id)) keysOf.set(a.vuln_id, []);
      keysOf.get(a.vuln_id)!.push({ kind: a.kind, key });
      if (!namesOf.has(a.vuln_id)) namesOf.set(a.vuln_id, []);
      namesOf.get(a.vuln_id)!.push(...[a.label, a.package_name, a.product].filter((s): s is string => !!s));
    }
    const allKeys = [...new Set([...keysOf.values()].flat().map((k) => k.key))];
    const counts = new Map(
      allKeys.length === 0
        ? []
        : (await store.all<{ kind: string; key: string; count: number }>(CATALOG_COUNTS_SQL, [JSON.stringify(allKeys)])).map((r) => [
            `${r.kind} ${r.key}`,
            r.count,
          ]),
    );

    const texts = new Map<string, string>();
    for (const r of rows) {
      const t = familyText(r.title, r.summary, namesOf.get(r.id) ?? []);
      if (t) texts.set(r.id, t);
    }
    const toEmbed = [...texts.entries()];
    const tokens = toEmbed.reduce((sum, [, t]) => sum + Math.ceil(t.length / 4), 0);
    let vectors: number[][] = [];
    if (toEmbed.length > 0) {
      budget.take(1);
      try {
        vectors = await opts.embed(toEmbed.map(([, t]) => t));
      } catch (err) {
        // Fail open: families wait for the next run; nothing else depends on them.
        log(`families: embedding failed: ${err instanceof Error ? err.message : String(err)}`);
        return { ...report, stopped: 'embedding failed' };
      }
    }

    // Oldest first, so a batch's earlier CVEs lead its later ones.
    const order = [...rows].reverse();
    const batch: FamilyCandidate[] = [];
    const vectorOf = new Map(toEmbed.map(([id], i) => [id, decodeVector(encodeVector(vectors[i]!))!]));
    for (const r of order) {
      const vector = vectorOf.get(r.id);
      if (!vector) continue;
      const keys = (keysOf.get(r.id) ?? []).map((k) => ({ ...k, count: counts.get(`${k.kind} ${k.key}`) ?? 0 }));
      batch.push({ id: r.id, vector, blocks: blocksFor(keys, texts.get(r.id)!) });
    }
    const blocks = [...new Set(batch.flatMap((c) => c.blocks))];
    const existing: Leader[] =
      blocks.length === 0
        ? []
        : (await store.all<{ block: string; leader: string; vector: string }>(LEADERS_SQL, [JSON.stringify(blocks)])).flatMap((l) => {
            const vector = decodeVector(l.vector);
            return vector ? [{ block: l.block, leader: l.leader, vector }] : [];
          });
    const { familyOf, newLeaders } = assign(batch, existing);
    // Vulns with nothing to embed lead a family of their own.
    for (const id of ids) if (!familyOf.has(id)) familyOf.set(id, id);

    const statements: Statement[] = [stmt(SET_FAMILIES, JSON.stringify([...familyOf.entries()]))];
    if (newLeaders.length > 0) {
      const encoded = new Map(toEmbed.map(([id], i) => [id, encodeVector(vectors[i]!)]));
      for (const chunk of chunkByJsonSize(newLeaders.map((l) => [l.block, l.leader, encoded.get(l.leader)!]))) {
        statements.push(stmt(INSERT_LEADERS, JSON.stringify(chunk)));
      }
    }
    if (tokens > 0) statements.push(addUsageStatement(USAGE_BUCKET, tokens, opts.now()));
    if (opts.dailyVulns !== undefined) statements.push(addUsageStatement(ASSIGNED_BUCKET, familyOf.size, opts.now()));
    await store.batch(statements);

    report.assigned += familyOf.size;
    report.joined += [...familyOf.entries()].filter(([id, f]) => id !== f).length;
    report.tokens += tokens;
    if (rows.length < size) break;
  }
  return report;
}
