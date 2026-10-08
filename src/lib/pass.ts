import { stmt, type Statement, type Store } from '../ingest/store';

/**
 * Feed passes: what one browser may look up. A pass is issued after a
 * Turnstile check (POST /api/resolve) and carried in an HttpOnly cookie. Each
 * hour, starting from its first use, it may load PASS_STACKS different stacks;
 * the same stack again, or the same stack over another window, is free.
 * Requests without a pass (feed readers, badges, scripts) keep the per-IP limits.
 *
 * The count lives in D1, not the cookie, so replaying an old cookie can't reset
 * it. Stacks are stored only as keyed hashes, and rows go after a day.
 */

export const PASS_COOKIE = 'vulnder_pass';
export const PASS_STACKS = 2;
export const PASS_WINDOW_MS = 3_600_000;
/** How long a pass lives, as a cookie and as a row. */
export const PASS_TTL_SECONDS = 86_400;

export interface PassStatus {
  /** Different stacks used in the current hour. */
  used: number;
  limit: number;
  /** When the allowance resets; null until the first stack. */
  resetsAt: string | null;
}

export type PassUse = { ok: true; status: PassStatus } | { ok: false; status: PassStatus };

interface PassRow {
  id: string;
  created_at: string;
  window_start: string | null;
  stacks: string;
}

const PASS_ID = /^[0-9a-f]{32}$/;
const SELECT_PASS = 'SELECT id, created_at, window_start, stacks FROM feed_passes WHERE id = ? AND created_at > ?';
/** Compare-and-set, so two requests at once can't both take the last place. */
const UPDATE_PASS = 'UPDATE feed_passes SET window_start = ?, stacks = ? WHERE id = ? AND stacks = ? RETURNING id';

/** Makes a pass and returns its id. */
export async function issuePass(store: Store, now: Date): Promise<string> {
  const id = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, '0')).join('');
  await store.batch([stmt('INSERT INTO feed_passes (id, created_at) VALUES (?, ?)', id, now.toISOString())]);
  return id;
}

/** The pass's allowance now, or null for an unknown or expired pass. */
export async function passStatus(store: Store, id: string, now: Date): Promise<PassStatus | null> {
  const row = await load(store, id, now);
  return row ? current(row, now).status : null;
}

/**
 * Counts `canonical` against the pass. Null for an unknown or expired pass;
 * otherwise whether the stack may load, and the allowance after it.
 */
export async function usePass(store: Store, id: string, canonical: string, secret: string, now: Date, attempt = 0): Promise<PassUse | null> {
  const row = await load(store, id, now);
  if (!row) return null;
  const { stacks, windowStart, status } = current(row, now);
  const hash = await stackHash(secret, id, canonical);
  if (stacks.includes(hash)) return { ok: true, status };
  if (stacks.length >= PASS_STACKS || attempt >= 3) return { ok: false, status };

  const start = windowStart ?? now.toISOString();
  const next = [...stacks, hash];
  const updated = await store.all(UPDATE_PASS, [start, JSON.stringify(next), id, row.stacks]);
  // Another request changed the pass first: count again from what it wrote.
  if (updated.length === 0) return usePass(store, id, canonical, secret, now, attempt + 1);
  return { ok: true, status: { used: next.length, limit: PASS_STACKS, resetsAt: resetAt(start) } };
}

/** Daily maintenance: drop passes past their lifetime. */
export function prunePassesStatement(now: Date): Statement {
  return stmt('DELETE FROM feed_passes WHERE created_at <= ?', new Date(now.getTime() - PASS_TTL_SECONDS * 1000).toISOString());
}

async function load(store: Store, id: string, now: Date): Promise<PassRow | null> {
  if (!PASS_ID.test(id)) return null;
  const [row] = await store.all<PassRow>(SELECT_PASS, [id, new Date(now.getTime() - PASS_TTL_SECONDS * 1000).toISOString()]);
  return row ?? null;
}

/** The stored window, or a fresh one once its hour is over. */
function current(row: PassRow, now: Date): { stacks: string[]; windowStart: string | null; status: PassStatus } {
  const expired = row.window_start !== null && now.getTime() >= Date.parse(row.window_start) + PASS_WINDOW_MS;
  const windowStart = expired ? null : row.window_start;
  const stacks = expired ? [] : parseStacks(row.stacks);
  return { stacks, windowStart, status: { used: stacks.length, limit: PASS_STACKS, resetsAt: windowStart ? resetAt(windowStart) : null } };
}

function resetAt(windowStart: string): string {
  return new Date(Date.parse(windowStart) + PASS_WINDOW_MS).toISOString();
}

function parseStacks(text: string): string[] {
  try {
    const v = JSON.parse(text) as unknown;
    return Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string') : [];
  } catch {
    return [];
  }
}

/** HMAC of the pass and stack, keyed by a Worker secret, cut to 64 bits: enough to tell two stacks apart. */
async function stackHash(secret: string, id: string, canonical: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(`vulnder-pass:${secret}`), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${id}\n${canonical}`));
  return [...new Uint8Array(mac).slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
