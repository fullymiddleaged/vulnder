import { stmt, type Store } from '../ingest/store';

/**
 * Daily caps on metered work, counted in D1. The Workers rate limiting binding
 * only covers short windows and is per location, so it can't hold a daily
 * budget; this can. Each client gets its own cap, and a total cap protects the
 * daily allowance against many clients at once.
 *
 * Clients are counted by a salted hash of their IP. The salt is random, lives
 * only for one UTC day, and is deleted along with that day's counters.
 */

export interface DailyLimits {
  perClient: number;
  total: number;
}

export type QuotaResult = 'ok' | 'client-limit' | 'total-limit';

const SALT_PREFIX = 'usage_salt:';
const TOTAL = '*';

/**
 * Counts one unit of work for this client, unless a cap is already reached.
 * The client's counter goes first, so a client over its own cap never uses up
 * the total.
 */
export async function takeDailyQuota(store: Store, bucket: string, clientIp: string | null, limits: DailyLimits, now: Date): Promise<QuotaResult> {
  const day = now.toISOString().slice(0, 10);
  const subject = await clientHash(await dailySalt(store, day), clientIp ?? 'unknown');
  if ((await increment(store, day, bucket, subject)) > limits.perClient) return 'client-limit';
  if ((await increment(store, day, bucket, TOTAL)) > limits.total) return 'total-limit';
  return 'ok';
}

async function increment(store: Store, day: string, bucket: string, subject: string): Promise<number> {
  const [row] = await store.all<{ count: number }>(
    `INSERT INTO usage_counters (day, bucket, subject, count) VALUES (?, ?, ?, 1)
     ON CONFLICT (day, bucket, subject) DO UPDATE SET count = count + 1
     RETURNING count`,
    [day, bucket, subject],
  );
  return row?.count ?? 0;
}

/** Today's salt, created on first use; creating it clears earlier days. */
async function dailySalt(store: Store, day: string): Promise<string> {
  const key = `${SALT_PREFIX}${day}`;
  const existing = await store.all<{ value: string }>('SELECT value FROM meta WHERE key = ?', [key]);
  if (existing[0]) return JSON.parse(existing[0].value) as string;

  const fresh = [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, '0')).join('');
  await store.batch([
    // Two isolates can race here; OR IGNORE keeps the first salt, which both then read.
    stmt('INSERT OR IGNORE INTO meta (key, value, updated_at) VALUES (?, ?, ?)', key, JSON.stringify(fresh), new Date().toISOString()),
    stmt("DELETE FROM meta WHERE key LIKE 'usage\\_salt:%' ESCAPE '\\' AND key < ?", key),
    stmt('DELETE FROM usage_counters WHERE day < ?', day),
  ]);
  const [row] = await store.all<{ value: string }>('SELECT value FROM meta WHERE key = ?', [key]);
  return JSON.parse(row!.value) as string;
}

async function clientHash(salt: string, ip: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${salt}:${ip}`));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** A positive whole number from a string var, or the fallback. */
export function limitFromVar(value: string | undefined, fallback: number): number {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}
