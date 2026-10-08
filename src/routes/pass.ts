import { Hono, type Context } from 'hono';
import { generateCookie, getCookie } from 'hono/cookie';
import { D1BindingStore } from '../ingest/d1-store';
import { LOCK_COOKIE, lockedStatus, lockedUntil, PASS_COOKIE, PASS_STACKS, passStatus, type PassStatus } from '../lib/pass';
import type { AppEnv } from '../types';

/**
 * GET /api/pass: what this browser's pass has left this hour, so the page can
 * grey out looking up another stack. `active` is false without a valid pass;
 * the page then gets one from its next POST /api/resolve. A locked browser is
 * answered from its lock cookie, without reading D1.
 */
export const pass = new Hono<AppEnv>().get('/', async (c) => {
  const now = new Date();
  const locked = readLock(c, now);
  if (locked) return c.json({ active: true, ...lockedStatus(locked) }, 200, { 'Cache-Control': 'no-store' });
  const id = getCookie(c, PASS_COOKIE);
  const status = id ? await passStatus(new D1BindingStore(c.env.DB), id, now) : null;
  return c.json({ active: status !== null, ...(status ?? { used: 0, limit: PASS_STACKS, resetsAt: null }) }, 200, { 'Cache-Control': 'no-store' });
});

/** When this browser's lock ends, or null when it isn't locked. */
export function readLock(c: Context<AppEnv>, now: Date): string | null {
  return lockedUntil(getCookie(c, LOCK_COOKIE), now);
}

/**
 * Locks this browser until `resetsAt`, so its next requests are refused before
 * any D1 read. Added to the response on its way out, after any copy has gone
 * into the shared cache, so the cookie can never be served to someone else.
 */
export function withLock(res: Response, resetsAt: string, now: Date): Response {
  const until = Date.parse(resetsAt);
  const maxAge = Math.ceil((until - now.getTime()) / 1000);
  if (maxAge <= 0) return res;
  const out = new Response(res.body, res);
  out.headers.append('Set-Cookie', generateCookie(LOCK_COOKIE, String(until), { path: '/', maxAge, httpOnly: true, secure: true, sameSite: 'Strict' }));
  out.headers.set('Cache-Control', 'no-store');
  return out;
}

/** The refusal for a spent pass, with when it unlocks. */
export function passLimited(c: Context<AppEnv>, status: PassStatus, now: Date): Response {
  const retry = status.resetsAt ? Math.max(1, Math.ceil((Date.parse(status.resetsAt) - now.getTime()) / 1000)) : 60;
  return c.json(
    { error: "your usage is restricted: you've looked up the most stacks an hour allows; try again after the time shown", reason: 'pass-limit', pass: status },
    429,
    { 'Retry-After': String(retry), 'Cache-Control': 'no-store' },
  );
}
