import { Hono, type Context } from 'hono';
import { generateCookie, getCookie, setCookie } from 'hono/cookie';
import { z } from 'zod';
import { D1BindingStore } from '../ingest/d1-store';
import { BodyTooLarge, readCapped } from '../lib/body';
import { clientKey } from '../lib/client';
import { issuePass, LOCK_COOKIE, lockedStatus, lockedUntil, PASS_COOKIE, PASS_STACKS, PASS_TTL_SECONDS, passStatus, type PassStatus } from '../lib/pass';
import { TURNSTILE_ACTION, verifyTurnstile } from '../resolve/turnstile';
import type { AppEnv } from '../types';

/** A token and nothing else. */
const MAX_PASS_BODY = 4096;
const PassBody = z.object({ turnstileToken: z.string().max(2048) });

/**
 * GET /api/pass: what this browser's pass has left this hour, so the page can
 * grey out looking up another stack. `active` is false without a valid pass;
 * the page then gets one from its next POST. A locked browser is answered from
 * its lock cookie, without reading D1.
 *
 * POST /api/pass: a Turnstile token in, a pass out. The CVE list tab uses it,
 * since its lookup goes straight to the feed and so never reaches
 * /api/resolve, which issues passes the same way.
 */
export const pass = new Hono<AppEnv>()
  .get('/', async (c) => {
    const now = new Date();
    const locked = readLock(c, now);
    if (locked) return c.json({ active: true, ...lockedStatus(locked) }, 200, { 'Cache-Control': 'no-store' });
    const id = getCookie(c, PASS_COOKIE);
    const status = id ? await passStatus(new D1BindingStore(c.env.DB), id, now) : null;
    return c.json({ active: status !== null, ...(status ?? { used: 0, limit: PASS_STACKS, resetsAt: null }) }, 200, { 'Cache-Control': 'no-store' });
  })
  .post('/', async (c) => {
    if (Number(c.req.header('content-length') ?? 0) > MAX_PASS_BODY) return c.json({ error: 'request too large' }, 413);
    const now = new Date();
    const locked = readLock(c, now);
    if (locked) return passLimited(c, lockedStatus(locked), now);
    // The same per-IP limit as /api/resolve: both are where a browser proves itself.
    if (c.env.RESOLVE_LIMITER) {
      const { success } = await c.env.RESOLVE_LIMITER.limit({ key: clientKey(c.req.header('cf-connecting-ip') ?? null) });
      if (!success) return c.json({ error: 'too many requests; try again in a minute' }, 429, { 'Retry-After': '60' });
    }
    let token: string;
    try {
      const parsed = PassBody.safeParse(JSON.parse(await readCapped(c.req.raw, MAX_PASS_BODY)));
      if (!parsed.success) return c.json({ error: 'invalid request' }, 400);
      token = parsed.data.turnstileToken;
    } catch (err) {
      if (err instanceof BodyTooLarge) return c.json({ error: 'request too large' }, 413);
      return c.json({ error: 'invalid JSON' }, 400);
    }
    const earned = await earnPass(c, token);
    if (earned instanceof Response) return earned;
    const status = await passStatus(new D1BindingStore(c.env.DB), earned, now);
    return c.json({ active: true, ...(status ?? { used: 0, limit: PASS_STACKS, resetsAt: null }) }, 200, { 'Cache-Control': 'no-store' });
  });

/**
 * Checks a Turnstile token and, when it passes, gives this browser a feed pass
 * (src/lib/pass.ts) unless it has a live one. Returns the refusal to send, or
 * the browser's pass id.
 */
export async function earnPass(c: Context<AppEnv>, token: string): Promise<Response | string> {
  const secret = c.env.TURNSTILE_SECRET_KEY;
  if (!secret) return c.json({ error: 'Turnstile is not configured on this server' }, 503);
  const check = await verifyTurnstile((i, init) => fetch(i, init), secret, token, c.req.header('cf-connecting-ip') ?? null, {
    hostname: new URL(c.env.BASE_URL).hostname,
    action: TURNSTILE_ACTION,
  });
  if (!check.success) return c.json({ error: 'verification failed; reload the page and try again', codes: check.errors }, 403);
  const store = new D1BindingStore(c.env.DB);
  const now = new Date();
  const id = getCookie(c, PASS_COOKIE);
  if (id && (await passStatus(store, id, now))) return id;
  const issued = await issuePass(store, now);
  setCookie(c, PASS_COOKIE, issued, { path: '/', maxAge: PASS_TTL_SECONDS, httpOnly: true, secure: true, sameSite: 'Strict' });
  return issued;
}

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
