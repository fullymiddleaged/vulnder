import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { maintenanceStatements } from '../src/ingest/maintenance';
import { issuePass, lockedUntil, PASS_STACKS, passStatus, usePass } from '../src/lib/pass';
import { SITEVERIFY_URL, TURNSTILE_ACTION } from '../src/resolve/turnstile';
import { app } from '../src/index';
import { resetDb, rows, store } from './helpers/db';

const SECRET = 'test-secret';
const T0 = new Date('2026-10-08T10:00:00Z');
const at = (minutes: number) => new Date(T0.getTime() + minutes * 60_000);

beforeEach(resetDb);

describe('feed passes', () => {
  it('allows the first stack and one more in an hour, then locks until the hour is over', async () => {
    const id = await issuePass(store(), T0);
    expect(await passStatus(store(), id, T0)).toEqual({ used: 0, limit: PASS_STACKS, resetsAt: null });

    expect(await usePass(store(), id, 'npm:next', SECRET, T0)).toEqual({ ok: true, status: { used: 1, limit: 2, resetsAt: at(60).toISOString() } });
    // Before the last place goes, the same stack again is free.
    expect(await usePass(store(), id, 'npm:next', SECRET, at(5))).toMatchObject({ ok: true, status: { used: 1 } });
    expect(await usePass(store(), id, 'npm:next,p:f5/nginx', SECRET, at(10))).toMatchObject({ ok: true, status: { used: 2 } });

    // Spent: a third stack waits for the hour that started with the first, and so do the two it used.
    expect(await usePass(store(), id, 'pypi:django', SECRET, at(20))).toEqual({ ok: false, status: { used: 2, limit: 2, resetsAt: at(60).toISOString() } });
    expect(await usePass(store(), id, 'npm:next', SECRET, at(30))).toMatchObject({ ok: false });

    // An hour after the first use, the allowance starts again.
    expect(await usePass(store(), id, 'pypi:django', SECRET, at(60))).toEqual({ ok: true, status: { used: 1, limit: 2, resetsAt: at(120).toISOString() } });
  });

  it('stores only keyed hashes of stacks', async () => {
    const id = await issuePass(store(), T0);
    await usePass(store(), id, 'npm:next', SECRET, T0);
    const [row] = await rows<{ stacks: string }>('SELECT stacks FROM feed_passes');
    expect(row!.stacks).not.toContain('next');
    expect(JSON.parse(row!.stacks)).toEqual([expect.stringMatching(/^[0-9a-f]{16}$/)]);
  });

  it('ignores unknown, malformed and expired passes, and maintenance drops expired ones', async () => {
    expect(await usePass(store(), '0'.repeat(32), 'npm:next', SECRET, T0)).toBeNull();
    expect(await usePass(store(), "x' OR 1=1 --", 'npm:next', SECRET, T0)).toBeNull();
    const id = await issuePass(store(), T0);
    const nextDay = new Date(T0.getTime() + 86_400_000);
    expect(await passStatus(store(), id, nextDay)).toBeNull();
    await store().batch(maintenanceStatements(nextDay));
    expect(await rows('SELECT id FROM feed_passes')).toEqual([]);
  });
});

describe('feed passes on the routes', () => {
  const e = () => ({ ...env, TURNSTILE_SECRET_KEY: SECRET });
  const feed = (s: string, cookie: string, limiter?: RateLimit) =>
    app.request(`/api/feed?s=${encodeURIComponent(s)}`, { headers: { cookie, 'cf-connecting-ip': '203.0.113.9' } }, { ...e(), ...(limiter ? { FEED_LIMITER: limiter } : {}) });

  /** The lock cookie a response sets, as `name=value`, or null. */
  const lockCookie = (res: Response) => res.headers.getSetCookie().find((c) => c.startsWith('vulnder_lock='))?.split(';')[0] ?? null;

  it('limits a pass to two different stacks an hour, then locks the browser', async () => {
    const id = await issuePass(store(), new Date());
    const cookie = `vulnder_pass=${id}`;
    // A shared office IP whose limiter is spent doesn't stop a browser with a pass: the pass has a bucket of its own.
    const keys: string[] = [];
    const refuse = { limit: async ({ key }: { key: string }) => (keys.push(key), { success: key.startsWith('pass:') }) } as unknown as RateLimit;
    const first = await feed('pypi:fastapi', cookie, refuse);
    expect(first.status).toBe(200);
    expect(lockCookie(first)).toBeNull();
    expect(keys).toEqual([`pass:${id}`]);

    // The second stack loads, and its response locks the browser.
    const second = await feed('p:postgresql/postgresql', cookie, refuse);
    expect(second.status).toBe(200);
    const lock = lockCookie(second);
    expect(lock).toMatch(/^vulnder_lock=\d+$/);
    expect(second.headers.get('Set-Cookie')).toContain('HttpOnly');
    expect(second.headers.get('Cache-Control')).toBe('no-store');

    // Without the lock cookie, D1 still refuses every stack, the used ones too, and hands the lock back.
    for (const s of ['npm:next', 'pypi:fastapi']) {
      const res = await feed(s, cookie, refuse);
      expect(res.status).toBe(429);
      expect(await res.json()).toMatchObject({ reason: 'pass-limit', pass: { used: 2, limit: 2 } });
      expect(Number(res.headers.get('Retry-After'))).toBeGreaterThan(3000);
      expect(lockCookie(res)).toBe(lock);
    }

    const status = await app.request('/api/pass', { headers: { cookie } }, e());
    expect(await status.json()).toMatchObject({ active: true, used: 2, limit: 2 });
    expect(await (await app.request('/api/pass', {}, e())).json()).toEqual({ active: false, used: 0, limit: 2, resetsAt: null });
  });

  it('still rate-limits cache misses for a pass, in its own bucket', async () => {
    // One stack under many windows and routes counts once against the pass, so
    // without this a pass could ask for hundreds of uncached feeds at once.
    const id = await issuePass(store(), new Date());
    const spentPass = { limit: async ({ key }: { key: string }) => ({ success: key !== `pass:${id}` }) } as unknown as RateLimit;
    const res = await feed('npm:left-pad', `vulnder_pass=${id}`, spentPass);
    expect(res.status).toBe(429);
    expect(res.headers.get('Retry-After')).toBe('60');
  });

  it('refuses a locked browser from its lock cookie alone, without D1', async () => {
    const until = Date.now() + 30 * 60_000;
    const cookie = `vulnder_lock=${until}`;
    // No database: any D1 read would throw.
    const noDb = { ...e(), DB: undefined as unknown as D1Database };
    const res = await app.request('/api/feed?s=npm%3Anext', { headers: { cookie } }, noDb);
    expect(res.status).toBe(429);
    expect(await res.json()).toMatchObject({ reason: 'pass-limit', pass: { used: 2, limit: 2, resetsAt: new Date(until).toISOString() } });
    expect((await app.request('/feed.xml?s=npm%3Anext', { headers: { cookie } }, noDb)).status).toBe(429);
    expect((await app.request('/badge.svg?s=npm%3Anext', { headers: { cookie } }, noDb)).status).toBe(429);
    const resolved = await app.request('/api/resolve', { method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: '{}' }, noDb);
    expect(resolved.status).toBe(429);
    expect(await (await app.request('/api/pass', { headers: { cookie } }, noDb)).json()).toEqual({
      active: true,
      used: 2,
      limit: 2,
      resetsAt: new Date(until).toISOString(),
    });
  });

  describe('POST /api/pass', () => {
    const turnstile = (success: boolean) =>
      vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url !== SITEVERIFY_URL) throw new Error(`unexpected fetch ${url}`);
        // As Cloudflare answers for a widget on this site, so the hostname and action checks run.
        return Response.json(success ? { success: true, hostname: new URL(env.BASE_URL).hostname, action: TURNSTILE_ACTION } : { success: false, 'error-codes': ['invalid-input-response'] });
      });
    const earn = (body: string, cookie = '', env_ = e()) =>
      app.request('/api/pass', { method: 'POST', headers: { cookie, 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.9' }, body }, env_);
    const passCookie = (res: Response) => res.headers.getSetCookie().find((c) => c.startsWith('vulnder_pass='))?.split(';')[0] ?? null;
    afterEach(() => vi.restoreAllMocks());

    it('trades a Turnstile token for a pass that the feed then counts', async () => {
      turnstile(true);
      const res = await earn(JSON.stringify({ turnstileToken: 'tok' }));
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ active: true, used: 0, limit: PASS_STACKS, resetsAt: null });
      const cookie = passCookie(res)!;
      expect(cookie).toMatch(/^vulnder_pass=/);
      expect(res.headers.getSetCookie().find((c) => c.startsWith('vulnder_pass='))).toMatch(/HttpOnly.*Secure|Secure.*HttpOnly/);

      expect((await feed('cve:2021-44228', cookie)).status).toBe(200);
      expect(await passStatus(store(), cookie.split('=')[1]!, new Date())).toMatchObject({ used: 1 });
      // A live pass is kept, not replaced, so earning again can't reset the count.
      const again = await earn(JSON.stringify({ turnstileToken: 'tok2' }), cookie);
      expect(passCookie(again)).toBeNull();
      expect(await again.json()).toMatchObject({ used: 1 });
    });

    it('refuses a failed check, a bad body and a locked browser, issuing nothing', async () => {
      turnstile(false);
      const failed = await earn(JSON.stringify({ turnstileToken: 'bad' }));
      expect(failed.status).toBe(403);
      expect(passCookie(failed)).toBeNull();
      for (const body of ['not json', '{}', JSON.stringify({ turnstileToken: 'x'.repeat(3000) })]) {
        const res = await earn(body);
        expect(res.status, body.slice(0, 20)).toBeGreaterThanOrEqual(400);
        expect(passCookie(res)).toBeNull();
      }
      expect((await earn(JSON.stringify({ turnstileToken: 'x'.repeat(5000) }))).status).toBe(413);
      const locked = await earn(JSON.stringify({ turnstileToken: 'tok' }), `vulnder_lock=${Date.now() + 60_000}`);
      expect(locked.status).toBe(429);
      expect(await rows('SELECT id FROM feed_passes')).toEqual([]);
    });

    it('shares the resolve rate limit', async () => {
      turnstile(true);
      const limit = vi.fn(async () => ({ success: false }));
      const res = await earn(JSON.stringify({ turnstileToken: 'tok' }), '', { ...e(), RESOLVE_LIMITER: { limit } as unknown as RateLimit });
      expect(res.status).toBe(429);
      expect(limit).toHaveBeenCalledWith({ key: '203.0.113.9' });
    });
  });

  it('ignores lock cookies that are over, malformed or further off than an hour', () => {
    const now = new Date('2026-10-08T10:00:00Z');
    const ms = (minutes: number) => String(now.getTime() + minutes * 60_000);
    expect(lockedUntil(ms(30), now)).toBe(new Date(now.getTime() + 30 * 60_000).toISOString());
    expect(lockedUntil(ms(60), now)).not.toBeNull();
    for (const bad of [undefined, '', ms(0), ms(-5), ms(61), 'abc', '1e15', `${ms(30)};x`, '9'.repeat(400)]) expect(lockedUntil(bad, now)).toBeNull();
  });
});
