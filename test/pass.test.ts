import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { maintenanceStatements } from '../src/ingest/maintenance';
import { issuePass, lockedUntil, PASS_STACKS, passStatus, usePass } from '../src/lib/pass';
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

  it('ignores lock cookies that are over, malformed or further off than an hour', () => {
    const now = new Date('2026-10-08T10:00:00Z');
    const ms = (minutes: number) => String(now.getTime() + minutes * 60_000);
    expect(lockedUntil(ms(30), now)).toBe(new Date(now.getTime() + 30 * 60_000).toISOString());
    expect(lockedUntil(ms(60), now)).not.toBeNull();
    for (const bad of [undefined, '', ms(0), ms(-5), ms(61), 'abc', '1e15', `${ms(30)};x`, '9'.repeat(400)]) expect(lockedUntil(bad, now)).toBeNull();
  });
});
