import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { maintenanceStatements } from '../src/ingest/maintenance';
import { issuePass, PASS_STACKS, passStatus, usePass } from '../src/lib/pass';
import { app } from '../src/index';
import { resetDb, rows, store } from './helpers/db';

const SECRET = 'test-secret';
const T0 = new Date('2026-10-08T10:00:00Z');
const at = (minutes: number) => new Date(T0.getTime() + minutes * 60_000);

beforeEach(resetDb);

describe('feed passes', () => {
  it('allows the first stack and one more in an hour, and the same stacks again for free', async () => {
    const id = await issuePass(store(), T0);
    expect(await passStatus(store(), id, T0)).toEqual({ used: 0, limit: PASS_STACKS, resetsAt: null });

    expect(await usePass(store(), id, 'npm:next', SECRET, T0)).toEqual({ ok: true, status: { used: 1, limit: 2, resetsAt: at(60).toISOString() } });
    expect(await usePass(store(), id, 'npm:next', SECRET, at(5))).toMatchObject({ ok: true, status: { used: 1 } });
    expect(await usePass(store(), id, 'npm:next,p:f5/nginx', SECRET, at(10))).toMatchObject({ ok: true, status: { used: 2 } });

    // A third different stack waits for the hour that started with the first.
    expect(await usePass(store(), id, 'pypi:django', SECRET, at(20))).toEqual({ ok: false, status: { used: 2, limit: 2, resetsAt: at(60).toISOString() } });
    // The two it has used still load.
    expect(await usePass(store(), id, 'npm:next', SECRET, at(30))).toMatchObject({ ok: true });

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

  it('limits a pass to two different stacks an hour and reports what is left', async () => {
    const id = await issuePass(store(), new Date());
    const cookie = `vulnder_pass=${id}`;
    // A shared office IP whose limiter is spent doesn't stop a browser with a pass.
    const refuse = { limit: async () => ({ success: false }) } as unknown as RateLimit;
    expect((await feed('pypi:fastapi', cookie, refuse)).status).toBe(200);
    expect((await feed('p:postgresql/postgresql', cookie, refuse)).status).toBe(200);

    const third = await feed('npm:next', cookie, refuse);
    expect(third.status).toBe(429);
    expect(await third.json()).toMatchObject({ reason: 'pass-limit', pass: { used: 2, limit: 2 } });
    expect(Number(third.headers.get('Retry-After'))).toBeGreaterThan(3000);
    expect((await feed('pypi:fastapi', cookie, refuse)).status).toBe(200);

    const status = await app.request('/api/pass', { headers: { cookie } }, e());
    expect(await status.json()).toMatchObject({ active: true, used: 2, limit: 2 });
    expect(await (await app.request('/api/pass', {}, e())).json()).toEqual({ active: false, used: 0, limit: 2, resetsAt: null });
  });
});
