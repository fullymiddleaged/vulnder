import { describe, expect, it } from 'vitest';
import { EXTRACT_DEADLINE_MS, EXTRACT_HEDGE_MS, JEV_TIMEOUT_MS } from '../src/resolve/limits';
import { ApiError, oneAtATime, READ_DEADLINE_MS, READ_SLOW_MS, readHint, request, RESOLVE_TIMEOUT_MS } from '../web/api';

describe('reading a description', () => {
  it("waits longer than the server's own model deadlines, so the manual fallback answers first", () => {
    expect(READ_DEADLINE_MS).toBe(JEV_TIMEOUT_MS + EXTRACT_DEADLINE_MS + JEV_TIMEOUT_MS);
    expect(RESOLVE_TIMEOUT_MS).toBeGreaterThan(READ_DEADLINE_MS);
  });

  it('says it is running long once the second model would have started', () => {
    expect(READ_SLOW_MS).toBeGreaterThan(EXTRACT_HEDGE_MS);
    expect(readHint(0)).toBe('This usually takes a few seconds.');
    expect(readHint(READ_SLOW_MS - 1)).toBe(readHint(0));
    expect(readHint(READ_SLOW_MS)).toMatch(/^Taking longer than usual\. When the first AI model is slow, Vulnder asks a second one\.$/);
  });
});

/** A server that never answers: settles only when the request's signal aborts it. */
const hang: typeof fetch = (_url, init) =>
  new Promise((_, reject) => init?.signal?.addEventListener('abort', () => reject(init.signal!.reason)));

describe('request', () => {
  it('gives up on a request that never answers, and says it took too long', async () => {
    const err = await request('/api/feed', {}, 20, hang).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ reason: 'timeout', message: 'Vulnder took too long to answer. Try again in a moment.' });
  });

  it('says so when the connection drops', async () => {
    const offline: typeof fetch = async () => Promise.reject(new TypeError('Failed to fetch'));
    await expect(request('/api/feed', {}, 1000, offline)).rejects.toMatchObject({ reason: 'network', message: "Couldn't reach Vulnder. Check your connection and try again." });
  });

  it('passes the answer through, and keeps the caller’s options', async () => {
    let seen: RequestInit | undefined;
    const ok: typeof fetch = async (_url, init) => ((seen = init), Response.json({ ok: true }));
    const res = await request('/api/resolve', { method: 'POST', body: '{}' }, 1000, ok);
    expect(await res.json()).toEqual({ ok: true });
    expect(seen).toMatchObject({ method: 'POST', body: '{}', signal: expect.any(AbortSignal) });
  });
});

describe('oneAtATime', () => {
  it('drops a second send while the first is out, and takes the next one after it settles', async () => {
    const run = oneAtATime();
    let release!: () => void;
    let sends = 0;
    const slow = () => new Promise<void>((r) => ((sends += 1), (release = r)));
    const first = run(slow);
    expect(await run(slow)).toBe(false);
    expect(sends).toBe(1);
    release();
    expect(await first).toBe(true);
    expect(await run(async () => void (sends += 1))).toBe(true);
    expect(sends).toBe(2);
  });

  it('lets go after a send that fails', async () => {
    const run = oneAtATime();
    await expect(run(async () => Promise.reject(new Error('down')))).rejects.toThrow('down');
    expect(await run(async () => {})).toBe(true);
  });
});
