import { describe, expect, it } from 'vitest';
import { ApiError, request } from '../web/api';

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
