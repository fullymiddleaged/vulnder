import { describe, expect, it } from 'vitest';
import { Budget, RateLimited } from '../../src/ingest/budget';
import { GITHUB_GAP_MS, githubError, githubGet, RETRY_DELAYS_MS } from '../../src/ingest/sources/github';
import { FakeFetch, jsonResponse } from '../helpers/fake-fetch';
import { sourceContext } from '../helpers/db';

const NOW = new Date('2026-10-04T18:00:00Z');
const URL_ = 'https://api.github.com/advisories';

/** Serves the responses in order, repeating the last one. */
function sequence(...responses: (() => Response)[]): FakeFetch {
  let i = 0;
  return new FakeFetch().on(URL_, () => responses[Math.min(i++, responses.length - 1)]!());
}

function recordingContext(f: FakeFetch, overrides: Parameters<typeof sourceContext>[2] = {}) {
  const waits: number[] = [];
  const ctx = sourceContext(f.fetch, NOW, {
    sleep: async (ms) => {
      waits.push(ms);
    },
    ...overrides,
  });
  return { ctx, waits };
}

describe('githubGet', () => {
  it('retries a server error, then succeeds', async () => {
    const f = sequence(() => jsonResponse({}, { status: 503 }), () => jsonResponse([]));
    const { ctx, waits } = recordingContext(f);
    const res = await githubGet(ctx, URL_, 'ghsa');
    expect(res.status).toBe(200);
    expect(f.calls).toHaveLength(2);
    expect(waits[0]).toBeGreaterThanOrEqual(RETRY_DELAYS_MS[0]!);
  });

  it('gives up after its retries and returns the last error', async () => {
    const f = sequence(() => jsonResponse({}, { status: 502 }));
    const { ctx } = recordingContext(f);
    expect((await githubGet(ctx, URL_, 'ghsa')).status).toBe(502);
    expect(f.calls).toHaveLength(RETRY_DELAYS_MS.length + 1);
  });

  it('retries a dropped connection', async () => {
    let first = true;
    const f = new FakeFetch().on(URL_, () => {
      if (first) {
        first = false;
        throw new TypeError('Network connection lost.');
      }
      return jsonResponse([]);
    });
    const { ctx } = recordingContext(f);
    expect((await githubGet(ctx, URL_, 'ghsa')).status).toBe(200);
    expect(f.calls).toHaveLength(2);
  });

  it('never retries a client error', async () => {
    const f = sequence(() => jsonResponse({ message: 'bad cursor' }, { status: 400 }), () => jsonResponse([]));
    const { ctx } = recordingContext(f);
    expect((await githubGet(ctx, URL_, 'ghsa')).status).toBe(400);
    expect(f.calls).toHaveLength(1);
  });

  it('waits out a short secondary rate limit', async () => {
    const f = sequence(() => jsonResponse({ message: 'secondary rate limit' }, { status: 403, headers: { 'retry-after': '2' } }), () => jsonResponse([]));
    const { ctx, waits } = recordingContext(f);
    expect((await githubGet(ctx, URL_, 'ghsa')).status).toBe(200);
    expect(waits).toContain(2000);
  });

  it('stops on a long secondary limit, an exhausted primary limit, or a 403 saying so', async () => {
    const limits = [
      () => jsonResponse({}, { status: 429, headers: { 'retry-after': '120' } }),
      () => jsonResponse({}, { status: 403, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1791112003' } }),
      () => jsonResponse({}, { status: 429 }),
      () => jsonResponse({ message: 'You have exceeded a secondary rate limit.' }, { status: 403 }),
    ];
    for (const limit of limits) {
      const f = sequence(limit, () => jsonResponse([]));
      await expect(githubGet(recordingContext(f).ctx, URL_, 'ghsa')).rejects.toBeInstanceOf(RateLimited);
      expect(f.calls).toHaveLength(1);
    }
  });

  it('returns a plain 403 as a refusal, not a rate limit', async () => {
    const f = sequence(() => jsonResponse({ message: 'Resource not accessible by integration' }, { status: 403 }));
    const res = await githubGet(recordingContext(f).ctx, URL_, 'ghsa');
    expect(res.status).toBe(403);
    expect((await githubError(res, 'GitHub advisories')).message).toBe('GitHub advisories: HTTP 403 (Resource not accessible by integration)');
  });

  it('does not retry once the budget is spent', async () => {
    const f = sequence(() => jsonResponse({}, { status: 503 }), () => jsonResponse([]));
    const budget = new Budget({ maxSubrequests: 1, deadline: Number.MAX_SAFE_INTEGER });
    const { ctx } = recordingContext(f, { budget });
    expect((await githubGet(ctx, URL_, 'ghsa')).status).toBe(503);
    expect(f.calls).toHaveLength(1);
  });

  it('spaces calls in a run apart', async () => {
    const f = sequence(() => jsonResponse([]));
    const { ctx, waits } = recordingContext(f);
    await githubGet(ctx, URL_, 'ghsa');
    await githubGet(ctx, URL_, 'ghsa');
    expect(waits).toHaveLength(1);
    expect(waits[0]).toBeGreaterThan(0);
    expect(waits[0]).toBeLessThanOrEqual(GITHUB_GAP_MS);
  });
});

describe('githubError', () => {
  it('copes with a body that is not JSON', async () => {
    const err = await githubError(new Response('<html>oops</html>', { status: 400 }), 'cvelistV5 releases');
    expect(err.message).toBe('cvelistV5 releases: HTTP 400');
  });
});
