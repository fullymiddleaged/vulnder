import { GITHUB_API_VERSION, USER_AGENT } from '../../config';
import { RateLimited } from '../budget';
import type { SourceContext } from '../types';

/** Least time between two GitHub calls in a run; GitHub asks for serial, unhurried requests. */
export const GITHUB_GAP_MS = 250;
/** Waits before each soft retry of a 5xx or a dropped connection. */
export const RETRY_DELAYS_MS = [1_000, 3_000];
/** A secondary limit asking for a longer wait than this ends the run's GitHub work instead. */
export const MAX_RETRY_AFTER_S = 10;
const MAX_MESSAGE = 200;

export function githubHeaders(ctx: Pick<SourceContext, 'githubToken'>): Record<string, string> {
  const h: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': GITHUB_API_VERSION,
    'User-Agent': USER_AGENT,
  };
  if (ctx.githubToken) h.Authorization = `Bearer ${ctx.githubToken}`;
  return h;
}

/** GETs a GitHub API URL, paced and softly retried (see githubFetch). */
export function githubGet(ctx: SourceContext, url: string, source: string): Promise<Response> {
  return githubFetch(ctx, url, { headers: githubHeaders(ctx) }, source);
}

const lastCallAt = new WeakMap<SourceContext, number>();

/**
 * Fetches from GitHub (API or downloads) one call at a time, at least
 * GITHUB_GAP_MS apart. 5xx responses and dropped connections are retried after
 * RETRY_DELAYS_MS while the budget allows, and so is a secondary rate limit
 * with a short retry-after. Other rate limits throw RateLimited, so the run
 * stops this source and the next one resumes from its cursor. Other 4xx
 * responses are returned as they are, never retried.
 */
export async function githubFetch(ctx: SourceContext, url: string, init: RequestInit, source: string): Promise<Response> {
  for (let attempt = 0; ; attempt++) {
    const retryLeft = attempt < RETRY_DELAYS_MS.length && ctx.budget.has(2);
    await pace(ctx);
    let res: Response;
    try {
      res = await ctx.fetch(url, init);
    } catch (err) {
      // Network failures surface as TypeError; timeouts and budget errors don't.
      if (!(err instanceof TypeError) || !retryLeft) throw err;
      ctx.log(`${source}: GitHub connection failed (${err.message}), retrying`);
      await backoff(ctx, attempt);
      continue;
    }

    const limit = await rateLimit(res);
    if (limit) {
      if (limit.retryAfterS === null || limit.retryAfterS > MAX_RETRY_AFTER_S || !retryLeft) {
        throw new RateLimited(source, limit.detail);
      }
      ctx.log(`${source}: GitHub asked to wait ${limit.retryAfterS}s, retrying`);
      await sleep(ctx, limit.retryAfterS * 1000);
      continue;
    }
    if (res.status >= 500 && retryLeft) {
      ctx.log(`${source}: GitHub HTTP ${res.status}, retrying`);
      await res.body?.cancel();
      await backoff(ctx, attempt);
      continue;
    }
    return res;
  }
}

/** Reads a rate-limit response (primary or secondary), or null for any other response. */
async function rateLimit(res: Response): Promise<{ retryAfterS: number | null; detail: string } | null> {
  if (res.status !== 403 && res.status !== 429) return null;
  const retryAfter = res.headers.get('retry-after');
  const reset = res.headers.get('x-ratelimit-reset');
  const resetDetail = reset ? `resets at ${new Date(Number(reset) * 1000).toISOString()}` : `HTTP ${res.status}`;
  if (res.headers.get('x-ratelimit-remaining') === '0') return { retryAfterS: null, detail: resetDetail };
  if (retryAfter !== null) {
    const s = Number(retryAfter);
    return { retryAfterS: Number.isFinite(s) && s >= 0 ? s : null, detail: `retry after ${retryAfter}s` };
  }
  if (res.status === 429) return { retryAfterS: null, detail: 'HTTP 429' };
  // A 403 is a rate limit only when GitHub says so; otherwise it's a real refusal.
  const message = await githubMessage(res.clone());
  return message && /rate limit/i.test(message) ? { retryAfterS: null, detail: message } : null;
}

/** An error naming the call, its status and GitHub's own message, if any. */
export async function githubError(res: Response, what: string): Promise<Error> {
  const message = await githubMessage(res);
  return new Error(`${what}: HTTP ${res.status}${message ? ` (${message})` : ''}`);
}

/** GitHub's `message` from an error body, on one line and capped; null if there isn't one. */
async function githubMessage(res: Response): Promise<string | null> {
  try {
    const body = (await res.json()) as { message?: unknown };
    if (typeof body?.message !== 'string') return null;
    return body.message.replace(/\s+/g, ' ').trim().slice(0, MAX_MESSAGE) || null;
  } catch {
    return null;
  }
}

async function pace(ctx: SourceContext): Promise<void> {
  const last = lastCallAt.get(ctx);
  if (last !== undefined) {
    const wait = last + GITHUB_GAP_MS - Date.now();
    if (wait > 0) await sleep(ctx, wait);
  }
  lastCallAt.set(ctx, Date.now());
}

function backoff(ctx: SourceContext, attempt: number): Promise<void> {
  return sleep(ctx, RETRY_DELAYS_MS[attempt]! + Math.floor(Math.random() * 250));
}

function sleep(ctx: SourceContext, ms: number): Promise<void> {
  return ctx.sleep ? ctx.sleep(ms) : new Promise((resolve) => setTimeout(resolve, ms));
}

/** The URL for rel="next" in a Link header, if any. */
export function nextLink(header: string | null): string | null {
  if (!header) return null;
  for (const part of header.split(',')) {
    const m = /<([^>]+)>\s*;\s*rel="next"/.exec(part);
    if (m) return m[1]!;
  }
  return null;
}
