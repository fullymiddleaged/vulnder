import { GITHUB_API_VERSION, USER_AGENT } from '../../config';
import { RateLimited } from '../budget';
import type { SourceContext } from '../types';

export function githubHeaders(ctx: Pick<SourceContext, 'githubToken'>): Record<string, string> {
  const h: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': GITHUB_API_VERSION,
    'User-Agent': USER_AGENT,
  };
  if (ctx.githubToken) h.Authorization = `Bearer ${ctx.githubToken}`;
  return h;
}

/** GETs a GitHub API URL, turning rate-limit responses into RateLimited. */
export async function githubGet(ctx: SourceContext, url: string, source: string): Promise<Response> {
  const res = await ctx.fetch(url, { headers: githubHeaders(ctx) });
  if (res.status === 429 || (res.status === 403 && res.headers.get('x-ratelimit-remaining') === '0')) {
    const reset = res.headers.get('x-ratelimit-reset');
    throw new RateLimited(source, reset ? `resets at ${new Date(Number(reset) * 1000).toISOString()}` : `HTTP ${res.status}`);
  }
  return res;
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
