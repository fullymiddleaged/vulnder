import { USER_AGENT } from '../config';

/**
 * OSV querybatch (https://google.github.io/osv.dev/post-v1-querybatch/):
 * which vulnerabilities affect an exact package version. Results are cached
 * per (ecosystem, name, version) in the Cache API.
 */

export const OSV_QUERYBATCH_URL = 'https://api.osv.dev/v1/querybatch';
const MAX_QUERIES = 1000;
/** Follow-up pages per query when OSV paginates (very large result sets only). */
const MAX_PAGES = 3;
const CACHE_TTL_SECONDS = 6 * 3600;
const CACHE_ORIGIN = 'https://osv-cache.vulnture.invalid';
/** Someone is waiting on the page; give up on OSV rather than hang. */
const TIMEOUT_MS = 5000;

export interface OsvQuery {
  ecosystem: string;
  name: string;
  version: string;
}

export interface OsvClient {
  /** Affecting OSV IDs per query, keyed by queryKey(). Throws if OSV is unreachable. */
  affecting(queries: OsvQuery[]): Promise<Map<string, Set<string>>>;
}

export const queryKey = (q: OsvQuery) => `${q.ecosystem}\u0000${q.name}\u0000${q.version}`;

interface BatchResponse {
  results?: { vulns?: { id?: string }[]; next_page_token?: string }[];
}

export function createOsvClient(fetchImpl: typeof fetch, cache: Cache | null): OsvClient {
  const cacheUrl = (q: OsvQuery) =>
    `${CACHE_ORIGIN}/v1/${encodeURIComponent(q.ecosystem)}/${encodeURIComponent(q.name)}/${encodeURIComponent(q.version)}`;

  return {
    async affecting(queries) {
      const out = new Map<string, Set<string>>();
      const unique = [...new Map(queries.map((q) => [queryKey(q), q])).values()];
      const misses: OsvQuery[] = [];

      for (const q of unique) {
        const hit = cache ? await cache.match(cacheUrl(q)) : undefined;
        if (hit) out.set(queryKey(q), new Set((await hit.json()) as string[]));
        else misses.push(q);
      }

      for (let i = 0; i < misses.length; i += MAX_QUERIES) {
        const chunk = misses.slice(i, i + MAX_QUERIES);
        const ids = chunk.map(() => new Set<string>());
        let pending = chunk.map((q, j) => ({ j, body: { package: { ecosystem: q.ecosystem, name: q.name }, version: q.version } as Record<string, unknown> }));
        for (let page = 0; pending.length > 0 && page <= MAX_PAGES; page++) {
          const res = await fetchImpl(OSV_QUERYBATCH_URL, {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'user-agent': USER_AGENT },
            body: JSON.stringify({ queries: pending.map((p) => p.body) }),
            signal: AbortSignal.timeout(TIMEOUT_MS),
          });
          if (!res.ok) throw new Error(`OSV querybatch: HTTP ${res.status}`);
          const body = (await res.json()) as BatchResponse;
          const next: typeof pending = [];
          pending.forEach((p, k) => {
            const r = body.results?.[k];
            for (const v of r?.vulns ?? []) if (v.id) ids[p.j]!.add(v.id);
            if (r?.next_page_token) next.push({ j: p.j, body: { ...p.body, page_token: r.next_page_token } });
          });
          pending = next;
        }
        for (const [j, q] of chunk.entries()) {
          out.set(queryKey(q), ids[j]!);
          if (cache) {
            await cache.put(
              cacheUrl(q),
              new Response(JSON.stringify([...ids[j]!]), {
                headers: { 'content-type': 'application/json', 'cache-control': `max-age=${CACHE_TTL_SECONDS}` },
              }),
            );
          }
        }
      }
      return out;
    },
  };
}
