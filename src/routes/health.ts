import { Hono } from 'hono';
import { STALE_AFTER_HOURS } from '../config';
import { D1BindingStore } from '../ingest/d1-store';
import { DATA_VERSION_KEY, EMPTY_STATUS, statusKey, type SourceStatus } from '../ingest/meta';
import { SOURCE_ORDER } from '../ingest/run';
import type { AppEnv } from '../types';
import { openCache, putInBackground } from './cache';
import { baseUrl } from './feeds';

export type SourceHealth = 'ok' | 'stale' | 'error' | 'never';

/**
 * Freshness per source. Staleness is judged from the last
 * successful run, which also catches a GitHub Actions schedule that GitHub has
 * disabled after 60 days without repository activity.
 */
export function sourceHealth(status: SourceStatus, staleAfterHours: number, now: Date): SourceHealth {
  if (!status.lastSuccessAt) return status.lastError ? 'error' : 'never';
  const ageHours = (now.getTime() - Date.parse(status.lastSuccessAt)) / 3_600_000;
  if (ageHours > staleAfterHours) return 'stale';
  if (status.lastError && status.lastErrorAt && status.lastErrorAt > status.lastSuccessAt) return 'error';
  return 'ok';
}

/** Ingest runs hourly, so a reply up to 15 minutes old is still accurate enough. */
export const HEALTH_CACHE_SECONDS = 900;
export const HEALTH_CACHE = 'vulnder-health';

/** The per-source status rows and the data version: one query, a primary-key lookup per row. */
export const HEALTH_META_SQL = 'SELECT key, value FROM meta WHERE key IN (SELECT value FROM json_each(?))';
const HEALTH_KEYS = [...SOURCE_ORDER.map(statusKey), DATA_VERSION_KEY];
export const healthCacheKey = (env: Env) => new Request(`${baseUrl(env)}/__cache/health`);

export const health = new Hono<AppEnv>().get('/', async (c) => {
  // Every page load asks for this (the footer), so it is served from the edge
  // cache and reaches D1 at most once per cache period per location.
  const key = healthCacheKey(c.env);
  const cache = await openCache(HEALTH_CACHE);
  const hit = cache ? await cache.match(key) : undefined;
  if (hit) return new Response(hit.body, hit);

  const store = new D1BindingStore(c.env.DB);
  const now = new Date();
  const meta = new Map<string, unknown>();
  for (const r of await store.all<{ key: string; value: string }>(HEALTH_META_SQL, [JSON.stringify(HEALTH_KEYS)])) {
    try {
      meta.set(r.key, JSON.parse(r.value));
    } catch {
      // ignore malformed values
    }
  }

  const sources = Object.fromEntries(
    SOURCE_ORDER.map((name) => {
      const status = { ...EMPTY_STATUS, ...((meta.get(statusKey(name)) as Partial<SourceStatus>) ?? {}) };
      return [
        name,
        {
          health: sourceHealth(status, STALE_AFTER_HOURS[name] ?? 6, now),
          lastSuccessAt: status.lastSuccessAt,
          lastRunAt: status.lastRunAt,
          catchingUp: status.partial,
          // Upstream error text can include URLs but never user input.
          lastError: status.lastError,
        },
      ];
    }),
  );
  const overall = Object.values(sources).every((s) => s.health === 'ok') ? 'ok' : 'degraded';

  const res = c.json(
    {
      status: overall,
      sources,
      dataVersion: Number(meta.get(DATA_VERSION_KEY) ?? 0),
      ingestRuntime: c.env.INGEST_RUNTIME,
    },
    200,
    { 'Cache-Control': `public, max-age=${HEALTH_CACHE_SECONDS}` },
  );
  if (cache) await putInBackground(c, cache, key, res);
  return res;
});
