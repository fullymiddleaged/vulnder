import { Hono } from 'hono';
import { STALE_AFTER_HOURS } from '../config';
import { D1BindingStore } from '../ingest/d1-store';
import { DATA_VERSION_KEY, EMPTY_STATUS, getAllMeta, statusKey, type SourceStatus } from '../ingest/meta';
import { SOURCE_ORDER } from '../ingest/run';
import type { AppEnv } from '../types';

export type SourceHealth = 'ok' | 'stale' | 'error' | 'never';

/**
 * Freshness per source plus record counts. Staleness is judged from the last
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

export const health = new Hono<AppEnv>().get('/', async (c) => {
  const store = new D1BindingStore(c.env.DB);
  const now = new Date();
  const [meta, counts] = await Promise.all([
    getAllMeta(store),
    store.all<{ vulns: number; affected: number; events: number; catalog: number }>(
      `SELECT (SELECT COUNT(*) FROM vulns) AS vulns, (SELECT COUNT(*) FROM affected) AS affected,
              (SELECT COUNT(*) FROM events) AS events, (SELECT COUNT(*) FROM catalog) AS catalog`,
    ),
  ]);

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

  return c.json(
    {
      status: overall,
      sources,
      counts: counts[0] ?? { vulns: 0, affected: 0, events: 0, catalog: 0 },
      dataVersion: Number(meta.get(DATA_VERSION_KEY) ?? 0),
      ingestRuntime: c.env.INGEST_RUNTIME,
    },
    200,
    { 'Cache-Control': 'public, max-age=60' },
  );
});
