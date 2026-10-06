import { stmt, type Statement, type Store } from './store';
import type { SourceName } from './types';

export interface SourceStatus {
  lastRunAt: string | null;
  lastSuccessAt: string | null;
  /** True when the last run stopped on its budget and has more to fetch. */
  partial: boolean;
  lastError: string | null;
  lastErrorAt: string | null;
  lastRecords: number;
}

export const EMPTY_STATUS: SourceStatus = {
  lastRunAt: null,
  lastSuccessAt: null,
  partial: false,
  lastError: null,
  lastErrorAt: null,
  lastRecords: 0,
};

export const cursorKey = (source: SourceName) => `cursor:${source}`;
export const statusKey = (source: SourceName) => `status:${source}`;
export const DATA_VERSION_KEY = 'data_version';
export const LAST_MAINTENANCE_KEY = 'last_maintenance';
/** Present while scripts/seed-remote.ts is copying a snapshot in; ingest waits until it's gone. */
export const SEEDING_KEY = 'seeding';

export async function getMeta<T>(store: Store, key: string): Promise<T | null> {
  const rows = await store.all<{ value: string }>('SELECT value FROM meta WHERE key = ?', [key]);
  if (rows.length === 0) return null;
  try {
    return JSON.parse(rows[0]!.value) as T;
  } catch {
    return null;
  }
}

export async function getAllMeta(store: Store): Promise<Map<string, unknown>> {
  const rows = await store.all<{ key: string; value: string }>('SELECT key, value FROM meta');
  const out = new Map<string, unknown>();
  for (const r of rows) {
    try {
      out.set(r.key, JSON.parse(r.value));
    } catch {
      // ignore malformed values
    }
  }
  return out;
}

export function setMetaStatement(key: string, value: unknown, now: Date): Statement {
  return stmt(
    'INSERT INTO meta (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at',
    key,
    JSON.stringify(value),
    now.toISOString(),
  );
}

export function bumpDataVersionStatement(now: Date): Statement {
  return stmt(
    `INSERT INTO meta (key, value, updated_at) VALUES ('${DATA_VERSION_KEY}', '1', ?)
     ON CONFLICT (key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT), updated_at = excluded.updated_at`,
    now.toISOString(),
  );
}
