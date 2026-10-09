import { env } from 'cloudflare:workers';
import { Budget } from '../../src/ingest/budget';
import { D1BindingStore } from '../../src/ingest/d1-store';
import type { SourceContext } from '../../src/ingest/types';

export async function resetDb(): Promise<void> {
  await env.DB.batch(
    ['vulns', 'aliases', 'affected', 'events', 'catalog', 'meta', 'usage_counters', 'families', 'feed_passes'].map((t) => env.DB.prepare(`DELETE FROM ${t}`)),
  );
}

export function store(): D1BindingStore {
  return new D1BindingStore(env.DB);
}

export function unlimitedBudget(): Budget {
  return new Budget({ maxSubrequests: 1_000_000, deadline: Number.MAX_SAFE_INTEGER });
}

export function sourceContext(fetchImpl: typeof fetch, now: Date, overrides: Partial<SourceContext> = {}): SourceContext {
  const budget = overrides.budget ?? unlimitedBudget();
  return {
    fetch: budget.wrapFetch(fetchImpl),
    store: store(),
    budget,
    now: () => now,
    log: () => {},
    runtime: 'worker',
    sleep: async () => {},
    ...overrides,
  };
}

export async function rows<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T[]> {
  return (await env.DB.prepare(sql).bind(...params).all<T>()).results;
}
