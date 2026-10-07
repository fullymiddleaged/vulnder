import type { Context } from 'hono';
import type { AppEnv } from '../types';

/** A named Cache API cache, or null where there is none. */
export async function openCache(name: string): Promise<Cache | null> {
  try {
    return await caches.open(name);
  } catch {
    return null;
  }
}

/** Stores a response without holding up the reply. */
export async function putInBackground(c: Context<AppEnv>, cache: Cache, key: Request, res: Response): Promise<void> {
  const put = cache.put(key, res.clone());
  try {
    c.executionCtx.waitUntil(put);
  } catch {
    await put; // no execution context (tests)
  }
}
