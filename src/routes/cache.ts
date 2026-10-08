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

/**
 * Stores a response without holding up the reply. `cacheControl`, when given,
 * replaces the stored copy's Cache-Control, so the edge can keep it longer
 * than browsers do.
 */
export async function putInBackground(c: Context<AppEnv>, cache: Cache, key: Request, res: Response, cacheControl?: string): Promise<void> {
  let copy = res.clone();
  if (cacheControl) {
    copy = new Response(copy.body, copy);
    copy.headers.set('Cache-Control', cacheControl);
  }
  const put = cache.put(key, copy);
  try {
    c.executionCtx.waitUntil(put);
  } catch {
    await put; // no execution context (tests)
  }
}
