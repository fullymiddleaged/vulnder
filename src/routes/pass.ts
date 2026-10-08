import { Hono } from 'hono';
import { getCookie } from 'hono/cookie';
import { D1BindingStore } from '../ingest/d1-store';
import { PASS_COOKIE, PASS_STACKS, passStatus } from '../lib/pass';
import type { AppEnv } from '../types';

/**
 * GET /api/pass: what this browser's pass has left this hour, so the page can
 * grey out looking up another stack. `active` is false without a valid pass;
 * the page then gets one from its next POST /api/resolve.
 */
export const pass = new Hono<AppEnv>().get('/', async (c) => {
  const id = getCookie(c, PASS_COOKIE);
  const status = id ? await passStatus(new D1BindingStore(c.env.DB), id, new Date()) : null;
  return c.json({ active: status !== null, ...(status ?? { used: 0, limit: PASS_STACKS, resetsAt: null }) }, 200, { 'Cache-Control': 'no-store' });
});
