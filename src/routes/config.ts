import { Hono } from 'hono';
import type { AppEnv } from '../types';

/** Public settings the front end needs. Nothing secret. */
export const config = new Hono<AppEnv>().get('/', (c) =>
  c.json(
    { displayName: c.env.DISPLAY_NAME, baseUrl: c.env.BASE_URL.replace(/\/+$/, ''), turnstileSiteKey: c.env.TURNSTILE_SITE_KEY },
    200,
    { 'Cache-Control': 'public, max-age=300' },
  ),
);
