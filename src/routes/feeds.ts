import { Hono, type Context } from 'hono';
import { D1BindingStore } from '../ingest/d1-store';
import { DATA_VERSION_KEY, getMeta } from '../ingest/meta';
import { addDays } from '../lib/time';
import { changesFor, matchStack, type ChangeEvent, type MatchedVuln, type MatchResult } from '../match/match';
import { createOsvClient } from '../match/osv';
import { parseStack, serializeStack, StackFormatError, type StackItem } from '../stack/format';
import type { AppEnv } from '../types';

/**
 * GET /api/feed, /feed.xml and /badge.svg for a stack in `s`.
 * Responses are cached in the Cache API, keyed on the canonical stack, the
 * window and the data version, so they invalidate whenever ingest writes.
 * Nothing here logs the stack.
 */

export const DEFAULT_DAYS = 30;
export const MAX_DAYS = 90;
const CHANGES_DAYS = 7;
const CACHE_SECONDS = 300;

interface StackRequest {
  items: StackItem[];
  canonical: string;
  days: number;
}

function readParams(c: Context<AppEnv>): StackRequest | Response {
  const s = c.req.query('s');
  if (!s) return c.json({ error: 'missing the s parameter; see docs/STACK_FORMAT.md' }, 400);
  let items: StackItem[];
  try {
    items = parseStack(s);
  } catch (err) {
    if (err instanceof StackFormatError) return c.json({ error: err.message, invalid: err.invalid }, 400);
    throw err;
  }
  const daysParam = c.req.query('days');
  const days = daysParam === undefined ? DEFAULT_DAYS : Number(daysParam);
  if (!Number.isInteger(days) || days < 1 || days > MAX_DAYS) {
    return c.json({ error: `days must be a whole number from 1 to ${MAX_DAYS}` }, 400);
  }
  return { items, canonical: serializeStack(items), days };
}

export function baseUrl(env: Env): string {
  return env.BASE_URL.replace(/\/+$/, '');
}

export function stackLinks(base: string, canonical: string, days: number) {
  const q = `s=${encodeURIComponent(canonical)}${days === DEFAULT_DAYS ? '' : `&days=${days}`}`;
  return {
    page: `${base}/?${q}`,
    json: `${base}/api/feed?${q}`,
    atom: `${base}/feed.xml?${q}`,
    badge: `${base}/badge.svg?${q}`,
  };
}

async function cached(
  c: Context<AppEnv>,
  route: string,
  req: StackRequest,
  build: (dataVersion: number) => Promise<Response>,
): Promise<Response> {
  const store = new D1BindingStore(c.env.DB);
  const dataVersion = Number((await getMeta<number>(store, DATA_VERSION_KEY)) ?? 0);
  const key = new Request(
    `${baseUrl(c.env)}/__cache/${route}?s=${encodeURIComponent(req.canonical)}&days=${req.days}&v=${dataVersion}`,
  );
  const cache = await openCache();
  const hit = cache ? await cache.match(key) : undefined;
  // Cached responses have immutable headers; copy so middleware can add to them.
  if (hit) return new Response(hit.body, hit);

  const res = await build(dataVersion);
  res.headers.set('Cache-Control', `public, max-age=${CACHE_SECONDS}`);
  if (cache && res.ok) {
    const put = cache.put(key, res.clone());
    try {
      c.executionCtx.waitUntil(put);
    } catch {
      await put; // no execution context (tests)
    }
  }
  return res;
}

async function openCache(): Promise<Cache | null> {
  try {
    return await caches.open('vulnder-feeds');
  } catch {
    return null;
  }
}

async function runMatch(c: Context<AppEnv>, req: StackRequest, now: Date): Promise<MatchResult> {
  const osvCache = await (async () => {
    try {
      return await caches.open('vulnder-osv');
    } catch {
      return null;
    }
  })();
  return matchStack(new D1BindingStore(c.env.DB), req.items, {
    now,
    days: req.days,
    osv: createOsvClient((input, init) => fetch(input, init), osvCache),
  });
}

export const feeds = new Hono<AppEnv>()
  .get('/api/feed', async (c) => {
    const req = readParams(c);
    if (req instanceof Response) return req;
    return cached(c, 'feed', req, async (dataVersion) => {
      const now = new Date();
      const match = await runMatch(c, req, now);
      const byId = new Map(match.results.map((r) => [r.id, r]));
      const changes = await changesFor(
        new D1BindingStore(c.env.DB),
        match.results.map((r) => r.id),
        addDays(now, -CHANGES_DAYS).toISOString(),
      );
      return c.json({
        stack: req.canonical,
        days: req.days,
        generatedAt: now.toISOString(),
        dataVersion,
        links: stackLinks(baseUrl(c.env), req.canonical, req.days),
        versionCheckUnavailable: match.versionCheckUnavailable,
        summary: {
          exploited: match.results.filter((r) => r.tier === 'exploited').length,
          likely: match.results.filter((r) => r.tier === 'likely').length,
          backlog: match.results.filter((r) => r.tier === 'backlog').length,
        },
        changes: changes.map((e) => ({ ...e, title: byId.get(e.vulnId)?.title ?? null, tier: byId.get(e.vulnId)?.tier })),
        results: match.results,
        watching: match.watching,
      });
    });
  })
  .get('/feed.xml', async (c) => {
    const req = readParams(c);
    if (req instanceof Response) return req;
    return cached(c, 'atom', req, async () => {
      const now = new Date();
      const match = await runMatch(c, req, now);
      const events = await changesFor(
        new D1BindingStore(c.env.DB),
        match.results.map((r) => r.id),
        addDays(now, -req.days).toISOString(),
      );
      const xml = atomFeed({
        base: baseUrl(c.env),
        displayName: c.env.DISPLAY_NAME,
        canonical: req.canonical,
        days: req.days,
        now,
        events,
        vulns: new Map(match.results.map((r) => [r.id, r])),
      });
      return c.body(xml, 200, { 'Content-Type': 'application/atom+xml; charset=utf-8' });
    });
  })
  .get('/badge.svg', async (c) => {
    const req = readParams(c);
    if (req instanceof Response) return req;
    return cached(c, 'badge', req, async () => {
      const match = await runMatch(c, req, new Date());
      const n = match.results.filter((r) => r.tier === 'exploited').length;
      return c.body(badgeSvg(n), 200, { 'Content-Type': 'image/svg+xml; charset=utf-8' });
    });
  });

// ---- Atom ----

export function eventTitle(e: ChangeEvent, v: MatchedVuln | undefined): string {
  const name = v?.title ? `${e.vulnId}: ${v.title}` : e.vulnId;
  switch (e.type) {
    case 'kev_added':
      return `Known exploited (added to CISA KEV): ${name}`;
    case 'epss_crossed': {
      const to = typeof e.detail.to === 'number' ? `${(e.detail.to * 100).toFixed(1)}%` : 'a higher value';
      return `EPSS rose to ${to}: ${name}`;
    }
    case 'fix_released': {
      const what = e.detail.package ?? e.detail.product ?? 'a component';
      return `Fix released (${String(what)} ${String(e.detail.fixedVersion ?? '')}): ${name}`.replace(' )', ')');
    }
    default:
      return `New: ${name}`;
  }
}

function eventSummary(e: ChangeEvent, v: MatchedVuln | undefined): string {
  const lines: string[] = [];
  if (e.type === 'epss_crossed') {
    lines.push('EPSS is a predicted probability of exploitation in the next 30 days, not evidence of exploitation.');
  }
  if (v) {
    lines.push(`Tier: ${v.tier}. Confidence: ${v.confidence === 'version_confirmed' ? 'version confirmed' : 'product match'}.`);
    lines.push(`Matched: ${v.matched.join(', ')}.`);
    if (v.fixedVersions.length > 0) lines.push(`Fixed in: ${v.fixedVersions.join(', ')}.`);
    if (v.summary) lines.push(v.summary);
  }
  return lines.join('\n\n');
}

export function atomFeed(opts: {
  base: string;
  displayName: string;
  canonical: string;
  days: number;
  now: Date;
  events: ChangeEvent[];
  vulns: Map<string, MatchedVuln>;
}): string {
  const links = stackLinks(opts.base, opts.canonical, opts.days);
  const updated = opts.events[0]?.occurredAt ?? opts.now.toISOString();
  const entries = opts.events.map((e) => {
    const v = opts.vulns.get(e.vulnId);
    const id = `${opts.base}/events/${encodeURIComponent(e.vulnId)}/${e.type}/${encodeURIComponent(e.occurredAt)}`;
    const href = v?.links.advisory ?? links.page;
    return `  <entry>
    <id>${xml(id)}</id>
    <title>${xml(eventTitle(e, v))}</title>
    <updated>${xml(e.occurredAt)}</updated>
    <link rel="alternate" href="${xml(href)}"/>
    <category term="${xml(e.type)}"/>
    <summary type="text">${xml(eventSummary(e, v))}</summary>
  </entry>`;
  });
  return `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>${xml(links.atom)}</id>
  <title>${xml(`${opts.displayName}: changes for your stack`)}</title>
  <subtitle>${xml(`Vulnerability changes from the last ${opts.days} days for this stack, one entry per change.`)}</subtitle>
  <updated>${xml(updated)}</updated>
  <link rel="self" href="${xml(links.atom)}"/>
  <link rel="alternate" href="${xml(links.page)}"/>
  <generator>${xml(opts.displayName)}</generator>
${entries.join('\n')}
</feed>
`;
}

function xml(s: string): string {
  return s
    // eslint-disable-next-line no-control-regex -- strip characters XML 1.0 cannot represent
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ---- Badge ----

/** Approximate Verdana 11px widths, as shields.io-style badges use. */
function textWidth(s: string): number {
  let w = 0;
  for (const ch of s) w += /[ilj.,:;|!']/.test(ch) ? 3.5 : /[mwMW]/.test(ch) ? 9.5 : /[A-Z0-9]/.test(ch) ? 7.5 : 6.5;
  return Math.ceil(w);
}

export function badgeSvg(count: number): string {
  const label = 'known-exploited';
  const value = `${count} CVE${count === 1 ? '' : 's'}`;
  const color = count === 0 ? '#2e7d32' : '#c62828';
  const lw = textWidth(label) + 12;
  const vw = textWidth(value) + 12;
  const total = lw + vw;
  const aria = `${count} known-exploited CVE${count === 1 ? '' : 's'}`;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="20" role="img" aria-label="${aria}">
  <title>${aria}</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="${total}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${lw}" height="20" fill="#555"/>
    <rect x="${lw}" width="${vw}" height="20" fill="${color}"/>
    <rect width="${total}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${lw / 2}" y="14">${label}</text>
    <text x="${lw + vw / 2}" y="14">${value}</text>
  </g>
</svg>
`;
}
