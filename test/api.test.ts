import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../src/index';
import { applyPatches } from '../src/ingest/apply';
import { bumpDataVersionStatement } from '../src/ingest/meta';
import type { VulnPatch } from '../src/ingest/types';
import { OSV_QUERYBATCH_URL } from '../src/match/osv';
import { MAX_PRODUCT_LOOKUPS } from '../src/resolve/catalog';
import { STACK_DAILY_PER_CLIENT } from '../src/routes/api';
import { parseStack } from '../src/stack/format';
import { resetDb, store } from './helpers/db';

const NOW = new Date();
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();
const GHSA_NEXT = 'GHSA-2222-3333-4444';
const STACK = 'npm:next@14.2.3,pypi:fastapi,p:postgresql/postgresql@16,p:cisco/ios_xe';
let ipSeq = 0;
/** A fresh address per test, so daily quotas and limits never carry over. */
const freshIp = () => `198.51.100.${++ipSeq}`;

function seedPatches(): VulnPatch[] {
  return [
    {
      source: 'ghsa',
      id: 'CVE-2026-1001',
      aliases: [GHSA_NEXT],
      fields: { title: 'Next.js middleware bypass', publishedAt: daysAgo(10), cvssScore: 9.1 },
      affected: [{ kind: 'package', ecosystem: 'npm', packageName: 'next', ranges: [{ range: '< 14.2.5' }], fixedVersion: '14.2.5' }],
    },
    { source: 'kev', id: 'CVE-2026-1001', aliases: [], fields: { kevAddedAt: daysAgo(3), kevRansomware: false, kevDueDate: null } },
    {
      source: 'cve',
      id: 'CVE-2026-1003',
      aliases: [],
      fields: { title: 'PostgreSQL privilege escalation', publishedAt: daysAgo(20), cvssScore: 8.8 },
      affected: [{ kind: 'product', vendor: 'postgresql', product: 'postgresql', ranges: [], fixedVersion: null }],
    },
    {
      source: 'kev',
      id: 'CVE-2026-1005',
      aliases: [],
      fields: { title: 'Cisco IOS XE web UI privilege escalation', kevAddedAt: daysAgo(1), kevRansomware: true, kevDueDate: daysAgo(-20) },
      affected: [{ kind: 'product', vendor: 'cisco', product: 'ios_xe', ranges: [], fixedVersion: null }],
    },
  ];
}

/** OSV says next@14.2.3 is affected by CVE-2026-1001 (via its GHSA alias). */
function stubOsvFetch() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const req = new Request(input, init);
    if (req.url !== OSV_QUERYBATCH_URL) throw new Error(`unexpected fetch ${req.url}`);
    const body = (await req.json()) as { queries: { package: { name: string }; version: string }[] };
    return Response.json({ results: body.queries.map((q) => (q.package.name === 'next' && q.version === '14.2.3' ? { vulns: [{ id: GHSA_NEXT, modified: 'x' }] } : {})) });
  });
}

function post(path: string, body: unknown, ip = freshIp(), e: Env = env) {
  return app.request(path, { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': ip }, body: typeof body === 'string' ? body : JSON.stringify(body) }, e);
}

interface StackReply {
  schema: number;
  stack: string;
  resolved: { input: string; items: { item: string; close: boolean }[] }[];
  unrecognised: string[];
  error?: string;
}

interface RankReply {
  schema: number;
  stack: string;
  dataVersion: number;
  priorities: Record<string, number>;
  rows: Record<string, unknown>[];
  changes: { id: string; cve: string; type: string; priority: string | null }[];
  listed?: { notFound: string[] };
  error?: string;
}

// The Cache API outlives each test and cannot be cleared in workerd, so every
// test starts from its own data version, as feeds.test.ts does.
let versionBase = Date.now() * 100 + 70;

beforeEach(async () => {
  await resetDb();
  await applyPatches(store(), seedPatches(), { now: NOW, windowStart: daysAgo(90), epssEvents: true });
  await store().batch([bumpDataVersionStatement(NOW)]);
  versionBase += 100;
  await env.DB.prepare("UPDATE meta SET value = ? WHERE key = 'data_version'").bind(String(versionBase)).run();
});
afterEach(() => vi.restoreAllMocks());

describe('POST /api/v1/stack', () => {
  it('turns names, versions and CVE IDs into one stack, without Turnstile or a model', async () => {
    const e = { ...env, AI: { run: () => Promise.reject(new Error('model must not be called')) } as unknown as Ai };
    const res = await post(
      '/api/v1/stack',
      {
        packages: [{ ecosystem: 'npm', name: 'next', version: '14.2.3' }],
        products: [{ name: 'postgres', version: '16' }, { name: 'qqzzv flurbo' }],
        cves: ['cve-2026-1005'],
      },
      freshIp(),
      e,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    const body = (await res.json()) as StackReply;
    expect(body.schema).toBe(1);
    expect(parseStack(body.stack).map((i) => (i.kind === 'cve' ? i.id : i.kind === 'package' ? `${i.name}@${i.version}` : `${i.vendor}/${i.product}@${i.version}`))).toEqual([
      'CVE-2026-1005',
      'next@14.2.3',
      'postgresql/postgresql@16',
    ]);
    expect(body.resolved.map((r) => r.input)).toEqual(['next 14.2.3', 'postgres 16']);
    expect(body.unrecognised).toEqual(['qqzzv flurbo']);
  });

  it('takes CVE IDs alone, without spending the daily lookups', async () => {
    const ip = freshIp();
    for (let i = 0; i < 3; i++) expect((await post('/api/v1/stack', { cves: ['CVE-2026-1001'] }, ip)).status).toBe(200);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM usage_counters WHERE bucket = 'api-stack'").first<{ n: number }>()).toEqual({ n: 0 });
  });

  it('answers 422 with what it couldn’t match when nothing resolves', async () => {
    const res = await post('/api/v1/stack', { products: [{ name: 'qqzzv flurbo' }] });
    expect(res.status).toBe(422);
    expect((await res.json()) as StackReply).toMatchObject({ error: 'nothing recognised', unrecognised: ['qqzzv flurbo'] });
  });

  it('refuses bad input with a readable reason', async () => {
    const bad = async (body: unknown) => {
      const res = await post('/api/v1/stack', body);
      expect(res.status).toBe(400);
      return ((await res.json()) as { error: string; details?: string[] });
    };
    expect((await bad('not json')).error).toBe('invalid JSON');
    expect((await bad({})).details).toEqual(['body: send products, packages or cves']);
    expect((await bad({ packages: [{ ecosystem: 'PyPI', name: 'x' }] })).details?.[0]).toMatch(/^packages\.0\.ecosystem:/);
    expect((await bad({ text: 'nginx and postgres' })).details?.[0]).toMatch(/Unrecognized key/);
    expect((await bad({ cves: ['log4shell'] })).error).toMatch(/^not CVE IDs: log4shell/);
  });

  it('refuses more products than a stack can hold', async () => {
    const products = Array.from({ length: MAX_PRODUCT_LOOKUPS + 1 }, (_, i) => ({ name: `widget${i}`, vendor: 'acme' }));
    const res = await post('/api/v1/stack', { products });
    expect(res.status).toBe(413);
    expect(((await res.json()) as { error: string }).error).toMatch(/at most 200 different products/);
  });

  it('limits each client by the minute under its own key, and by the day', async () => {
    const ip = freshIp();
    const limit = vi.fn(async () => ({ success: true }));
    const e = { ...env, RESOLVE_LIMITER: { limit } as unknown as RateLimit };
    expect((await post('/api/v1/stack', { products: [{ name: 'postgres' }] }, ip, e)).status).toBe(200);
    expect(limit.mock.calls).toEqual([[{ key: `api:${ip}` }]]);

    limit.mockResolvedValue({ success: false });
    const refused = await post('/api/v1/stack', { products: [{ name: 'postgres' }] }, ip, e);
    expect(refused.status).toBe(429);
    expect(refused.headers.get('retry-after')).toBe('60');

    // The day's lookups are counted by a hash of the IP; use them up directly.
    const ip2 = freshIp();
    await env.DB.prepare('UPDATE usage_counters SET count = ? WHERE bucket = ?').bind(STACK_DAILY_PER_CLIENT, 'api-stack').run();
    expect((await post('/api/v1/stack', { products: [{ name: 'postgres' }] }, ip)).status).toBe(429);
    expect((await post('/api/v1/stack', { products: [{ name: 'postgres' }] }, ip2)).status).toBe(200);
  });
});

describe('POST /api/v1/rank', () => {
  it('ranks a stack exactly as the JSON feed does, as flat rows', async () => {
    stubOsvFetch();
    const res = await post('/api/v1/rank', { stack: STACK });
    expect(res.status).toBe(200);
    const body = (await res.json()) as RankReply;
    const feed = (await (await app.request(`/api/feed?s=${encodeURIComponent(STACK)}`, {}, env)).json()) as { stack: string; priorities: unknown; results: { id: string }[] };
    expect(body.stack).toBe(feed.stack);
    expect(body.priorities).toEqual(feed.priorities);
    expect(body.rows.map((r) => r.cve)).toEqual(feed.results.map((r) => r.id));
    expect(body.rows[0]).toMatchObject({ cve: 'CVE-2026-1001', priority: 'act', exploited: true, fixedVersions: ['14.2.5'], matched: ['npm:next@14.2.3'] });
    // Every row is flat: scalars, or arrays of strings.
    for (const row of body.rows) {
      for (const v of Object.values(row)) expect(v === null || typeof v !== 'object' || (Array.isArray(v) && v.every((x) => typeof x === 'string'))).toBe(true);
    }
    // Changes carry an ID that stays the same between polls, for deduplicating.
    const kev = body.changes.find((ch) => ch.cve === 'CVE-2026-1001' && ch.type === 'kev_added')!;
    expect(kev).toMatchObject({ priority: 'act' });
    const again = (await (await post('/api/v1/rank', { stack: STACK })).json()) as RankReply;
    expect(again.changes.map((ch) => ch.id)).toContain(kev.id);
  });

  it('ranks CVE IDs, alone or with a stack, whatever their age', async () => {
    const res = await post('/api/v1/rank', { cves: ['CVE-2026-1005', 'CVE-2026-1003', 'CVE-2026-9999'] });
    const body = (await res.json()) as RankReply;
    expect(body.rows.map((r) => r.cve).sort()).toEqual(['CVE-2026-1003', 'CVE-2026-1005']);
    expect(body.listed?.notFound).toEqual(['CVE-2026-9999']);

    stubOsvFetch();
    const both = (await (await post('/api/v1/rank', { stack: 'npm:next@14.2.3', cves: ['CVE-2026-1005'] })).json()) as RankReply;
    expect(both.rows.map((r) => r.cve).sort()).toEqual(['CVE-2026-1001', 'CVE-2026-1005']);
    expect(both.stack).toBe('cve:2026-1005,npm:next@14.2.3');
  });

  it('refuses a bad stack, naming what it didn’t recognise', async () => {
    const res = await post('/api/v1/rank', { stack: 'npm:next,bogus:x' });
    expect(res.status).toBe(400);
    expect((await res.json()) as { invalid: string[] }).toMatchObject({ invalid: ['bogus:x'] });
    expect((await post('/api/v1/rank', { stack: ' ' })).status).toBe(400);
    expect((await post('/api/v1/rank', { stack: 'npm:next', days: 91 })).status).toBe(400);
  });

  it('serves repeats from the cache, and limits new lookups under its own key', async () => {
    stubOsvFetch();
    const ip = freshIp();
    const limit = vi.fn(async () => ({ success: true }));
    const e = { ...env, FEED_LIMITER: { limit } as unknown as RateLimit };
    expect((await post('/api/v1/rank', { stack: 'pypi:fastapi' }, ip, e)).status).toBe(200);
    expect(limit.mock.calls).toEqual([[{ key: `api:${ip}` }]]);
    limit.mockResolvedValue({ success: false });
    expect((await post('/api/v1/rank', { stack: 'pypi:fastapi' }, ip, e)).status).toBe(200);
    const refused = await post('/api/v1/rank', { stack: 'npm:next' }, ip, e);
    expect(refused.status).toBe(429);
    expect(refused.headers.get('retry-after')).toBe('60');
  });
});

describe('machine API privacy', () => {
  it('never logs a stack or a product name', async () => {
    stubOsvFetch();
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => {}));
    await post('/api/v1/stack', { products: [{ name: 'secret-host-widget', vendor: 'acme' }, { name: 'postgres' }] });
    await post('/api/v1/rank', { stack: STACK });
    await post('/api/v1/rank', { stack: 'npm:next,bogus:secret-host' });
    const logged = spies.flatMap((s) => s.mock.calls.flat().map(String)).join('\n');
    expect(logged).not.toMatch(/next@14\.2\.3|ios_xe|secret-host|postgres/);
  });
});
