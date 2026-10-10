import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../src/index';
import { applyPatches } from '../src/ingest/apply';
import { bumpDataVersionStatement } from '../src/ingest/meta';
import type { VulnPatch } from '../src/ingest/types';
import type { ComponentCache, ComponentData } from '../src/match/components';
import { changesFor, matchStack, pickLinks, RECENT_EVENTS_SQL } from '../src/match/match';
import { OSV_QUERYBATCH_URL, type OsvClient } from '../src/match/osv';
import { describeHours } from '../src/lib/time';
import { badgeSvg, EDGE_CACHE_SECONDS, HEAVY_STACK_VULNS } from '../src/routes/feeds';
import { parseStack } from '../src/stack/format';
import { resetDb, store } from './helpers/db';

const NOW = new Date();
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();
const GHSA_NEXT_1 = 'GHSA-2222-3333-4444';
const GHSA_NEXT_2 = 'GHSA-5555-6666-7777';

/** The hand-written stack the phase is judged on. */
const STACK = 'npm:next@14.2.3,pypi:fastapi,p:postgresql/postgresql@16,p:cisco/ios_xe,p:cisco/asa';

function seedPatches(): VulnPatch[] {
  return [
    // Exploited, version confirmed by OSV.
    {
      source: 'ghsa',
      id: 'CVE-2026-1001',
      aliases: [GHSA_NEXT_1],
      fields: {
        title: 'Next.js middleware bypass',
        publishedAt: daysAgo(10),
        cvssScore: 9.1,
        refs: [
          { url: `https://github.com/advisories/${GHSA_NEXT_1}`, tags: ['advisory'] },
          { url: 'https://github.com/vercel/next.js/commit/abcdef1234567' },
        ],
      },
      affected: [{ kind: 'package', ecosystem: 'npm', packageName: 'next', ranges: [{ range: '< 14.2.5' }], fixedVersion: '14.2.5' }],
    },
    { source: 'kev', id: 'CVE-2026-1001', aliases: [], fields: { kevAddedAt: daysAgo(3), kevRansomware: false, kevDueDate: null } },
    // High EPSS but OSV says 14.2.3 is not affected: dropped.
    {
      source: 'ghsa',
      id: 'CVE-2026-1002',
      aliases: [GHSA_NEXT_2],
      fields: { title: 'Next.js image cache poisoning', publishedAt: daysAgo(5) },
      affected: [{ kind: 'package', ecosystem: 'npm', packageName: 'next', ranges: [{ range: '>= 15.0.0, < 15.0.1' }], fixedVersion: '15.0.1' }],
    },
    { source: 'epss', id: 'CVE-2026-1002', aliases: [], fields: { epss: 0.3, epssPercentile: 0.97, epssDate: daysAgo(1).slice(0, 10) } },
    // Product match, backlog.
    {
      source: 'cve',
      id: 'CVE-2026-1003',
      aliases: [],
      fields: {
        title: 'PostgreSQL privilege escalation',
        publishedAt: daysAgo(20),
        cvssScore: 8.8,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
        refs: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1003' }],
      },
      affected: [{ kind: 'product', vendor: 'postgresql', product: 'postgresql', ranges: [], fixedVersion: null }],
    },
    { source: 'epss', id: 'CVE-2026-1003', aliases: [], fields: { epss: 0.01, epssPercentile: 0.6, epssDate: daysAgo(1).slice(0, 10) } },
    // Outside a 30-day window, inside 90.
    {
      source: 'ghsa',
      id: 'CVE-2026-1004',
      aliases: [],
      fields: { title: 'FastAPI header injection', publishedAt: daysAgo(60) },
      affected: [{ kind: 'package', ecosystem: 'PyPI', packageName: 'fastapi', ranges: [], fixedVersion: '0.120.0' }],
    },
    // Exploited product, newer KEV addition than CVE-2026-1001.
    {
      source: 'kev',
      id: 'CVE-2026-1005',
      aliases: [],
      fields: { title: 'Cisco IOS XE web UI privilege escalation', kevAddedAt: daysAgo(1), kevRansomware: true, kevDueDate: daysAgo(-20) },
      affected: [{ kind: 'product', vendor: 'cisco', product: 'ios_xe', ranges: [], fixedVersion: null }],
    },
  ];
}

async function seed(): Promise<void> {
  await applyPatches(store(), seedPatches(), { now: NOW, windowStart: daysAgo(90), epssEvents: true });
  await store().batch([bumpDataVersionStatement(NOW)]);
}

/** OSV says next@14.2.3 is affected by CVE-2026-1001 (via its GHSA alias) and an unrelated old advisory. */
function fakeOsv(): OsvClient & { calls: number } {
  const client = {
    calls: 0,
    async affecting(queries: { ecosystem: string; name: string; version: string }[]) {
      client.calls++;
      return new Map(
        queries.map((q) => [`${q.ecosystem}\u0000${q.name}\u0000${q.version}`, new Set(q.name === 'next' && q.version === '14.2.3' ? [GHSA_NEXT_1, 'GHSA-old0-old0-old0'] : [])]),
      );
    },
  };
  return client;
}

function stubOsvFetch() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const req = new Request(input, init);
    if (req.url !== OSV_QUERYBATCH_URL) throw new Error(`unexpected fetch ${req.url}`);
    const body = (await req.json()) as { queries: { package: { name: string }; version: string }[] };
    return Response.json({
      results: body.queries.map((q) => (q.package.name === 'next' && q.version === '14.2.3' ? { vulns: [{ id: GHSA_NEXT_1, modified: 'x' }] } : {})),
    });
  });
}

// The Cache API outlives each test and cannot be cleared in workerd, so every
// test starts from its own data version (as in production, it only goes up).
let versionBase = Date.now() * 100;

beforeEach(async () => {
  await resetDb();
  await seed();
  versionBase += 100;
  await env.DB.prepare("UPDATE meta SET value = ? WHERE key = 'data_version'").bind(String(versionBase)).run();
});
afterEach(() => vi.restoreAllMocks());

describe('matchStack', () => {
  it('returns the tiered results for the hand-written stack', async () => {
    const osv = fakeOsv();
    const res = await matchStack(store(), parseStack(STACK), { now: NOW, days: 30, osv });
    // Both exploited CVEs are "act"; within it, CVSS 9.1 outscores ransomware with no CVSS (impact 0.5).
    expect(res.results.map((r) => [r.id, r.tier, r.confidence, r.priority, r.score])).toEqual([
      ['CVE-2026-1001', 'exploited', 'version_confirmed', 'act', 91],
      ['CVE-2026-1005', 'exploited', 'product_match', 'act', 60],
      ['CVE-2026-1003', 'backlog', 'product_match', 'watch', 0.9],
    ]);
    expect(res.results[1]!.reasons).toEqual(['On CISA KEV', 'Used in ransomware']);
    expect(res.fixFirst.map((f) => [f.item, f.score, f.counts, f.fixable])).toEqual([
      ['npm:next@14.2.3', 91, { act: 1, attend: 0, watch: 0, track: 0 }, 1],
      ['p:cisco/ios_xe', 60, { act: 1, attend: 0, watch: 0, track: 0 }, 0],
      ['p:postgresql/postgresql@16', 0.9, { act: 0, attend: 0, watch: 1, track: 0 }, 0],
    ]);
    expect(res.watching).toEqual(['p:cisco/asa', 'pypi:fastapi']);
    expect(res.versionCheckUnavailable).toBe(false);
    expect(osv.calls).toBe(1);

    const next = res.results[0]!;
    expect(next.matched).toEqual(['npm:next@14.2.3']);
    expect(next.fixedVersions).toEqual(['14.2.5']);
    expect(next.links).toEqual({
      advisory: `https://github.com/advisories/${GHSA_NEXT_1}`,
      patch: 'https://github.com/vercel/next.js/commit/abcdef1234567',
    });
    expect(res.results[1]!.evidence).toMatchObject({ knownRansomware: true });
  });

  it('labels close matches and ranks them after exact ones in the same tier', async () => {
    const res = await matchStack(store(), parseStack('?p:cisco/ios_xe,npm:next'), { now: NOW, days: 30, osv: fakeOsv() });
    expect(res.results.map((r) => [r.id, r.tier, r.match])).toEqual([
      ['CVE-2026-1001', 'exploited', 'exact'],
      ['CVE-2026-1005', 'exploited', 'close'],
      ['CVE-2026-1002', 'likely', 'exact'],
    ]);
    expect(res.results[1]!.matched).toEqual(['?p:cisco/ios_xe']);
  });

  it('ranks an edge device ahead of the same bug elsewhere, in the same priority, and says why', async () => {
    // The same severity, vector and EPSS as the PostgreSQL CVE, on FortiOS.
    await applyPatches(
      store(),
      [
        {
          source: 'cve',
          id: 'CVE-2026-1009',
          aliases: [],
          fields: { title: 'FortiOS SSL VPN heap overflow', publishedAt: daysAgo(20), cvssScore: 8.8, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N' },
          affected: [{ kind: 'product', vendor: 'fortinet', product: 'fortios', ranges: [], fixedVersion: null }],
        },
        { source: 'epss', id: 'CVE-2026-1009', aliases: [], fields: { epss: 0.01, epssPercentile: 0.6, epssDate: daysAgo(1).slice(0, 10) } },
      ],
      { now: NOW, windowStart: daysAgo(90), epssEvents: true },
    );
    const res = await matchStack(store(), parseStack('p:fortinet/fortios,p:postgresql/postgresql@16'), { now: NOW, days: 30, osv: fakeOsv() });
    const edge = (r: { reasons: string[] }) => r.reasons.some((t) => t.startsWith('Edge device'));
    expect(res.results.map((r) => [r.id, r.priority, edge(r)])).toEqual([
      ['CVE-2026-1009', 'watch', true],
      ['CVE-2026-1003', 'watch', false],
    ]);
    expect(res.results[0]!.score).toBeGreaterThan(res.results[1]!.score);
    expect(res.fixFirst.map((f) => f.item)).toEqual(['p:fortinet/fortios', 'p:postgresql/postgresql@16']);

    // The user's tags win both ways: an internal FortiGate, an internet-facing database.
    const tagged = await matchStack(store(), parseStack('p:fortinet/fortios;internal,p:postgresql/postgresql@16;edge'), { now: NOW, days: 30, osv: fakeOsv() });
    expect(tagged.results.map((r) => [r.id, r.priority, edge(r)])).toEqual([
      ['CVE-2026-1003', 'watch', true],
      ['CVE-2026-1009', 'watch', false],
    ]);
    expect(tagged.fixFirst.map((f) => f.item)).toEqual(['p:postgresql/postgresql@16;edge', 'p:fortinet/fortios;internal']);
  });

  it('carries an item’s team through to its matches without changing the ranking', async () => {
    const plain = await matchStack(store(), parseStack('p:postgresql/postgresql@16'), { now: NOW, days: 30, osv: fakeOsv() });
    const teamed = await matchStack(store(), parseStack('p:postgresql/postgresql@16;database'), { now: NOW, days: 30, osv: fakeOsv() });
    expect(plain.results.map((r) => [r.id, r.score])).toEqual([['CVE-2026-1003', 0.9]]);
    expect(teamed.results.map((r) => [r.id, r.score, r.matched])).toEqual([['CVE-2026-1003', 0.9, ['p:postgresql/postgresql@16;database']]]);
    expect(teamed.fixFirst.map((f) => f.item)).toEqual(['p:postgresql/postgresql@16;database']);
  });

  it('widens the window with days', async () => {
    const res = await matchStack(store(), parseStack(STACK), { now: NOW, days: 90, osv: fakeOsv() });
    expect(res.results.map((r) => r.id)).toContain('CVE-2026-1004');
    expect(res.watching).toEqual(['p:cisco/asa']);
  });

  it('shows every package match as a product match when no version is given', async () => {
    const osv = fakeOsv();
    const res = await matchStack(store(), parseStack('npm:next'), { now: NOW, days: 30, osv });
    expect(res.results.map((r) => [r.id, r.tier, r.confidence])).toEqual([
      ['CVE-2026-1001', 'exploited', 'product_match'],
      ['CVE-2026-1002', 'likely', 'product_match'],
    ]);
    expect(osv.calls).toBe(0);
  });

  it('falls back to product matches when OSV is unreachable', async () => {
    const res = await matchStack(store(), parseStack('npm:next@14.2.3'), {
      now: NOW,
      days: 30,
      osv: { affecting: () => Promise.reject(new Error('down')) },
    });
    expect(res.versionCheckUnavailable).toBe(true);
    expect(res.results.map((r) => [r.id, r.confidence])).toEqual([
      ['CVE-2026-1001', 'product_match'],
      ['CVE-2026-1002', 'product_match'],
    ]);
  });

  it('avoids bare NVD links', () => {
    expect(pickLinks('CVE-2026-1003', [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1003' }])).toEqual({
      advisory: 'https://www.cve.org/CVERecord?id=CVE-2026-1003',
      patch: null,
    });
  });
});

describe('GET /api/feed', () => {
  it('serves the tiered list, the week’s changes and links', async () => {
    stubOsvFetch();
    const res = await app.request(`/api/feed?s=${encodeURIComponent(STACK)}`, {}, env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      stack: string;
      summary: Record<string, number>;
      priorities: Record<string, number>;
      fixFirst: { item: string }[];
      changes: { vulnId: string; type: string }[];
      results: { id: string }[];
      links: Record<string, string>;
      watching: string[];
    };
    expect(body.stack).toBe('npm:next@14.2.3,p:cisco/asa,p:cisco/ios_xe,p:postgresql/postgresql@16,pypi:fastapi');
    expect(body.summary).toEqual({ exploited: 2, likely: 0, backlog: 1 });
    expect(body.results.map((r) => r.id)).toEqual(['CVE-2026-1001', 'CVE-2026-1005', 'CVE-2026-1003']);
    expect(body.priorities).toEqual({ act: 2, attend: 0, watch: 1, track: 0 });
    expect(body.fixFirst.map((f) => f.item)).toEqual(['npm:next@14.2.3', 'p:cisco/ios_xe', 'p:postgresql/postgresql@16']);
    // Only events from the last 7 days: both KEV additions, nothing older.
    expect(body.changes.map((c) => [c.vulnId, c.type])).toEqual([
      ['CVE-2026-1005', 'kev_added'],
      ['CVE-2026-1001', 'kev_added'],
    ]);
    expect(body.links.atom).toBe(`${env.BASE_URL}/feed.xml?s=${encodeURIComponent(body.stack)}`);
    expect(body.watching).toEqual(['p:cisco/asa', 'pypi:fastapi']);
  });

  it('rejects bad input with a helpful 400', async () => {
    for (const [query, message] of [
      ['', /missing the s parameter/],
      ['?s=bogus:x', /unrecognised/],
      ['?s=npm:next&days=0', /days must be/],
      ['?s=npm:next&days=91', /days must be/],
      ['?s=npm:next&days=7.5', /days must be/],
    ] as const) {
      const res = await app.request(`/api/feed${query}`, {}, env);
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toMatch(message);
    }
  });

  it('caches by canonical stack and invalidates when the data version changes', async () => {
    const fetchSpy = stubOsvFetch();
    const url = `/api/feed?s=${encodeURIComponent('npm:next@14.2.3')}`;
    const equivalent = `/api/feed?s=${encodeURIComponent(' npm:NEXT@14.2.3,npm:next@14.2.3')}`;
    const first = (await (await app.request(url, {}, env)).json()) as { generatedAt: string; dataVersion: number };
    const second = (await (await app.request(equivalent, {}, env)).json()) as { generatedAt: string };
    expect(second.generatedAt).toBe(first.generatedAt);
    const calls = fetchSpy.mock.calls.length;

    await store().batch([bumpDataVersionStatement(new Date())]);
    const third = (await (await app.request(url, {}, env)).json()) as { dataVersion: number };
    expect(third.dataVersion).toBe(first.dataVersion + 1);
    // OSV results are cached separately, so a data change does not refetch them.
    expect(fetchSpy.mock.calls.length).toBe(calls);
  });
});

describe('feed rate limit', () => {
  it('limits cache misses per IP and never cached responses', async () => {
    stubOsvFetch();
    const limit = vi.fn(async () => ({ success: true }));
    const e = { ...env, FEED_LIMITER: { limit } as unknown as RateLimit };
    const url = `/api/feed?s=${encodeURIComponent('pypi:fastapi')}`;
    const headers = { 'cf-connecting-ip': '203.0.113.9' };
    expect((await app.request(url, { headers }, e)).status).toBe(200);
    expect(limit.mock.calls).toEqual([[{ key: '203.0.113.9' }]]);

    // A cached response is served without asking the limiter, even when it would refuse.
    limit.mockResolvedValue({ success: false });
    expect((await app.request(url, { headers }, e)).status).toBe(200);
    expect(limit).toHaveBeenCalledTimes(1);

    const miss = await app.request(`/badge.svg?s=${encodeURIComponent('pypi:fastapi,npm:next')}`, { headers }, e);
    expect(miss.status).toBe(429);
    expect(miss.headers.get('Retry-After')).toBe('60');
  });
});

describe('feed cost controls', () => {
  const headers = { 'cf-connecting-ip': '203.0.113.9' };
  const limiters = () => {
    const feed = vi.fn(async () => ({ success: true }));
    const heavy = vi.fn(async () => ({ success: false }));
    return { feed, heavy, env: { ...env, FEED_LIMITER: { limit: feed } as unknown as RateLimit, FEED_HEAVY_LIMITER: { limit: heavy } as unknown as RateLimit } };
  };

  it('keeps a feed at the edge for an hour but tells browsers five minutes', async () => {
    stubOsvFetch();
    const url = `/api/feed?s=${encodeURIComponent('p:postgresql/postgresql')}`;
    const miss = await app.request(url, {}, env);
    expect(miss.headers.get('Cache-Control')).toBe('public, max-age=300');
    const stored = await (await caches.open('vulnder-feeds')).match(
      `${env.BASE_URL}/__cache/feed?s=${encodeURIComponent('p:postgresql/postgresql')}&days=30&v=${versionBase}`,
    );
    expect(stored?.headers.get('Cache-Control')).toBe(`public, max-age=${EDGE_CACHE_SECONDS}`);
    const hit = await app.request(url, {}, env);
    expect(hit.headers.get('Cache-Control')).toBe('public, max-age=300');
  });

  it('puts misses for stacks with many vulns behind the heavy limiter, and only those', async () => {
    stubOsvFetch();
    await env.DB.prepare(
      "INSERT INTO catalog (kind, key, vendor, product, normalized, count) VALUES ('product', 'linux/linux', 'linux', 'linux', 'linux', ?)",
    ).bind(HEAVY_STACK_VULNS).run();
    const l = limiters();
    expect((await app.request(`/api/feed?s=${encodeURIComponent('p:postgresql/postgresql')}`, { headers }, l.env)).status).toBe(200);
    expect(l.heavy).not.toHaveBeenCalled();

    const res = await app.request(`/api/feed?s=${encodeURIComponent('p:linux/linux,p:postgresql/postgresql')}`, { headers }, l.env);
    expect(res.status).toBe(429);
    expect(l.heavy.mock.calls).toEqual([[{ key: '203.0.113.9' }]]);
  });

  it('reads each component from D1 once, then serves any stack and window from the cache', async () => {
    const kept = new Map<string, ComponentData>();
    const components: ComponentCache = { get: async (k) => kept.get(k) ?? null, put: (k, d) => void kept.set(k, d) };
    const first = await matchStack(store(), parseStack(STACK), { now: NOW, days: 30, osv: fakeOsv(), components });
    expect([...kept.keys()].sort()).toEqual(['pkg:PyPI:fastapi', 'pkg:npm:next', 'prod:cisco/asa', 'prod:cisco/ios_xe', 'prod:postgresql/postgresql']);

    // No component reads now: a different window and a reordered, smaller stack both come from the cache.
    const noReads = store();
    noReads.all = (() => Promise.reject(new Error('read D1'))) as typeof noReads.all;
    const again = await matchStack(noReads, parseStack(STACK), { now: NOW, days: 30, osv: fakeOsv(), components });
    expect(again.results.map((r) => r.id)).toEqual(first.results.map((r) => r.id));
    const wider = await matchStack(noReads, parseStack('pypi:fastapi,p:cisco/ios_xe'), { now: NOW, days: 90, osv: fakeOsv(), components });
    // CVE-2026-1004 is 60 days old: outside 30 days, inside 90.
    expect(wider.results.map((r) => r.id).sort()).toEqual(['CVE-2026-1004', 'CVE-2026-1005']);
  });

  it('finds events by time once a stack has more results than recent events, with the same answer', async () => {
    const ids = ['CVE-2026-1001', 'CVE-2026-1003', 'CVE-2026-1005', ...Array.from({ length: 300 }, (_, i) => `CVE-2099-${10000 + i}`)];
    const since = daysAgo(30);
    const sql: string[] = [];
    const spy = store();
    const all = spy.all.bind(spy);
    spy.all = ((s: string, p?: unknown[]) => {
      sql.push(s);
      return all(s, p);
    }) as typeof spy.all;
    // 303 lookups would read about 1,200 rows; a day of events is about 500.
    const byTime = await changesFor(spy, ids, since, 1);
    expect(sql).toEqual([RECENT_EVENTS_SQL]);
    sql.length = 0;
    const perVuln = await changesFor(spy, ids, since, 30);
    expect(sql).toHaveLength(1);
    expect(sql[0]).not.toBe(RECENT_EVENTS_SQL);
    expect(byTime).toEqual(perVuln);
    expect(byTime.map((e) => e.vulnId)).toContain('CVE-2026-1005');
  });

  it('reads a large stack in a few queries', async () => {
    const n = 4500;
    await env.DB.batch([
      env.DB.prepare(
        `WITH RECURSIVE i(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM i WHERE x < ?)
         INSERT INTO vulns (id, published_at, updated_at) SELECT printf('CVE-2026-%05d', 50000 + x), ?, ? FROM i`,
      ).bind(n, daysAgo(2), NOW.toISOString()),
      env.DB.prepare(
        `INSERT INTO affected (vuln_id, source, kind, vendor, product) SELECT id, 'cve', 'product', 'linux', 'linux' FROM vulns WHERE id >= 'CVE-2026-50001'`,
      ),
    ]);
    const counting = store();
    const all = counting.all.bind(counting);
    let queries = 0;
    counting.all = ((sql: string, params?: unknown[]) => {
      queries++;
      return all(sql, params);
    }) as typeof counting.all;
    const res = await matchStack(counting, parseStack('p:linux/linux'), { now: NOW, days: 30, osv: fakeOsv() });
    expect(res.results).toHaveLength(n);
    // Affected rows, the vulns in chunks of 2,000 (at 400 a chunk this was 13), then the
    // product's unsupported-when-assigned tag. Linux maps to no endoflife.date product, so no dates.
    expect(queries).toBe(5);
  });
});

describe('vendor support', () => {
  async function seedSupport() {
    const day = (n: number) => daysAgo(n).slice(0, 10);
    await env.DB.batch(
      [
        ['windows', '7_sp1', '7 SP1', '2020-01-14', 1, null],
        ['windows', '11_24h2_e', '11 24H2 (E)', day(-400), 0, null],
        ['windows-server', '2012_r2', '2012 R2', '2023-10-10', 1, day(-30)],
        ['windows-server', '2022', '2022', day(-1800), 0, null],
      ].map(([slug, release, label, eol, isEol, eoes]) =>
        env.DB.prepare('INSERT INTO eol_releases (slug, release, label, eol_from, is_eol, eoes_from, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(
          slug,
          release,
          label,
          eol,
          isEol,
          eoes,
          NOW.toISOString(),
        ),
      ),
    );
    await applyPatches(
      store(),
      [
        {
          source: 'cve',
          id: 'CVE-2026-1101',
          aliases: [],
          fields: { title: 'Windows Server 2012 R2 info leak', publishedAt: daysAgo(4), cvssScore: 3.1 },
          affected: [{ kind: 'product', vendor: 'microsoft', product: 'windows_server_2012_r2', ranges: [], fixedVersion: null }],
        },
      ],
      { now: NOW, windowStart: daysAgo(90), epssEvents: true },
    );
  }

  it('flags named releases past their end, ranks them with Act in Fix first, and leaves CVE bands alone', async () => {
    await seedSupport();
    const res = await matchStack(store(), parseStack('p:microsoft/windows@7,p:microsoft/windows_server_2012_r2,p:microsoft/windows_server_2022,p:postgresql/postgresql@16'), {
      now: NOW,
      days: 30,
      osv: fakeOsv(),
    });
    expect(res.support.map((s) => [s.state, s.name, s.items])).toEqual([
      ['eol', 'Windows 7', ['p:microsoft/windows@7']],
      ['eol', 'Windows Server 2012 R2', ['p:microsoft/windows_server_2012_r2']],
    ]);
    expect(res.support[1]).toMatchObject({ date: '2023-10-10', esuUntil: daysAgo(-30).slice(0, 10) });
    // Its only CVE is low severity: Track, but the item ranks with Act, ahead of PostgreSQL's Watch.
    expect(res.results.find((r) => r.id === 'CVE-2026-1101')?.priority).toBe('track');
    expect(res.fixFirst.map((f) => [f.item, f.support ?? null])).toEqual([
      ['p:microsoft/windows_server_2012_r2', 'eol'],
      ['p:postgresql/postgresql@16', null],
    ]);
  });

  it('counts ESU the stack says it has, and finds nothing in a broad name', async () => {
    await seedSupport();
    const res = await matchStack(store(), parseStack('p:microsoft/windows_server_2012_r2;esu,p:microsoft/windows'), { now: NOW, days: 30, osv: fakeOsv() });
    expect(res.support.map((s) => [s.state, s.esu, s.items])).toEqual([['ending', true, ['p:microsoft/windows_server_2012_r2;esu']]]);
  });

  it('serves the findings in the JSON feed and as Atom entries', async () => {
    await seedSupport();
    stubOsvFetch();
    const s = encodeURIComponent('p:microsoft/windows@7');
    const body = (await (await app.request(`/api/feed?s=${s}`, {}, env)).json()) as { support: { name: string; state: string }[] };
    expect(body.support).toMatchObject([{ name: 'Windows 7', state: 'eol' }]);
    const xml = await (await app.request(`/feed.xml?s=${s}`, {}, env)).text();
    expect(xml).toContain('<title>Out of support: Windows 7</title>');
    expect(xml).toContain('<updated>2020-01-14T00:00:00.000Z</updated>');
    expect(xml).toContain('Windows 7 is out of support since 2020-01-14: it gets no more security updates.');
  });
});

describe('GET /feed.xml', () => {
  it('has one entry per event, with IDs built from the base URL', async () => {
    stubOsvFetch();
    const res = await app.request(`/feed.xml?s=${encodeURIComponent(STACK)}`, {}, env);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('application/atom+xml');
    const xml = await res.text();
    const entries = xml.match(/<entry>/g) ?? [];
    // 1005: kev_added; 1001: published + kev_added; 1003: published (KEV stub 1005 has no publication date).
    expect(entries).toHaveLength(4);
    expect(xml).toContain(`<id>${env.BASE_URL}/events/CVE-2026-1001/kev_added/`);
    expect(xml).toContain('Known exploited (added to CISA KEV): CVE-2026-1005: Cisco IOS XE web UI privilege escalation');
    expect(xml).not.toMatch(/weaponi[sz]ed/i);
    // Each entry says what to do and by when, and what to do meanwhile when no fix is known.
    expect(xml).toContain('Priority: Act now, respond within 24 hours. Why: On CISA KEV');
    expect(xml).toContain('No fixed version known yet: mitigate meanwhile.');
  });

  it('describes response windows in hours, then days', () => {
    expect([24, 48, 168, 720].map(describeHours)).toEqual(['24 hours', '48 hours', '7 days', '30 days']);
  });

  it('describes EPSS as a prediction, never as exploitation', async () => {
    stubOsvFetch();
    await applyPatches(store(), [{ source: 'epss', id: 'CVE-2026-1003', aliases: [], fields: { epss: 0.42, epssPercentile: 0.99, epssDate: NOW.toISOString().slice(0, 10) } }], {
      now: NOW,
      windowStart: daysAgo(90),
      epssEvents: true,
    });
    await store().batch([bumpDataVersionStatement(NOW)]);
    const xml = await (await app.request(`/feed.xml?s=${encodeURIComponent('p:postgresql/postgresql')}`, {}, env)).text();
    expect(xml).toContain('EPSS rose to 42.0%: CVE-2026-1003');
    expect(xml).toContain('predicted probability of exploitation in the next 30 days, not evidence of exploitation');
    expect(xml).not.toMatch(/Known exploited/);
  });

  it('escapes XML in titles', async () => {
    stubOsvFetch();
    await applyPatches(store(), [{ source: 'cve', id: 'CVE-2026-1003', aliases: [], fields: { title: '<script>&"x"' } }], { now: NOW, windowStart: daysAgo(90), epssEvents: true });
    await store().batch([bumpDataVersionStatement(NOW)]);
    const xml = await (await app.request(`/feed.xml?s=${encodeURIComponent('p:postgresql/postgresql')}`, {}, env)).text();
    expect(xml).toContain('&lt;script&gt;&amp;&quot;x&quot;');
    expect(xml).not.toContain('<script>');
  });
});

describe('GET /badge.svg', () => {
  it('counts known-exploited matches', async () => {
    stubOsvFetch();
    const res = await app.request(`/badge.svg?s=${encodeURIComponent(STACK)}`, {}, env);
    expect(res.headers.get('content-type')).toContain('image/svg+xml');
    const svg = await res.text();
    expect(svg).toContain('aria-label="2 known-exploited CVEs"');
    expect(svg).toContain('#c62828');
  });

  it('is green at zero', async () => {
    stubOsvFetch();
    const svg = await (await app.request(`/badge.svg?s=${encodeURIComponent('p:cisco/asa')}`, {}, env)).text();
    expect(svg).toContain('aria-label="0 known-exploited CVEs"');
    expect(svg).toContain('#2e7d32');
  });

  it('uses the singular for one', () => {
    expect(badgeSvg(1)).toContain('1 known-exploited CVE"');
  });
});

describe('response headers', () => {
  it('sets no-referrer and nosniff, including on cached responses', async () => {
    stubOsvFetch();
    const url = `/badge.svg?s=${encodeURIComponent('p:cisco/asa')}`;
    for (let i = 0; i < 2; i++) {
      const res = await app.request(url, {}, env);
      expect(res.headers.get('referrer-policy')).toBe('no-referrer');
      expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    }
  });
});
