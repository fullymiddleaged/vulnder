import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../src/index';
import { applyPatches } from '../src/ingest/apply';
import { bumpDataVersionStatement } from '../src/ingest/meta';
import type { VulnPatch } from '../src/ingest/types';
import { matchStack, pickLinks } from '../src/match/match';
import { OSV_QUERYBATCH_URL, type OsvClient } from '../src/match/osv';
import { badgeSvg } from '../src/routes/feeds';
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
      fields: { title: 'PostgreSQL privilege escalation', publishedAt: daysAgo(20), cvssScore: 8.8, refs: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1003' }] },
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
    expect(res.results.map((r) => [r.id, r.tier, r.confidence])).toEqual([
      ['CVE-2026-1005', 'exploited', 'product_match'],
      ['CVE-2026-1001', 'exploited', 'version_confirmed'],
      ['CVE-2026-1003', 'backlog', 'product_match'],
    ]);
    expect(res.watching).toEqual(['p:cisco/asa', 'pypi:fastapi']);
    expect(res.versionCheckUnavailable).toBe(false);
    expect(osv.calls).toBe(1);

    const next = res.results[1]!;
    expect(next.matched).toEqual(['npm:next@14.2.3']);
    expect(next.fixedVersions).toEqual(['14.2.5']);
    expect(next.links).toEqual({
      advisory: `https://github.com/advisories/${GHSA_NEXT_1}`,
      patch: 'https://github.com/vercel/next.js/commit/abcdef1234567',
    });
    expect(res.results[0]!.evidence).toMatchObject({ knownRansomware: true });
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
      changes: { vulnId: string; type: string }[];
      results: { id: string }[];
      links: Record<string, string>;
      watching: string[];
    };
    expect(body.stack).toBe('npm:next@14.2.3,p:cisco/asa,p:cisco/ios_xe,p:postgresql/postgresql@16,pypi:fastapi');
    expect(body.summary).toEqual({ exploited: 2, likely: 0, backlog: 1 });
    expect(body.results.map((r) => r.id)).toEqual(['CVE-2026-1005', 'CVE-2026-1001', 'CVE-2026-1003']);
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
