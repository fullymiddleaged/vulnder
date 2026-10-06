import { createExecutionContext, createScheduledController, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import worker, { app } from '../src/index';
import { Budget } from '../src/ingest/budget';
import { D1BindingStore } from '../src/ingest/d1-store';
import { runIngest } from '../src/ingest/run';
import { RAW_BASE, RELEASES_URL } from '../src/ingest/sources/cve';
import { EPSS_URL } from '../src/ingest/sources/epss';
import { ADVISORIES_URL } from '../src/ingest/sources/ghsa';
import { KEV_URL } from '../src/ingest/sources/kev';
import { sourceHealth } from '../src/routes/health';
import { FakeFetch, jsonResponse } from './helpers/fake-fetch';
import { cveRecords, deltaZip, epssLatest, ghsaPage, kevFeed, releases, withMeta } from './helpers/fixtures';
import { resetDb, rows, unlimitedBudget } from './helpers/db';

const NOW = new Date('2026-10-04T18:00:00Z');

/** Every upstream, served from fixtures. */
function upstreams(): FakeFetch {
  const todayZip = deltaZip([
    withMeta(cveRecords['CVE-2026-104910']!, { dateUpdated: '2026-10-04T10:00:00.000Z' }),
    withMeta(cveRecords['CVE-2026-100107']!, { dateUpdated: '2026-10-04T11:00:00.000Z' }),
    withMeta(cveRecords['CVE-2026-104886']!, { dateUpdated: '2026-10-04T12:00:00.000Z' }),
  ]);
  return new FakeFetch()
    .on(RELEASES_URL, () => jsonResponse(releases))
    .on(/\/releases\/download\/.*2026-10-04_delta_CVEs_at_1700Z\.zip$/, () => new Response(todayZip))
    .on(ADVISORIES_URL, () => jsonResponse(ghsaPage.advisories))
    .on(KEV_URL, (req) =>
      req.headers.get('if-none-match') === kevFeed.headers.etag
        ? new Response(null, { status: 304 })
        : jsonResponse(kevFeed.body, { headers: kevFeed.headers as Record<string, string> }),
    )
    .on(RAW_BASE, (req) => {
      const id = req.url.split('/').pop()!.replace('.json', '');
      const record = cveRecords[id];
      return record ? jsonResponse(record) : new Response('not found', { status: 404 });
    })
    .on(EPSS_URL, (req) => {
      const u = new URL(req.url);
      if (!u.searchParams.has('cve')) return jsonResponse(epssLatest);
      const date = u.searchParams.get('date')!;
      const data = u.searchParams
        .get('cve')!
        .split(',')
        // KEV entries score high, everything else low.
        .map((cve) => ({ cve, epss: cve.startsWith('CVE-2026-102') ? '0.450000000' : '0.002000000', percentile: '0.500000000', date }));
      return jsonResponse({ status: 'OK', data });
    });
}

async function ingest(f: FakeFetch, budget = unlimitedBudget()) {
  return runIngest({
    store: new D1BindingStore(env.DB, budget),
    fetch: f.fetch,
    budget,
    runtime: 'worker',
    now: () => NOW,
  });
}

async function snapshot() {
  return {
    vulns: await rows('SELECT id, title, published_at, cvss_score, epss, kev_added_at, source_flags FROM vulns ORDER BY id'),
    affected: await rows('SELECT vuln_id, source, kind, ecosystem, package_name, vendor, product, fixed_version FROM affected ORDER BY vuln_id, source, kind, package_name, product'),
    events: await rows('SELECT vuln_id, type, occurred_at, dedupe_key FROM events ORDER BY vuln_id, type'),
  };
}

beforeEach(resetDb);

describe('runIngest', () => {
  it('ingests every source end to end', async () => {
    const report = await ingest(upstreams());
    expect(report.sources.map((s) => [s.source, s.status])).toEqual([
      ['cve', 'ok'],
      ['ghsa', 'ok'],
      ['kev', 'ok'],
      ['epss', 'ok'],
    ]);
    expect(report.maintenance).toBe(true);

    const ids = (await rows<{ id: string }>('SELECT id FROM vulns')).map((r) => r.id);
    // From today's zip; the rejected record is not stored.
    expect(ids).toEqual(expect.arrayContaining(['CVE-2026-104910', 'CVE-2026-100107']));
    expect(ids).not.toContain('CVE-2026-104886');
    // KEV additions inside the window, including ones never seen in a CVE zip.
    expect(ids).toEqual(expect.arrayContaining(['CVE-2026-102490', 'CVE-2026-102489', 'CVE-2026-104286', 'CVE-2026-59310']));
    expect(ids).not.toContain('CVE-2020-29583');
    // GHSA-only advisory published in the window.
    expect(ids).toEqual(expect.arrayContaining(['GHSA-456v-xq2p-r4cj']));

    const types = await rows<{ type: string; n: number }>('SELECT type, COUNT(*) AS n FROM events GROUP BY type ORDER BY type');
    expect(types.map((t) => t.type)).toEqual(['epss_crossed', 'kev_added', 'published']);
    expect(await rows("SELECT vuln_id FROM events WHERE type = 'epss_crossed' ORDER BY vuln_id")).toEqual([
      { vuln_id: 'CVE-2026-102489' },
      { vuln_id: 'CVE-2026-102490' },
    ]);

    expect(await rows("SELECT value FROM meta WHERE key = 'data_version'")).toEqual([{ value: '1' }]);
    const status = await rows<{ key: string; value: string }>("SELECT key, value FROM meta WHERE key LIKE 'status:%' ORDER BY key");
    expect(status).toHaveLength(4);
    for (const s of status) expect(JSON.parse(s.value)).toMatchObject({ lastSuccessAt: NOW.toISOString(), lastError: null, partial: false });
  });

  it('writes nothing on a second run with unchanged upstreams', async () => {
    await ingest(upstreams());
    const before = await snapshot();
    const report = await ingest(upstreams());
    expect(report.sources.map((s) => s.written + s.events + s.deleted)).toEqual([0, 0, 0, 0]);
    expect(report.maintenance).toBe(false);
    expect(await snapshot()).toEqual(before);
    expect(await rows("SELECT value FROM meta WHERE key = 'data_version'")).toEqual([{ value: '1' }]);
  });

  it('waits while a seed is in progress, then runs normally', async () => {
    await env.DB.prepare("INSERT INTO meta (key, value, updated_at) VALUES ('seeding', '{\"startedAt\":\"2026-10-04T17:00:00Z\"}', '2026-10-04')").run();
    const f = upstreams();
    const report = await ingest(f);
    expect(report).toEqual({ sources: [], maintenance: false, subrequests: 0, waitingForSeed: true });
    expect(f.calls).toHaveLength(0);
    expect(await rows("SELECT key FROM meta WHERE key != 'seeding'")).toEqual([]);

    await env.DB.prepare("DELETE FROM meta WHERE key = 'seeding'").run();
    expect((await ingest(f)).sources.map((s) => s.status)).toEqual(['ok', 'ok', 'ok', 'ok']);
  });

  it('resumes across budget-limited runs and ends with the same data', async () => {
    // A full first run costs ~66 subrequests and a caught-up run ~25 (fetches plus D1 queries).
    await ingest(upstreams());
    const expected = await snapshot();
    await resetDb();

    let runs = 0;
    let partialSeen = false;
    for (; runs < 40; runs++) {
      const tight = new Budget({ maxSubrequests: 30, deadline: Number.MAX_SAFE_INTEGER });
      const report = await ingest(upstreams(), tight);
      if (report.sources.some((s) => s.status === 'partial')) partialSeen = true;
      expect(report.sources.every((s) => s.status !== 'error')).toBe(true);
      const statuses = await rows<{ value: string }>("SELECT value FROM meta WHERE key LIKE 'status:%'");
      if (statuses.length === 4 && statuses.every((s) => JSON.parse(s.value).partial === false && JSON.parse(s.value).lastSuccessAt)) break;
    }
    expect(partialSeen).toBe(true);
    expect(runs).toBeLessThan(40);
    expect(await snapshot()).toEqual(expected);
  });

  it('does not let a source that is far behind starve the others', async () => {
    const template = cveRecords['CVE-2026-104910']!;
    const many = Array.from({ length: 600 }, (_, i) =>
      withMeta(template, {
        cveId: `CVE-2026-${300000 + i}`,
        dateUpdated: new Date(Date.parse('2026-10-04T01:00:00Z') + i * 1000).toISOString(),
      }),
    );
    const backlog = new FakeFetch()
      .on(/\/releases\/download\/.*2026-10-04_delta_CVEs_at_1700Z\.zip$/, () => new Response(deltaZip(many)))
      .on(() => true, (req) => upstreams().fetch(req));
    const budget = new Budget({ maxSubrequests: 60, deadline: Number.MAX_SAFE_INTEGER });
    const report = await ingest(backlog, budget);
    const cve = report.sources.find((s) => s.source === 'cve')!;
    expect(cve.status).toBe('partial');
    expect(cve.pages).toBeLessThan(3);
    expect(report.sources.find((s) => s.source === 'ghsa')!.pages).toBeGreaterThan(0);
    expect(report.sources.find((s) => s.source === 'kev')!.pages).toBeGreaterThan(0);
  });

  it('records a source error and carries on with the others', async () => {
    const f = upstreams().on(ADVISORIES_URL, () => jsonResponse({}, { status: 500 }));
    // The first matching route wins, so put the failure first.
    const failing = new FakeFetch().on(ADVISORIES_URL, () => jsonResponse({}, { status: 500 })).on(() => true, (req) => f.fetch(req));
    const report = await ingest(failing);
    expect(report.sources.find((s) => s.source === 'ghsa')).toMatchObject({ status: 'error', error: 'GitHub advisories: HTTP 500' });
    expect(report.sources.filter((s) => s.status === 'ok').map((s) => s.source)).toEqual(['cve', 'kev', 'epss']);
    const [ghsa] = await rows<{ value: string }>("SELECT value FROM meta WHERE key = 'status:ghsa'");
    expect(JSON.parse(ghsa!.value)).toMatchObject({ lastSuccessAt: null, lastError: 'GitHub advisories: HTTP 500' });
  });
});

describe('health', () => {
  it('judges freshness from the last successful run', () => {
    const now = new Date('2026-10-04T12:00:00Z');
    const base = { lastRunAt: null, partial: false, lastError: null, lastErrorAt: null, lastRecords: 0 };
    expect(sourceHealth({ ...base, lastSuccessAt: null }, 6, now)).toBe('never');
    expect(sourceHealth({ ...base, lastSuccessAt: null, lastError: 'x' }, 6, now)).toBe('error');
    expect(sourceHealth({ ...base, lastSuccessAt: '2026-10-04T06:00:00.000Z' }, 6, now)).toBe('ok');
    expect(sourceHealth({ ...base, lastSuccessAt: '2026-10-04T05:59:59.999Z' }, 6, now)).toBe('stale');
    expect(
      sourceHealth({ ...base, lastSuccessAt: '2026-10-04T11:00:00.000Z', lastError: 'boom', lastErrorAt: '2026-10-04T11:30:00.000Z' }, 6, now),
    ).toBe('error');
  });

  it('serves freshness and counts', async () => {
    await ingest(upstreams());
    const res = await app.request('/api/health', {}, env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      status: string;
      sources: Record<string, { health: string; lastSuccessAt: string }>;
      counts: Record<string, number>;
      dataVersion: number;
    };
    // NOW is in the past relative to the real clock, so these read as stale.
    expect(Object.keys(body.sources)).toEqual(['cve', 'ghsa', 'kev', 'epss']);
    expect(body.sources.cve!.lastSuccessAt).toBe(NOW.toISOString());
    expect(body.counts.vulns).toBeGreaterThan(5);
    expect(body.dataVersion).toBe(1);
  });

  it('reports "never" on an empty database', async () => {
    const res = await app.request('/api/health', {}, env);
    const body = (await res.json()) as { status: string; sources: Record<string, { health: string }> };
    expect(body.status).toBe('degraded');
    expect(Object.values(body.sources).map((s) => s.health)).toEqual(['never', 'never', 'never', 'never']);
  });

  it('returns JSON 404s under /api', async () => {
    const res = await app.request('/api/nope', {}, env);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'not found' });
  });
});

describe('scheduled handler', () => {
  it('does nothing unless INGEST_RUNTIME is "worker"', async () => {
    const ctx = createExecutionContext();
    await worker.scheduled(createScheduledController(), { ...env, INGEST_RUNTIME: 'actions' }, ctx);
    await waitOnExecutionContext(ctx);
    expect(await rows('SELECT * FROM meta')).toEqual([]);
  });
});
