import { beforeEach, describe, expect, it } from 'vitest';
import { applyPatches } from '../../src/ingest/apply';
import { RateLimited } from '../../src/ingest/budget';
import { EPSS_URL, epssSource, parseEpssResponse } from '../../src/ingest/sources/epss';
import { KEV_URL, kevSource, parseKevEntry } from '../../src/ingest/sources/kev';
import type { VulnPatch } from '../../src/ingest/types';
import { FakeFetch, jsonResponse } from '../helpers/fake-fetch';
import { epssLatest, epssScores, kevFeed } from '../helpers/fixtures';
import { resetDb, sourceContext, store } from '../helpers/db';

const NOW = new Date('2026-10-04T18:00:00Z');
const kevEntries = kevFeed.body.vulnerabilities;
const kevEntry = (id: string) => kevEntries.find((e) => e.cveID === id)!;

describe('KEV', () => {
  it('parses an entry', () => {
    expect(parseKevEntry(kevEntry('CVE-2026-59310'))).toMatchObject({
      source: 'kev',
      id: 'CVE-2026-59310',
      fields: { kevAddedAt: '2026-08-18T00:00:00.000Z', kevRansomware: true, kevDueDate: expect.any(String) },
      affected: [{ kind: 'product', vendor: 'broadcom', product: 'vmware_vcenter', label: 'Broadcom VMware vCenter' }],
    });
  });

  it('adds no product row for "Multiple Products"', () => {
    expect(parseKevEntry(kevEntry('CVE-2026-86950'))?.affected).toEqual([]);
  });

  it('rejects malformed entries', () => {
    expect(parseKevEntry({ cveID: 'CVE-2026-1' })).toBeNull();
    expect(parseKevEntry({ cveID: 'nope', dateAdded: '2026-01-01' })).toBeNull();
  });

  it('fetches the whole feed and stores the validators', async () => {
    const f = new FakeFetch().on(KEV_URL, () => jsonResponse(kevFeed.body, { headers: kevFeed.headers as Record<string, string> }));
    const res = await kevSource.fetchChanges(kevSource.initialCursor(NOW), sourceContext(f.fetch, NOW));
    expect(res.done).toBe(true);
    expect(res.records).toHaveLength(kevEntries.length);
    expect(res.nextCursor).toEqual({ etag: kevFeed.headers.etag, lastModified: kevFeed.headers['last-modified'] });
  });

  it('sends a conditional GET and does nothing on 304', async () => {
    const f = new FakeFetch().on(KEV_URL, () => new Response(null, { status: 304 }));
    const cursor = { etag: '"abc"', lastModified: 'Fri, 02 Oct 2026 15:19:38 GMT' };
    const res = await kevSource.fetchChanges(cursor, sourceContext(f.fetch, NOW));
    expect(res).toEqual({ records: [], nextCursor: cursor, done: true });
    expect(f.calls[0]!.headers.get('if-none-match')).toBe('"abc"');
    expect(f.calls[0]!.headers.get('if-modified-since')).toBe(cursor.lastModified);
  });
});

describe('EPSS', () => {
  beforeEach(resetDb);

  it('parses string values and drops out-of-range ones', () => {
    const patches = parseEpssResponse({
      data: [
        { cve: 'CVE-2026-1', epss: '0.100000000', percentile: '0.95', date: '2026-10-04' },
        { cve: 'CVE-2026-2', epss: '1.5', percentile: '0.5', date: '2026-10-04' },
        { cve: 'CVE-2026-3', epss: 'NaN', percentile: '0.5', date: '2026-10-04' },
        { cve: 'CVE-2026-4', epss: '0.2', percentile: '0.5', date: 'yesterday' },
      ],
    });
    expect(patches).toEqual([{ source: 'epss', id: 'CVE-2026-1', aliases: [], fields: { epss: 0.1, epssPercentile: 0.95, epssDate: '2026-10-04' } }]);
  });

  it('parses the recorded response', () => {
    const patches = parseEpssResponse(epssScores.body);
    expect(patches.length).toBe(epssScores.body.data.length);
    for (const p of patches) expect(p.fields.epss).toBeGreaterThanOrEqual(0);
  });

  it('rejects an unexpected shape', () => {
    expect(() => parseEpssResponse({ data: 'nope' })).toThrow(/unexpected/);
  });

  async function seed(ids: string[]): Promise<void> {
    const patches: VulnPatch[] = ids.map((id) => ({ source: 'cve', id, aliases: [], fields: { publishedAt: '2026-10-01T00:00:00.000Z' } }));
    await applyPatches(store(), patches, { now: NOW, windowStart: '2026-07-06T00:00:00.000Z', epssEvents: true });
  }

  function epssApi(): FakeFetch {
    return new FakeFetch().on(EPSS_URL, (req) => {
      const u = new URL(req.url);
      if (u.searchParams.get('limit') === '1' && !u.searchParams.has('cve')) return jsonResponse(epssLatest);
      const ids = (u.searchParams.get('cve') ?? '').split(',');
      const date = u.searchParams.get('date')!;
      return jsonResponse({ status: 'OK', data: ids.map((cve) => ({ cve, epss: '0.010000000', percentile: '0.500000000', date })) });
    });
  }

  it('skips the pass when the score date has not moved', async () => {
    const f = epssApi();
    const latest = epssLatest.data[0]!.date;
    const res = await epssSource.fetchChanges({ scoreDate: latest, lastId: null }, sourceContext(f.fetch, NOW));
    expect(res).toMatchObject({ records: [], done: true });
    expect(f.calls).toHaveLength(1);
  });

  it('walks every stored CVE in batches that fit the cve= limit', async () => {
    const ids = Array.from({ length: 300 }, (_, i) => `CVE-2026-${String(100000 + i)}`);
    await seed(ids);
    const f = epssApi();
    const ctx = sourceContext(f.fetch, NOW);

    let cursor = epssSource.initialCursor(NOW);
    const seen: string[] = [];
    for (let i = 0; i < 10; i++) {
      const res = await epssSource.fetchChanges(cursor, ctx);
      seen.push(...res.records.map((r) => r.id));
      cursor = res.nextCursor;
      if (res.done) break;
    }
    expect(seen).toEqual(ids);
    expect(cursor).toEqual({ scoreDate: epssLatest.data[0]!.date, lastId: null });
    for (const req of f.calls) {
      const cve = new URL(req.url).searchParams.get('cve');
      if (cve) expect(cve.length).toBeLessThanOrEqual(2000);
    }
  });

  it('turns HTTP 429 into RateLimited', async () => {
    const f = new FakeFetch().on(EPSS_URL, () => new Response('', { status: 429 }));
    await expect(epssSource.fetchChanges(epssSource.initialCursor(NOW), sourceContext(f.fetch, NOW))).rejects.toBeInstanceOf(RateLimited);
  });
});
