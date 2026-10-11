import { beforeEach, describe, expect, it } from 'vitest';
import { applyPatches } from '../../src/ingest/apply';
import { RateLimited } from '../../src/ingest/budget';
import { EPSS_URL, epssFileUrl, epssSource, parseEpssLine, parseEpssResponse } from '../../src/ingest/sources/epss';
import { KEV_URL, kevSource, parseKevEntry } from '../../src/ingest/sources/kev';
import type { VulnPatch } from '../../src/ingest/types';
import { FakeFetch, gzipResponse, jsonResponse } from '../helpers/fake-fetch';
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

  const LATEST = epssLatest.data[0]!.date;
  const csv = (rows: string[]) => ['#model_version:v2026.06.15,score_date:2026-10-04T12:00:00Z', 'cve,epss,percentile', ...rows].join('\n');

  function epssApi(file: () => Response): FakeFetch {
    return new FakeFetch().on(EPSS_URL, () => jsonResponse(epssLatest)).on(epssFileUrl(LATEST), file);
  }

  async function pass(f: FakeFetch, cursor = epssSource.initialCursor(NOW)) {
    const ctx = sourceContext(f.fetch, NOW);
    const pages: string[][] = [];
    for (let i = 0; i < 20; i++) {
      const res = await epssSource.fetchChanges(cursor, ctx);
      pages.push(res.records.map((r) => r.id));
      cursor = res.nextCursor;
      if (res.done) break;
    }
    return { pages, cursor };
  }

  it('parses file lines and drops headers and bad values', () => {
    expect(parseEpssLine('CVE-2026-1,0.10000,0.95000')).toEqual({ cve: 'CVE-2026-1', epss: 0.1, percentile: 0.95 });
    expect(parseEpssLine('CVE-2026-1,0.10000,0.95000\r')).toEqual({ cve: 'CVE-2026-1', epss: 0.1, percentile: 0.95 });
    for (const bad of ['#model_version:v2026.06.15,score_date:2026-10-04T12:00:00Z', 'cve,epss,percentile', 'CVE-2026-2,1.5,0.5', 'CVE-2026-3,NaN,0.5', 'CVE-2026-4,,0.5', 'CVE-2026-5,0.1', ''])
      expect(parseEpssLine(bad)).toBeNull();
  });

  it('skips the pass when the score date has not moved', async () => {
    const f = epssApi(() => gzipResponse(csv([])));
    const res = await epssSource.fetchChanges({ scoreDate: LATEST, lastId: null }, sourceContext(f.fetch, NOW));
    expect(res).toMatchObject({ records: [], done: true });
    expect(f.calls).toHaveLength(1);
  });

  it('downloads the file once and pages through stored CVEs only, in ID order', async () => {
    const ids = Array.from({ length: 900 }, (_, i) => `CVE-2026-${String(100000 + i)}`);
    await seed(ids);
    // Unsorted, with CVEs we don't hold.
    const f = epssApi(() => gzipResponse(csv([...ids].reverse().map((id) => `${id},0.01000,0.50000`).concat('CVE-1999-0001,0.5,0.9'))));
    const { pages, cursor } = await pass(f);
    expect(pages.map((p) => p.length)).toEqual([400, 400, 100]);
    expect(pages.flat()).toEqual(ids);
    expect(cursor).toEqual({ scoreDate: LATEST, lastId: null });
    expect(f.urls().filter((u) => u.endsWith('.csv.gz'))).toHaveLength(1);
  });

  it('leaves out scores that have not moved enough to write', async () => {
    await seed(['CVE-2026-1', 'CVE-2026-2', 'CVE-2026-3']);
    await applyPatches(
      store(),
      ['CVE-2026-1', 'CVE-2026-2', 'CVE-2026-3'].map((id) => ({ source: 'epss' as const, id, aliases: [], fields: { epss: 0.01, epssPercentile: 0.5, epssDate: '2026-10-03' } })),
      { now: NOW, windowStart: '2026-07-06T00:00:00.000Z', epssEvents: true },
    );
    const f = epssApi(() => gzipResponse(csv(['CVE-2026-1,0.01050,0.50500', 'CVE-2026-2,0.02000,0.50000', 'CVE-2026-3,0.01000,0.52000'])));
    const { pages } = await pass(f);
    expect(pages.flat()).toEqual(['CVE-2026-2', 'CVE-2026-3']);
  });

  it('resumes after the cursor in a new run', async () => {
    const ids = ['CVE-2026-1', 'CVE-2026-2', 'CVE-2026-3'];
    await seed(ids);
    const f = epssApi(() => gzipResponse(csv(ids.map((id) => `${id},0.01000,0.50000`))));
    const { pages } = await pass(f, { scoreDate: LATEST, lastId: 'CVE-2026-1' });
    expect(pages.flat()).toEqual(['CVE-2026-2', 'CVE-2026-3']);
  });

  it('waits for a file that is not published yet', async () => {
    await seed(['CVE-2026-1']);
    const f = epssApi(() => new Response('<Error>AccessDenied</Error>', { status: 403 }));
    const cursor = { scoreDate: '2026-10-03', lastId: null };
    const res = await epssSource.fetchChanges(cursor, sourceContext(f.fetch, NOW));
    expect(res).toEqual({ records: [], nextCursor: cursor, done: true });
  });

  it('turns HTTP 429 into RateLimited', async () => {
    const f = new FakeFetch().on(EPSS_URL, () => new Response('', { status: 429 }));
    await expect(epssSource.fetchChanges(epssSource.initialCursor(NOW), sourceContext(f.fetch, NOW))).rejects.toBeInstanceOf(RateLimited);
  });
});
