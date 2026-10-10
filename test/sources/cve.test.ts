import { describe, expect, it } from 'vitest';
import { cveRecordUrl, cveSource, indexZip, MAX_RELEASE_PAGES, RELEASES_URL, type CveCursor } from '../../src/ingest/sources/cve';
import { parseCveRecord, productLabel } from '../../src/ingest/sources/cve-record';
import { parseSeverityLabel } from '../../src/ingest/types';
import { FakeFetch, jsonResponse } from '../helpers/fake-fetch';
import { cveRecords, deltaZip, releases, withMeta, type CveRecordJson } from '../helpers/fixtures';
import { sourceContext } from '../helpers/db';

const NOW = new Date('2026-10-04T18:00:00Z');
const DOWNLOAD = 'https://github.com/CVEProject/cvelistV5/releases/download/';

function zipResponse(records: CveRecordJson[]): Response {
  return new Response(deltaZip(records), { headers: { 'content-type': 'application/zip' } });
}

/** Serves the recorded release list and a zip per asset name. */
function cvelist(zips: Record<string, CveRecordJson[]>, releaseList: unknown = releases): FakeFetch {
  return new FakeFetch()
    .on(RELEASES_URL, () => jsonResponse(releaseList))
    .on(DOWNLOAD, (req) => {
      const name = req.url.split('/').pop()!;
      const records = zips[name];
      if (!records) throw new Error(`no zip fixture for ${name}`);
      return zipResponse(records);
    });
}

describe('parseCveRecord', () => {
  it('reads a package-level record with CISA ADP enrichment', () => {
    const p = parseCveRecord(cveRecords['CVE-2024-34393'])!;
    expect(p.fields).toMatchObject({
      title: 'libxmljs2 attrs type confusion RCE',
      cvssScore: 8.1,
      cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cwe: ['CWE-843'],
      publishedAt: '2024-05-02T18:56:44.270Z',
    });
    expect(p.fields.ssvc).toEqual({ exploitation: 'poc', automatable: 'no', technicalImpact: 'total' });
    expect(p.affected).toContainEqual(
      expect.objectContaining({ kind: 'package', ecosystem: 'npm', packageName: 'libxmljs2', fixedVersion: null }),
    );
  });

  it('prefers CVSS 4.0 and reads products from CPEs', () => {
    const p = parseCveRecord(cveRecords['CVE-2026-104910'])!;
    expect(p.fields.cvssVector).toMatch(/^CVSS:4\.0\//);
    expect(p.fields.cwe).toEqual(['CWE-862', 'CWE-285']);
    expect(p.affected).toEqual([
      expect.objectContaining({ kind: 'product', vendor: 'misp', product: 'misp', label: 'MISP', fixedVersion: '2.5.48' }),
    ]);
  });

  it('falls back to CISA ADP CVSS and gives no single fix for multi-branch records', () => {
    const p = parseCveRecord(cveRecords['CVE-2022-48816'])!;
    expect(p.fields.cvssScore).toBe(7.8);
    expect(p.fields.ssvc?.exploitation).toBe('none');
    expect(p.affected!.every((a) => a.fixedVersion === null)).toBe(true);
    expect(p.affected![0]).toMatchObject({ vendor: 'linux', product: 'linux', label: 'Linux' });
  });

  it("reads a CNA's textual severity, which some give instead of a CVSS score", () => {
    const base = cveRecords['CVE-2024-34393']! as CveRecordJson & { containers: { cna: Record<string, unknown> } };
    const textual = { other: { type: 'Textual description of severity', content: { text: 'Important', namespace: 'https://access.redhat.com/security/updates/classification/' } } };
    // The CNA's metrics replaced by the word alone, and no CISA ADP container to fall back to.
    const p = parseCveRecord({ ...base, containers: { cna: { ...base.containers.cna, metrics: [textual] } } })!;
    expect(p.fields).toMatchObject({ cvssScore: null, severityLabel: 'high' });
    expect(parseCveRecord(base)!.fields.severityLabel).toBeNull();
  });

  it('maps every source severity word onto one scale', () => {
    expect(['Critical', 'important', 'HIGH', 'moderate', 'medium', 'low', 'none', '', 7].map(parseSeverityLabel)).toEqual([
      'critical', 'high', 'high', 'medium', 'medium', 'low', null, null, null,
    ]);
  });

  it('marks rejected records as withdrawn', () => {
    expect(parseCveRecord(cveRecords['CVE-2026-104886'])).toEqual({
      source: 'cve',
      id: 'CVE-2026-104886',
      aliases: [],
      fields: {},
      withdrawn: true,
    });
  });

  it('rejects things that are not CVE records', () => {
    expect(parseCveRecord(null)).toBeNull();
    expect(parseCveRecord({ cveMetadata: { cveId: 'not-a-cve' } })).toBeNull();
    expect(parseCveRecord('{}')).toBeNull();
  });

  it('builds product labels without repeating the vendor', () => {
    expect(productLabel('Cisco', 'IOS XE')).toBe('Cisco IOS XE');
    expect(productLabel('Linux', 'Linux')).toBe('Linux');
    expect(productLabel('Zammad GmbH', 'Zammad')).toBe('Zammad GmbH Zammad');
    expect(productLabel(null, 'nginx')).toBe('nginx');
    expect(productLabel('Acme', null)).toBe('Acme');
  });
});

describe('cveRecordUrl', () => {
  it('uses the thousands bucket', () => {
    expect(cveRecordUrl('CVE-2021-44228')).toMatch(/\/cves\/2021\/44xxx\/CVE-2021-44228\.json$/);
    expect(cveRecordUrl('CVE-2026-105096')).toMatch(/\/cves\/2026\/105xxx\/CVE-2026-105096\.json$/);
    expect(cveRecordUrl('CVE-2020-0601')).toMatch(/\/cves\/2020\/0xxx\/CVE-2020-0601\.json$/);
  });
});

describe('indexZip', () => {
  it('sorts by dateUpdated then ID and skips non-records', () => {
    const a = withMeta(cveRecords['CVE-2026-100107']!, { dateUpdated: '2026-10-03T10:00:00.000Z' });
    const b = withMeta(cveRecords['CVE-2026-100148']!, { dateUpdated: '2026-10-03T09:00:00.000Z' });
    const c = withMeta(cveRecords['CVE-2025-12828']!, { dateUpdated: '2026-10-03T10:00:00.000Z' });
    const entries = indexZip(deltaZip([a, b, c]));
    expect(entries.map((e) => e.id)).toEqual(['CVE-2026-100148', 'CVE-2025-12828', 'CVE-2026-100107']);
  });
});

describe('cveSource', () => {
  const day3 = [cveRecords['CVE-2026-100107']!, cveRecords['CVE-2026-100148']!, cveRecords['CVE-2025-12828']!, cveRecords['CVE-2026-104910']!];

  it('reads the end-of-day zip of a finished day, then moves to the next day', async () => {
    const f = cvelist({ '2026-10-03_delta_CVEs_at_end_of_day.zip': day3 });
    const ctx = sourceContext(f.fetch, NOW);
    const start: CveCursor = { day: '2026-10-03', ts: '2026-10-03T00:00:00.000Z', id: '' };

    const first = await cveSource.fetchChanges(start, ctx);
    expect(first.done).toBe(false);
    expect(first.records.map((r) => r.id)).toEqual([
      'CVE-2026-100148', // 15:42:43.676
      'CVE-2025-12828', // 15:42:44.465
      'CVE-2026-100107', // 15:42:49.125
      'CVE-2026-104910', // 15:52:56.095
    ]);
    expect(first.nextCursor).toEqual({ day: '2026-10-03', ts: '2026-10-03T15:52:56.095Z', id: 'CVE-2026-104910' });

    const second = await cveSource.fetchChanges(first.nextCursor, ctx);
    expect(second.records).toEqual([]);
    expect(second.done).toBe(false);
    // The next day starts by re-reading the last hour of this one.
    expect(second.nextCursor).toEqual({ day: '2026-10-04', ts: '2026-10-03T15:52:56.095Z', id: '' });

    // One release listing and one zip download, both cached for the run.
    expect(f.urls().filter((u) => u.startsWith(RELEASES_URL))).toHaveLength(1);
    expect(f.urls().filter((u) => u.startsWith(DOWNLOAD))).toHaveLength(1);
  });

  it('caps the overlap at the last hour of the day', async () => {
    const f = cvelist({ '2026-10-03_delta_CVEs_at_end_of_day.zip': [] });
    const res = await cveSource.fetchChanges({ day: '2026-10-03', ts: '2026-10-03T23:59:00.000Z', id: 'CVE-2026-1' }, sourceContext(f.fetch, NOW));
    expect(res.nextCursor).toEqual({ day: '2026-10-04', ts: '2026-10-03T23:00:00.000Z', id: '' });
  });

  it('reads the latest hourly zip for today, found by asset name not tag', async () => {
    const f = cvelist({ '2026-10-04_delta_CVEs_at_1700Z.zip': [withMeta(cveRecords['CVE-2026-104910']!, { dateUpdated: '2026-10-04T16:00:00.000Z' })] });
    const ctx = sourceContext(f.fetch, NOW);
    const res = await cveSource.fetchChanges({ day: '2026-10-04', ts: '2026-10-04T00:00:00.000Z', id: '' }, ctx);
    expect(res.records.map((r) => r.id)).toEqual(['CVE-2026-104910']);
    const done = await cveSource.fetchChanges(res.nextCursor, ctx);
    expect(done).toMatchObject({ records: [], done: true });
    expect(done.nextCursor.day).toBe('2026-10-04');
  });

  it('waits for the end-of-day zip before leaving a finished day', async () => {
    const withoutEod = (releases as { tag_name: string }[]).filter((r) => r.tag_name !== 'cve_2026-10-03_at_end_of_day');
    const f = cvelist({ '2026-10-03_delta_CVEs_at_2200Z.zip': [] }, withoutEod);
    const cursor: CveCursor = { day: '2026-10-03', ts: '2026-10-03T20:00:00.000Z', id: 'CVE-2026-1' };
    const res = await cveSource.fetchChanges(cursor, sourceContext(f.fetch, NOW));
    expect(res).toEqual({ records: [], nextCursor: cursor, done: true });
  });

  it('breaks timestamp ties by ID', async () => {
    const ts = '2026-10-03T12:00:00.000Z';
    const f = cvelist({
      '2026-10-03_delta_CVEs_at_end_of_day.zip': [
        withMeta(cveRecords['CVE-2026-100107']!, { dateUpdated: ts }),
        withMeta(cveRecords['CVE-2026-100148']!, { dateUpdated: ts }),
      ],
    });
    const res = await cveSource.fetchChanges({ day: '2026-10-03', ts, id: 'CVE-2026-100107' }, sourceContext(f.fetch, NOW));
    expect(res.records.map((r) => r.id)).toEqual(['CVE-2026-100148']);
  });

  it('is done when today has no release yet', async () => {
    const f = cvelist({});
    const later = new Date('2026-10-05T00:30:00Z');
    const cursor: CveCursor = { day: '2026-10-05', ts: '2026-10-04T23:00:00.000Z', id: '' };
    expect(await cveSource.fetchChanges(cursor, sourceContext(f.fetch, later))).toMatchObject({ done: true, records: [] });
  });

  it('fails loudly when a past day is missing from the releases', async () => {
    const f = cvelist({});
    const cursor: CveCursor = { day: '2026-01-01', ts: '2026-01-01T00:00:00.000Z', id: '' };
    await expect(cveSource.fetchChanges(cursor, sourceContext(f.fetch, NOW))).rejects.toThrow(/re-run the backfill/);
  });

  it("stops paging at GitHub's release listing limit", async () => {
    let page = 0;
    const f = new FakeFetch().on('https://api.github.com/repos/CVEProject/cvelistV5/releases', () => {
      page++;
      // Each page links to the next, and nothing matches the day being looked for.
      return jsonResponse([{ assets: [] }], { headers: { link: `<${RELEASES_URL}&page=${page + 1}>; rel="next"` } });
    });
    const cursor: CveCursor = { day: '2026-01-01', ts: '2026-01-01T00:00:00.000Z', id: '' };
    await expect(cveSource.fetchChanges(cursor, sourceContext(f.fetch, NOW))).rejects.toThrow(/re-run the backfill/);
    expect(f.calls).toHaveLength(MAX_RELEASE_PAGES);
  });

  it('treats a 422 past the listing limit as the end of the releases', async () => {
    const f = new FakeFetch().on(RELEASES_URL, () => jsonResponse({ message: 'Only the first 1000 results are available.' }, { status: 422 }));
    const cursor: CveCursor = { day: '2026-01-01', ts: '2026-01-01T00:00:00.000Z', id: '' };
    await expect(cveSource.fetchChanges(cursor, sourceContext(f.fetch, NOW))).rejects.toThrow(/re-run the backfill/);
    expect(f.calls).toHaveLength(1);
  });

  it('turns GitHub rate limiting of downloads too into RateLimited', async () => {
    const f = new FakeFetch().on(/github\.com\//, () => rateLimited());
    const cursor = cveSource.initialCursor(NOW);
    await expect(cveSource.fetchChanges(cursor, sourceContext(f.fetch, NOW))).rejects.toThrow(/rate limited/);
  });
});

function rateLimited(): Response {
  return jsonResponse({ message: 'API rate limit exceeded' }, { status: 403, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1791112003' } });
}

/** A rate-limited releases API, with zips downloadable by tag (404 for the rest). */
function byTag(zips: Record<string, CveRecordJson[]>): FakeFetch {
  return new FakeFetch().on(RELEASES_URL, () => rateLimited()).on(DOWNLOAD, (req) => {
    const [tag, name] = req.url.slice(DOWNLOAD.length).split('/') as [string, string];
    const records = zips[name];
    // The asset must be asked for under its own release's tag.
    const ownTag = `cve_${name.replace(/\.zip$/, '').replace('_delta_CVEs_at_end_of_day', '_at_end_of_day').replace('_delta_CVEs_at_', '_')}`;
    if (!records || tag !== ownTag) return new Response('Not Found', { status: 404 });
    return zipResponse(records);
  });
}

describe('cveSource without the releases API', () => {
  const day3 = [cveRecords['CVE-2026-100148']!, cveRecords['CVE-2026-104910']!];

  it('downloads the end-of-day zip of a finished day by tag, then moves on', async () => {
    const f = byTag({ '2026-10-03_delta_CVEs_at_end_of_day.zip': day3 });
    const ctx = sourceContext(f.fetch, NOW);
    const first = await cveSource.fetchChanges({ day: '2026-10-03', ts: '2026-10-03T00:00:00.000Z', id: '' }, ctx);
    expect(first.records.map((r) => r.id)).toEqual(['CVE-2026-100148', 'CVE-2026-104910']);
    const second = await cveSource.fetchChanges(first.nextCursor, ctx);
    expect(second.nextCursor).toEqual({ day: '2026-10-04', ts: '2026-10-03T15:52:56.095Z', id: '' });
    // The API is asked once; the zip is downloaded once and cached for the run.
    expect(f.urls().filter((u) => u.startsWith(RELEASES_URL))).toHaveLength(1);
    expect(f.urls()).toEqual([RELEASES_URL, `${DOWNLOAD}cve_2026-10-03_at_end_of_day/2026-10-03_delta_CVEs_at_end_of_day.zip`]);
  });

  it("reads today's latest hourly zip, walking back from the current hour", async () => {
    const f = byTag({ '2026-10-04_delta_CVEs_at_1700Z.zip': [withMeta(cveRecords['CVE-2026-104910']!, { dateUpdated: '2026-10-04T16:00:00.000Z' })] });
    const ctx = sourceContext(f.fetch, NOW);
    const res = await cveSource.fetchChanges({ day: '2026-10-04', ts: '2026-10-04T00:00:00.000Z', id: '' }, ctx);
    expect(res.records.map((r) => r.id)).toEqual(['CVE-2026-104910']);
    // 18:00 has no release yet; 17:00 does. No end-of-day zip is tried for today.
    expect(f.urls().slice(1).map((u) => u.split('/').pop())).toEqual(['2026-10-04_delta_CVEs_at_1800Z.zip', '2026-10-04_delta_CVEs_at_1700Z.zip']);
    expect(await cveSource.fetchChanges(res.nextCursor, ctx)).toMatchObject({ records: [], done: true });
  });

  it('waits on the latest hourly zip until a finished day has its end-of-day zip', async () => {
    const f = byTag({ '2026-10-03_delta_CVEs_at_2300Z.zip': [] });
    const cursor: CveCursor = { day: '2026-10-03', ts: '2026-10-03T20:00:00.000Z', id: 'CVE-2026-1' };
    expect(await cveSource.fetchChanges(cursor, sourceContext(f.fetch, NOW))).toEqual({ records: [], nextCursor: cursor, done: true });
  });

  it('is done when today has no release yet, and fails loudly for a past day with none', async () => {
    const early = new Date('2026-10-05T00:30:00Z');
    const today: CveCursor = { day: '2026-10-05', ts: '2026-10-04T23:00:00.000Z', id: '' };
    expect(await cveSource.fetchChanges(today, sourceContext(byTag({}).fetch, early))).toMatchObject({ done: true, records: [] });
    const past: CveCursor = { day: '2026-10-01', ts: '2026-10-01T00:00:00.000Z', id: '' };
    const f = byTag({});
    await expect(cveSource.fetchChanges(past, sourceContext(f.fetch, NOW))).rejects.toThrow(/re-run the backfill/);
    // The end-of-day release and all 24 hourly ones were tried.
    expect(f.urls().filter((u) => u.startsWith(DOWNLOAD))).toHaveLength(25);
  });
});
