import { describe, expect, it } from 'vitest';
import { RateLimited } from '../../src/ingest/budget';
import { ADVISORIES_URL, advisoriesUrl, ghsaSource, parseAdvisory } from '../../src/ingest/sources/ghsa';
import { parseSeverityLabel } from '../../src/ingest/types';
import { FakeFetch, jsonResponse } from '../helpers/fake-fetch';
import { ghsaPage } from '../helpers/fixtures';
import { sourceContext } from '../helpers/db';

const NOW = new Date('2026-10-04T18:00:00Z');
const advisories = ghsaPage.advisories as Record<string, unknown>[];
const byId = (id: string) => advisories.find((a) => a.ghsa_id === id)!;

describe('parseAdvisory', () => {
  it('keys by CVE and keeps the GHSA ID as an alias', () => {
    const p = parseAdvisory(byId('GHSA-wp3j-xq48-xpjw'))!;
    expect(p.id).toBe('CVE-2025-9566');
    expect(p.aliases).toEqual(['GHSA-wp3j-xq48-xpjw']);
    expect(p.fields.title).toBeTruthy();
    expect(p.fields.refs?.[0]).toEqual({ url: 'https://github.com/advisories/GHSA-wp3j-xq48-xpjw', tags: ['advisory'] });
  });

  it('maps packages and fixed versions, including branches without a fix', () => {
    const p = parseAdvisory(byId('GHSA-wp3j-xq48-xpjw'))!;
    expect(p.affected).toEqual([
      expect.objectContaining({ kind: 'package', ecosystem: 'Go', packageName: 'github.com/containers/podman/v5', fixedVersion: '5.6.1', ranges: [{ range: '<= 5.6.0' }] }),
      expect.objectContaining({ kind: 'package', ecosystem: 'Go', packageName: 'github.com/containers/podman/v4', fixedVersion: null }),
    ]);
  });

  it('maps GitHub ecosystem names to OSV names', () => {
    const p = parseAdvisory(byId('GHSA-9272-wg2r-7xmx'))!;
    expect(p.affected?.map((a) => a.ecosystem)).toEqual(['Maven', 'Maven']);
  });

  it("keeps GitHub's severity word, scored or not", () => {
    const a = byId('GHSA-456v-xq2p-r4cj');
    expect(parseAdvisory(a)!.fields.severityLabel).toBe(parseSeverityLabel(a.severity));
    const unscored = { ...a, severity: 'critical', cvss: null, cvss_severities: null };
    expect(parseAdvisory(unscored)!.fields).toMatchObject({ cvssScore: null, severityLabel: 'critical' });
    expect(parseAdvisory({ ...a, severity: 'unknown' })!.fields.severityLabel).toBeNull();
  });

  it('keys by GHSA when there is no CVE', () => {
    const p = parseAdvisory(byId('GHSA-456v-xq2p-r4cj'))!;
    expect(p.id).toBe('GHSA-456v-xq2p-r4cj');
    expect(p.aliases).toEqual([]);
    expect(p.affected?.[0]).toMatchObject({ ecosystem: 'npm', packageName: 'code-ollama', fixedVersion: '0.36.1' });
  });

  it('marks withdrawn advisories', () => {
    expect(parseAdvisory({ ...byId('GHSA-2mhw-wcx5-v3xj'), withdrawn_at: '2026-10-01T00:00:00Z' })).toMatchObject({
      id: 'CVE-2026-61834',
      withdrawn: true,
    });
  });

  it('accepts the older {identifier} shape for first_patched_version', () => {
    const adv = structuredClone(byId('GHSA-2mhw-wcx5-v3xj')) as { vulnerabilities: { first_patched_version: unknown }[] };
    adv.vulnerabilities[0]!.first_patched_version = { identifier: '0.9.2' };
    expect(parseAdvisory(adv)?.affected?.[0]?.fixedVersion).toBe('0.9.2');
  });

  it('ignores a zero CVSS score', () => {
    const adv = { ...byId('GHSA-2mhw-wcx5-v3xj'), cvss_severities: { cvss_v3: { score: 0, vector_string: null }, cvss_v4: { score: 0, vector_string: null } }, cvss: null };
    expect(parseAdvisory(adv)?.fields.cvssScore).toBeNull();
  });
});

describe('advisoriesUrl', () => {
  it('drops fractional seconds, which the API rejects', () => {
    const u = new URL(advisoriesUrl('2026-09-27T18:30:46.972Z'));
    expect(u.searchParams.get('modified')).toBe('>=2026-09-27T18:30:46Z');
    expect(u.searchParams.get('type')).toBe('reviewed');
    expect(u.searchParams.get('sort')).toBe('updated');
    expect(u.searchParams.get('direction')).toBe('asc');
  });
});

describe('ghsaSource', () => {
  const next = `${ADVISORIES_URL}?page=2-token`;

  it('follows the Link header, then moves `since` to the latest update seen', async () => {
    const f = new FakeFetch()
      .on((u) => u.href.startsWith(ADVISORIES_URL) && u.searchParams.has('modified'), () =>
        jsonResponse(advisories.slice(0, 3), { headers: { link: `<${next}>; rel="next"` } }),
      )
      .on(next, () => jsonResponse(advisories.slice(3)));
    const ctx = sourceContext(f.fetch, NOW);
    const start = ghsaSource.initialCursor(NOW);

    const first = await ghsaSource.fetchChanges(start, ctx);
    expect(first.done).toBe(false);
    expect(first.records).toHaveLength(3);
    expect(first.nextCursor).toEqual({ since: start.since, next, maxSeen: '2026-09-28T14:01:17.000Z' });

    const second = await ghsaSource.fetchChanges(first.nextCursor, ctx);
    expect(second.done).toBe(true);
    expect(second.nextCursor).toEqual({ since: '2026-09-28T21:57:00.000Z', next: null, maxSeen: null });
  });

  it('sends the API version and token', async () => {
    const f = new FakeFetch().on(ADVISORIES_URL, () => jsonResponse([]));
    await ghsaSource.fetchChanges(ghsaSource.initialCursor(NOW), sourceContext(f.fetch, NOW, { githubToken: 't0ken' }));
    const h = f.calls[0]!.headers;
    expect(h.get('x-github-api-version')).toBe('2022-11-28');
    expect(h.get('authorization')).toBe('Bearer t0ken');
    expect(h.get('user-agent')).toBeTruthy();
  });

  it('restarts the pass when a pagination token is rejected', async () => {
    const f = new FakeFetch().on(next, () => jsonResponse({ message: 'bad cursor' }, { status: 422 }));
    const cursor = { since: '2026-10-01T00:00:00.000Z', next, maxSeen: '2026-10-02T00:00:00.000Z' };
    const res = await ghsaSource.fetchChanges(cursor, sourceContext(f.fetch, NOW));
    expect(res).toEqual({ records: [], nextCursor: { ...cursor, next: null }, done: false });
  });

  it('restarts only once a run, then fails with the reason GitHub gave', async () => {
    const f = new FakeFetch().on(next, () => jsonResponse({ message: '`x` does not appear to be a valid cursor.' }, { status: 400 }));
    const cursor = { since: '2026-10-01T00:00:00.000Z', next, maxSeen: null };
    const ctx = sourceContext(f.fetch, NOW);
    expect((await ghsaSource.fetchChanges(cursor, ctx)).nextCursor.next).toBeNull();
    await expect(ghsaSource.fetchChanges(cursor, ctx)).rejects.toThrow('GitHub advisories: HTTP 400 (`x` does not appear to be a valid cursor.)');
    // A new run gets its restart back.
    expect((await ghsaSource.fetchChanges(cursor, sourceContext(f.fetch, NOW))).nextCursor.next).toBeNull();
  });

  it('fails, rather than restarting, when a page is refused for another reason', async () => {
    const f = new FakeFetch().on(next, () => jsonResponse({ message: 'Bad credentials' }, { status: 401 }));
    const cursor = { since: '2026-10-01T00:00:00.000Z', next, maxSeen: null };
    await expect(ghsaSource.fetchChanges(cursor, sourceContext(f.fetch, NOW))).rejects.toThrow(/HTTP 401 \(Bad credentials\)/);
  });

  it('stops on rate limiting without moving the cursor', async () => {
    const f = new FakeFetch().on(ADVISORIES_URL, () => jsonResponse({}, { status: 429 }));
    await expect(ghsaSource.fetchChanges(ghsaSource.initialCursor(NOW), sourceContext(f.fetch, NOW))).rejects.toBeInstanceOf(RateLimited);
  });

  it('fails on server errors that outlast the retries', async () => {
    const f = new FakeFetch().on(ADVISORIES_URL, () => jsonResponse({}, { status: 502 }));
    await expect(ghsaSource.fetchChanges(ghsaSource.initialCursor(NOW), sourceContext(f.fetch, NOW))).rejects.toThrow(/HTTP 502/);
    expect(f.calls).toHaveLength(3);
  });
});
