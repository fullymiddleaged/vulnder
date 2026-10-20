import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { applyPatches } from '../src/ingest/apply';
import type { VulnPatch } from '../src/ingest/types';
import { matchStack } from '../src/match/match';
import { compareDotted, explicitlyUnaffected, unaffectedBounds } from '../src/match/versions';
import { parseStack } from '../src/stack/format';
import { resetDb, rows, store } from './helpers/db';

/** A Linux kernel CNA record's semver entries (CVE-2026-74279's shape): introduced in `since`, fixed in mainline at `fixed`. */
const kernelRanges = (since: string, fixed: string) => [
  { version: since, status: 'affected' },
  { version: '0', lessThan: since, status: 'unaffected', versionType: 'semver' },
  { version: '6.6.145', lessThanOrEqual: '6.6.*', status: 'unaffected', versionType: 'semver' },
  { version: '6.12.97', lessThanOrEqual: '6.12.*', status: 'unaffected', versionType: 'semver' },
  { version: fixed, lessThanOrEqual: '*', status: 'unaffected', versionType: 'original_commit_for_fix' },
];
const GIT_RANGES = [{ version: 'f43798c27684ab925adde7d8acc34c78c6e50df8', lessThan: 'a464d950f31c89565cbaae038cc60db04fe01956', status: 'affected', versionType: 'git' }];

describe('unaffected bounds', () => {
  it('keeps where the bug was introduced and where it was fixed for good, and nothing from git ranges', () => {
    expect(unaffectedBounds(kernelRanges('4.11', '7.2'))).toEqual({ below: '4.11', from: '7.2' });
    expect(unaffectedBounds(GIT_RANGES)).toEqual({ below: null, from: null });
    expect(unaffectedBounds([null, 'x', { status: 'unaffected', version: 0, lessThan: '1.0' }])).toEqual({ below: null, from: null });
  });

  it('compares dotted versions, a series as its first release', () => {
    expect(compareDotted('6.8', '6.8.0')).toBe(0);
    expect(compareDotted('6.8', '6.10')).toBe(-1);
    expect(compareDotted('7.0', '6.19.12')).toBe(1);
    expect(compareDotted('6.8', 'f43798c2')).toBeNull();
    expect(compareDotted('24h2', '6.8')).toBeNull();
  });

  it('rules a version out only where the record says so', () => {
    const b = unaffectedBounds(kernelRanges('6.10', '7.2'));
    expect(explicitlyUnaffected(b, '6.8')).toBe(true); // before it was introduced
    expect(explicitlyUnaffected(b, '6.12')).toBe(false); // affected; the 6.12 branch fix is later than its first release
    expect(explicitlyUnaffected(b, '7.2')).toBe(true); // fixed for good
    expect(explicitlyUnaffected(unaffectedBounds(kernelRanges('4.11', '6.5')), '6.8')).toBe(true); // fixed before 6.8
    // Says nothing comparable: never ruled out.
    expect(explicitlyUnaffected({ below: null, from: null }, '6.8')).toBe(false);
    expect(explicitlyUnaffected({ below: '0:4.18.0-553.el8', from: null }, '4.18')).toBe(false);
    expect(explicitlyUnaffected(b, '24h2')).toBe(false);
  });
});

describe('a product named with a version', () => {
  const NOW = new Date('2026-10-20T00:00:00Z');
  const kernelCve = (id: string, since: string, fixed: string): VulnPatch => ({
    source: 'cve',
    id,
    aliases: [],
    fields: { title: id, publishedAt: '2026-10-15T00:00:00.000Z', cvssScore: 7.8 },
    affected: [
      { kind: 'product', vendor: 'linux', product: 'linux', label: 'Linux', ranges: GIT_RANGES },
      { kind: 'product', vendor: 'linux', product: 'linux', label: 'Linux', ranges: kernelRanges(since, fixed) },
    ],
  });

  beforeEach(async () => {
    await resetDb();
    await applyPatches(store(), [kernelCve('CVE-2026-0001', '4.11', '7.2'), kernelCve('CVE-2026-0002', '6.10', '7.2'), kernelCve('CVE-2026-0003', '4.14', '6.5')], {
      now: NOW,
      windowStart: '2026-07-22T00:00:00.000Z',
      epssEvents: true,
    });
  });

  const ids = async (stack: string) =>
    (await matchStack(store(), parseStack(stack), { now: NOW, days: 30, osv: { affecting: async () => new Map() } })).results.map((r) => r.id).sort();

  it('stores the bounds with each row', async () => {
    expect(await rows("SELECT unaffected_below, unaffected_from FROM affected WHERE vuln_id = 'CVE-2026-0002' ORDER BY unaffected_below")).toEqual([
      { unaffected_below: null, unaffected_from: null },
      { unaffected_below: '6.10', unaffected_from: '7.2' },
    ]);
  });

  it('drops only the CVEs its records rule out for that version, and none without one', async () => {
    // Ubuntu 24.04's kernel: not the bug introduced in 6.10, nor the one fixed in 6.5.
    expect(await ids('?p:linux/linux@6.8')).toEqual(['CVE-2026-0001']);
    expect(await ids('?p:linux/linux@6.12')).toEqual(['CVE-2026-0001', 'CVE-2026-0002']);
    expect(await ids('p:linux/linux')).toEqual(['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003']);
  });

  it("backfills existing rows exactly as ingest derives them (migration 0012)", async () => {
    const migration = env.TEST_MIGRATIONS.find((m) => m.name.startsWith('0012'))!;
    const backfill = migration.queries.find((q) => q.trimStart().startsWith('UPDATE affected'))!;
    const cases = [kernelRanges('4.11', '7.2'), GIT_RANGES, [{ version: '0', lessThan: '2.0', status: 'unaffected' }], [{ version: '3.1', lessThanOrEqual: '*', status: 'unaffected' }]];
    await env.DB.exec('DELETE FROM affected');
    await env.DB.batch(
      cases.map((r, i) =>
        env.DB.prepare("INSERT INTO affected (vuln_id, source, kind, vendor, product, label, ranges) VALUES (?, 'cve', 'product', 'v', 'p', 'P', ?)").bind(`CVE-2026-100${i}`, JSON.stringify(r)),
      ),
    );
    await env.DB.prepare(backfill).run();
    const got = await rows<{ unaffected_below: string | null; unaffected_from: string | null }>('SELECT unaffected_below, unaffected_from FROM affected ORDER BY vuln_id');
    expect(got.map((r) => ({ below: r.unaffected_below, from: r.unaffected_from }))).toEqual(cases.map(unaffectedBounds));
  });
});
