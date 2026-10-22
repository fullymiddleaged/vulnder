import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { applyPatches } from '../src/ingest/apply';
import type { VulnPatch } from '../src/ingest/types';
import { matchStack } from '../src/match/match';
import { compareDotted, explicitlyUnaffected, fixedVersionOf, fixesFor, MAX_FIXES, splitFixes, unaffectedBounds } from '../src/match/versions';
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

/** PHP's shape (CVE-2026-109618): one range per release branch. */
const PHP_RANGES = [
  { status: 'affected', version: '8.2.*', lessThan: '8.2.35', versionType: 'semver' },
  { status: 'affected', version: '8.3.*', lessThan: '8.3.36', versionType: 'semver' },
  { status: 'affected', version: '8.4.*', lessThan: '8.4.27', versionType: 'semver' },
  { status: 'affected', version: '8.5.*', lessThan: '8.5.12', versionType: 'semver' },
];
/** Cases for fixedVersionOf, each with what it should give. */
const FIX_CASES: [unknown[], string | null][] = [
  [PHP_RANGES, '8.2.35, 8.3.36, 8.4.27, 8.5.12'],
  // One bound is kept as written, from any start.
  [[{ status: 'affected', version: '0', lessThan: '2.5.48' }], '2.5.48'],
  [[{ status: 'affected', version: '1.0', lessThan: '2.0' }, { status: 'affected', version: '1.5', lessThan: '2.0' }], '2.0'],
  // A start written as the series itself, or as its first release.
  [[{ status: 'affected', version: '8.2', lessThan: '8.2.35' }, { status: 'affected', version: '8.3.0', lessThan: '8.3.36' }], '8.2.35, 8.3.36'],
  // The kernel's: 5.13.19 < 5.14 ends where the next series starts, which isn't a fix.
  [[{ status: 'affected', version: '5.10.67', lessThan: '5.10.271', versionType: 'semver' }, { status: 'affected', version: '5.13.19', lessThan: '5.14', versionType: 'semver' }], null],
  // No start to tell the branch by, a jump of more than one number, a comma.
  [[{ status: 'affected', lessThan: '8.2.35' }, { status: 'affected', version: '8.3.*', lessThan: '8.3.36' }], null],
  [[{ status: 'affected', version: '8.2.*', lessThan: '8.2.35.1' }, { status: 'affected', version: '8.3.*', lessThan: '8.3.36' }], null],
  [[{ status: 'affected', version: '8.2.*', lessThan: '8.2.35' }, { status: 'affected', version: '8.3.*', lessThan: '8.3.3,6' }], null],
  // Git ranges, wildcards and unaffected entries never count.
  [[...GIT_RANGES, { status: 'affected', version: '1.0', lessThan: '1.*' }, { status: 'unaffected', version: '0', lessThan: '1.0' }], null],
  // More branches than MAX_FIXES: none, rather than some.
  [Array.from({ length: 9 }, (_, i) => ({ status: 'affected', version: `1.${i}.*`, lessThan: `1.${i}.9` })), null],
  [[null, 'x', { status: 'affected', version: 1, lessThan: 2 }], null],
];

describe('fixed versions', () => {
  it('keeps one fix per release branch only when each is that branch plus one number', () => {
    for (const [ranges, want] of FIX_CASES) expect(fixedVersionOf(ranges)).toBe(want);
    expect(fixedVersionOf(Array.from({ length: MAX_FIXES }, (_, i) => ({ status: 'affected', version: `1.${i}.*`, lessThan: `1.${i}.9` })))).not.toBeNull();
  });

  it('gives a version the fix on its own branch, and every fix when none is', () => {
    const fixes = splitFixes('8.2.35, 8.3.36, 8.4.27, 8.5.12');
    expect(fixes).toEqual(['8.2.35', '8.3.36', '8.4.27', '8.5.12']);
    expect(fixesFor('8.3.10', fixes)).toEqual(['8.3.36']);
    expect(fixesFor('8.3', fixes)).toEqual(['8.3.36']);
    // Past its branch's fix: still that fix, never hidden.
    expect(fixesFor('8.3.40', fixes)).toEqual(['8.3.36']);
    expect(fixesFor('8.1.2', fixes)).toEqual(fixes);
    expect(fixesFor('8', fixes)).toEqual(fixes);
    expect(fixesFor(null, fixes)).toEqual(fixes);
    expect(fixesFor('1.2.3', ['2.5.48'])).toEqual(['2.5.48']);
    expect(splitFixes(null)).toEqual([]);
    expect(splitFixes('2.5.48')).toEqual(['2.5.48']);
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

describe('a product fixed on several branches', () => {
  const NOW = new Date('2026-10-22T00:00:00Z');
  const phpCve: VulnPatch = {
    source: 'cve',
    id: 'CVE-2026-109618',
    aliases: [],
    fields: { title: 'RCE via OOM corruption', publishedAt: '2026-10-21T13:48:34.845Z', cvssScore: 9.2, cvssVector: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' },
    affected: [{ kind: 'product', vendor: 'php_group', product: 'php', label: 'PHP Group PHP', ranges: PHP_RANGES, fixedVersion: fixedVersionOf(PHP_RANGES) }],
  };

  beforeEach(async () => {
    await resetDb();
    await applyPatches(store(), [phpCve], { now: NOW, windowStart: '2026-07-24T00:00:00.000Z', epssEvents: true });
  });

  const feed = (stack: string) => matchStack(store(), parseStack(stack), { now: NOW, days: 30, osv: { affecting: async () => new Map() } });

  it('names the fix on the version’s branch, so the item counts as fixable', async () => {
    const r = await feed('p:php_group/php@8.3.10');
    expect(r.results[0]).toMatchObject({ id: 'CVE-2026-109618', fixedVersions: ['8.3.36'], mitigation: null });
    expect(r.fixFirst[0]).toMatchObject({ item: 'p:php_group/php@8.3.10', fixable: 1 });
  });

  it('names every branch’s fix when no version is given', async () => {
    expect((await feed('p:php_group/php')).results[0]!.fixedVersions).toEqual(['8.2.35', '8.3.36', '8.4.27', '8.5.12']);
  });

  it('backfills existing rows exactly as ingest derives them (migration 0013)', async () => {
    const migration = env.TEST_MIGRATIONS.find((m) => m.name.startsWith('0013'))!;
    const backfill = migration.queries.find((q) => q.includes('UPDATE affected SET fixed_version'))!;
    await env.DB.exec('DELETE FROM affected');
    await env.DB.batch(
      FIX_CASES.map(([r], i) =>
        env.DB.prepare("INSERT INTO affected (vuln_id, source, kind, vendor, product, label, ranges) VALUES (?, 'cve', 'product', 'v', 'p', 'P', ?)").bind(`CVE-2026-1${String(i).padStart(4, '0')}`, JSON.stringify(r)),
      ),
    );
    // A row that already has a fix keeps it.
    await env.DB.prepare("INSERT INTO affected (vuln_id, source, kind, vendor, product, label, ranges, fixed_version) VALUES ('CVE-2026-19999', 'cve', 'product', 'v', 'p', 'P', ?, '9.9')").bind(JSON.stringify(PHP_RANGES)).run();
    await env.DB.prepare(backfill).run();
    const got = await rows<{ fixed_version: string | null }>('SELECT fixed_version FROM affected ORDER BY vuln_id');
    // A single bound was already stored by ingest, so the backfill leaves it alone.
    const want = FIX_CASES.map(([r]) => fixedVersionOf(r)).map((f) => (f && f.includes(', ') ? f : null));
    expect(got.map((r) => r.fixed_version)).toEqual([...want, '9.9']);
  });
});
