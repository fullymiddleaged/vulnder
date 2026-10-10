import { describe, expect, it } from 'vitest';
import { eolStatements, parseEol } from '../src/ingest/eol';
import { fixFirst, type Assessment } from '../src/match/priority';
import { supportFor, supportText, type CveSupport, type EolRelease } from '../src/match/support';
import { candidateReleases, EOL_PRODUCTS, EOL_SLUGS, eolTarget, releaseMatches, showRelease, versionPrefix } from '../src/stack/eol';
import { parseStack } from '../src/stack/format';
import { eolFull } from './helpers/fixtures';

// The day this was written: Windows Server 2012 R2's paid ESU ends two days later.
const NOW = new Date('2026-10-11T12:00:00Z');
const { rows: RELEASES, missing } = parseEol(eolFull);
const item = (s: string) => parseStack(s)[0]!;
const support = (s: string, now = NOW, cve: CveSupport | null = null) => supportFor(item(s), RELEASES, cve, now);

describe('the endoflife.date mapping', () => {
  it('names only products endoflife.date lists', () => {
    expect(missing).toEqual([]);
    expect(EOL_SLUGS.length).toBeGreaterThan(15);
  });

  it('reads a release from the key, or else from the version', () => {
    expect(eolTarget(item('p:microsoft/windows_server_2012_r2_server_core_installation'))).toMatchObject({ slug: 'windows-server', prefixes: ['2012_r2'], release: '2012 R2' });
    expect(eolTarget(item('p:microsoft/windows_server_2008_service_pack_2'))).toMatchObject({ prefixes: ['2008_sp2'] });
    expect(eolTarget(item('p:microsoft/windows_server_2022_23h2_edition_server_core_installation'))).toMatchObject({ prefixes: ['23h2'] });
    expect(eolTarget(item('p:microsoft/windows_10_version_22h2'))).toMatchObject({ slug: 'windows', prefixes: ['10_22h2'], release: '10 22H2' });
    expect(eolTarget(item('p:microsoft/windows@7'))).toMatchObject({ slug: 'windows', prefixes: ['7'], release: '7' });
    expect(eolTarget(item('p:canonical/ubuntu_18_04_lts'))).toMatchObject({ slug: 'ubuntu', prefixes: ['18_04'], release: '18.04' });
    expect(eolTarget(item('p:debian/debian_linux@10'))).toMatchObject({ slug: 'debian', prefixes: ['10'] });
    expect(eolTarget(item('p:microsoft/microsoft_sql_server_2014_service_pack_3_for_x64_based_systems_gdr'))).toMatchObject({
      slug: 'mssqlserver',
      prefixes: ['12_0_sp3'],
      release: '2014 SP3',
    });
    expect(eolTarget(item('p:microsoft/sql_server@2019'))).toMatchObject({ prefixes: ['15_0'], release: '2019' });
    expect(eolTarget(item('p:suse/suse_linux_enterprise_server_15_sp6_ltss'))).toMatchObject({ slug: 'sles', prefixes: ['15_6'], esu: true });
  });

  it('lets a version narrow the key, but not contradict it', () => {
    expect(eolTarget(item('p:red_hat/red_hat_enterprise_linux_9@9.4'))).toMatchObject({ prefixes: ['9_4'], release: '9.4' });
    expect(eolTarget(item('p:microsoft/windows_10_version_22h2@10'))).toMatchObject({ prefixes: ['10_22h2'] });
  });

  it('names nothing for a close match unless the user gave a version', () => {
    expect(eolTarget(item('?p:microsoft/windows_server_2012_r2'))).toBeNull();
    expect(eolTarget(item('?p:microsoft/windows_10_version_1607@10'))).toMatchObject({ prefixes: ['10'], release: '10' });
  });

  it('has no entry for products it doesn’t map, or for packages', () => {
    expect(eolTarget(item('p:linux/linux'))).toBeNull();
    expect(eolTarget(item('p:microsoft/sql_server_management_studio_22'))).toBeNull();
    expect(eolTarget(item('p:f5/big_ip_next_cnf'))).toBeNull();
    expect(eolTarget(item('npm:express@4.18.2'))).toBeNull();
  });

  it('matches release names by whole parts', () => {
    expect(versionPrefix('18.04.6')).toBe('18_04_6');
    expect(versionPrefix('10 Pro')).toBe('10');
    expect(versionPrefix('latest')).toBeNull();
    expect(releaseMatches('10_1607_e', '10_1607')).toBe(true);
    expect(releaseMatches('18_04', '18_04_6')).toBe(true);
    expect(releaseMatches('10_1607', '10_16')).toBe(false);
    expect(showRelease('2012_r2')).toBe('2012 R2');
    expect(showRelease('15_6')).toBe('15.6');
  });

  it('leaves LTSC and IoT editions out unless they are named', () => {
    const win = RELEASES.filter((r) => r.slug === 'windows');
    const ten = candidateReleases(eolTarget(item('p:microsoft/windows@10'))!, win).map((r) => r.release);
    expect(ten).toContain('10_22h2');
    expect(ten.some((r) => /lts|iot/.test(r))).toBe(false);
  });

  it('keeps every regex anchored, so a key can only match whole', () => {
    for (const p of EOL_PRODUCTS) expect(p.keys.source.startsWith('^'), p.slug).toBe(true);
  });
});

describe('supportFor', () => {
  it('calls a named release past its end out of support', () => {
    expect(support('p:microsoft/windows@7')).toMatchObject({ state: 'eol', name: 'Windows 7', date: '2020-01-14', esu: false, source: 'endoflife' });
    expect(support('p:canonical/ubuntu_18_04_lts')).toMatchObject({ state: 'eol', name: 'Ubuntu 18.04', date: '2023-05-31', esuUntil: '2028-04-26' });
    expect(support('p:microsoft/windows_10_version_22h2')).toMatchObject({ state: 'eol', date: '2025-10-14', esuUntil: '2028-10-10' });
    expect(support('p:microsoft/microsoft_exchange_server_2016_cumulative_update_23')).toMatchObject({ state: 'eol', name: 'Exchange Server 2016' });
  });

  it('never calls a broad name out of support', () => {
    expect(support('p:microsoft/windows')).toBeNull();
    expect(support('p:apple/macos')).toBeNull();
    expect(support('p:microsoft/windows@11')).toBeNull();
    expect(support('?p:microsoft/windows_server_2012_r2')).toBeNull();
  });

  it('calls "Windows 10" out of support, but not "Windows 11"', () => {
    expect(support('?p:microsoft/windows_10_version_1607@10')).toMatchObject({ state: 'eol', name: 'Windows 10' });
    expect(support('?p:microsoft/windows_11_version_21h2@11')).toBeNull();
  });

  it('leaves a supported release alone', () => {
    expect(support('p:canonical/ubuntu_24_04_lts')).toBeNull();
    expect(support('p:microsoft/windows_server_2025')).toBeNull();
  });

  it('warns 90 days ahead', () => {
    // Windows 11 23H2: Home and Pro ended in 2025, Enterprise ends 2026-11-10.
    expect(support('p:microsoft/windows_11_version_23h2')).toMatchObject({ state: 'ending', date: '2026-11-10' });
    expect(support('p:microsoft/windows_11_version_23h2', new Date('2026-07-01T00:00:00Z'))).toBeNull();
  });

  it('counts paid extended support the user has, until it ends', () => {
    // Windows Server 2012 R2: extended support ended 2023-10-10, ESU ends 2026-10-13.
    expect(support('p:microsoft/windows_server_2012_r2')).toMatchObject({ state: 'eol', date: '2023-10-10', esuUntil: '2026-10-13' });
    expect(support('p:microsoft/windows_server_2012_r2;esu')).toMatchObject({ state: 'ending', date: '2026-10-13', esu: true });
    expect(support('p:microsoft/windows_server_2012_r2;esu', new Date('2026-10-14T00:00:00Z'))).toMatchObject({ state: 'eol', esu: true, date: '2026-10-13' });
    // Ubuntu 22.04 isn't past its end, so ESU doesn't change anything yet.
    expect(support('p:canonical/ubuntu_22_04_lts;esu')).toBeNull();
    // Ubuntu 20.04 with Ubuntu Pro: covered to 2030.
    expect(support('p:canonical/ubuntu_20_04_lts;esu')).toMatchObject({ state: 'covered', date: '2030-04-23' });
  });

  it('takes a SLES LTSS key as having extended support', () => {
    expect(support('p:suse/suse_linux_enterprise_server_15_sp4_ltss')).toMatchObject({ esu: true });
  });

  it('says BOD 26-02 for an edge device', () => {
    const s = support('p:fortinet/fortios@7.0.12')!;
    expect(s).toMatchObject({ state: 'eol', name: 'FortiOS 7.0.12', edge: true });
    expect(supportText(s).at(-1)).toContain('BOD 26-02');
  });

  it('uses a CVE’s unsupported-when-assigned tag where endoflife.date has nothing', () => {
    const tag: CveSupport = { key: 'trendnet/tew_827dru', last_cve: 'CVE-2026-9214', last_published: '2026-09-01T00:00:00Z', tagged: 1 };
    expect(support('p:trendnet/tew_827dru', NOW, tag)).toMatchObject({ state: 'eol', source: 'cve', cve: 'CVE-2026-9214', date: null });
    expect(support('p:trendnet/tew_827dru', NOW, { ...tag, tagged: 0 })).toBeNull();
    expect(support('?p:trendnet/tew_827dru', NOW, tag)).toBeNull();
    // endoflife.date's dates win: a supported Ubuntu stays supported.
    expect(support('p:canonical/ubuntu_24_04_lts', NOW, { ...tag, key: 'canonical/ubuntu_24_04_lts' })).toBeNull();
  });

  it('takes an undated end from endoflife.date’s own flag', () => {
    const rows: EolRelease[] = [{ slug: 'macos', release: '10_0', label: '10.0', eol_from: null, is_eol: 1, eoes_from: null }];
    expect(supportFor(item('p:apple/macos@10.0'), rows, null, NOW)).toMatchObject({ state: 'eol', date: null });
  });
});

describe('fixFirst with support', () => {
  const ranked = (priority: Assessment['priority'], score: number) => ({ priority, score, respondWithinHours: null });
  it('ranks an out-of-support item with Act and one losing support with Attend, ahead of its CVEs’ bands', () => {
    const results = [
      { id: 'CVE-1', matched: ['p:a/watched'], fixedVersions: [], assessment: ranked('watch', 50) },
      { id: 'CVE-2', matched: ['p:a/old'], fixedVersions: [], assessment: ranked('track', 5) },
      { id: 'CVE-3', matched: ['p:a/ending'], fixedVersions: [], assessment: ranked('track', 1) },
    ];
    const order = fixFirst(results, new Map([['p:a/old', 'eol'], ['p:a/ending', 'ending']])).map((f) => [f.item, f.support ?? null]);
    expect(order).toEqual([
      ['p:a/old', 'eol'],
      ['p:a/ending', 'ending'],
      ['p:a/watched', null],
    ]);
  });
});

describe('the daily diff', () => {
  const row = (release: string, eol_from: string | null): EolRelease => ({ slug: 'ubuntu', release, label: release, eol_from, is_eol: 0, eoes_from: null });
  it('writes only changed rows, and deletes releases gone upstream', () => {
    const stored = [row('18_04', '2023-05-31'), row('20_04', '2025-05-31'), row('99_99', null)];
    const fresh = [row('18_04', '2023-05-31'), row('20_04', '2025-06-30')];
    const { statements, rows } = eolStatements(stored, fresh, NOW);
    expect(rows).toBe(2);
    expect(statements).toHaveLength(2);
    expect(JSON.parse(statements[0]!.params[1] as string)).toEqual([row('20_04', '2025-06-30')]);
    expect(JSON.parse(statements[1]!.params[0] as string)).toEqual([['ubuntu', '99_99']]);
    expect(eolStatements(fresh, fresh, NOW)).toEqual({ statements: [], rows: 0 });
  });

  it('keeps a product endoflife.date stops listing', () => {
    expect(eolStatements([row('18_04', '2023-05-31')], [], NOW).rows).toBe(0);
  });

  it('skips releases it can’t read, and products it doesn’t map', () => {
    const { rows } = parseEol({ result: [{ name: 'ubuntu', releases: [{ name: '' }, { name: '18.04', eolFrom: 'not a date' }, { name: '20.04', eolFrom: '2025-05-31' }] }, { name: 'nginx', releases: [{ name: '1.0' }] }] });
    expect(rows).toEqual([{ slug: 'ubuntu', release: '20_04', label: null, eol_from: '2025-05-31', is_eol: 0, eoes_from: null }]);
    expect(() => parseEol({ nope: true })).toThrow();
  });
});
