import { describe, expect, it } from 'vitest';
import {
  CVE_ID,
  ecosystemFromCollectionUrl,
  ecosystemFromGithub,
  GHSA_ID,
  normalizeKey,
  normalizePackageName,
  parseCpe,
} from '../src/lib/normalize';
import { nextDay, toIso } from '../src/lib/time';

describe('normalizeKey', () => {
  it('makes CPE-style keys', () => {
    expect(normalizeKey('Cisco IOS XE')).toBe('cisco_ios_xe');
    expect(normalizeKey('  Zammad GmbH ')).toBe('zammad_gmbh');
    expect(normalizeKey('Café-Software')).toBe('cafe_software');
  });

  it('treats placeholders as missing', () => {
    for (const v of ['n/a', 'N/A', '', '  ', '*', '-', 'unknown', null, undefined]) expect(normalizeKey(v)).toBeNull();
  });
});

describe('parseCpe', () => {
  it('reads vendor and product', () => {
    expect(parseCpe('cpe:2.3:a:misp:misp:*:*:*:*:*:*:*:*')).toEqual({ vendor: 'misp', product: 'misp' });
    expect(parseCpe('cpe:2.3:o:cisco:ios_xe:17.3:*:*:*:*:*:*:*')).toEqual({ vendor: 'cisco', product: 'ios_xe' });
  });

  it('handles escaped characters and wildcards', () => {
    expect(parseCpe('cpe:2.3:a:foo\\:bar:baz:1:*:*:*:*:*:*:*')).toEqual({ vendor: 'foo_bar', product: 'baz' });
    expect(parseCpe('cpe:2.3:a:*:*:*:*:*:*:*:*:*:*')).toBeNull();
    expect(parseCpe('cpe:/a:apache:http_server:2.4')).toBeNull();
  });
});

describe('package names', () => {
  it('follows each registry', () => {
    expect(normalizePackageName('PyPI', 'Django_REST.framework')).toBe('django-rest-framework');
    expect(normalizePackageName('npm', '@Scope/Pkg')).toBe('@scope/pkg');
    expect(normalizePackageName('Go', 'github.com/Foo/Bar')).toBe('github.com/Foo/Bar');
    expect(normalizePackageName('Maven', 'org.Yamcs:yamcs-core')).toBe('org.Yamcs:yamcs-core');
  });

  it('maps GitHub ecosystems to OSV names', () => {
    expect(ecosystemFromGithub('pip')).toBe('PyPI');
    expect(ecosystemFromGithub('rust')).toBe('crates.io');
    expect(ecosystemFromGithub('composer')).toBe('Packagist');
    expect(ecosystemFromGithub('erlang')).toBe('Hex');
    expect(ecosystemFromGithub('other')).toBeNull();
  });

  it('maps registry URLs to ecosystems', () => {
    expect(ecosystemFromCollectionUrl('https://www.npmjs.com')).toBe('npm');
    expect(ecosystemFromCollectionUrl('https://registry.npmjs.org')).toBe('npm');
    expect(ecosystemFromCollectionUrl('https://pypi.org/simple')).toBe('PyPI');
    expect(ecosystemFromCollectionUrl('https://repo.maven.apache.org/maven2/')).toBe('Maven');
    expect(ecosystemFromCollectionUrl('https://example.com')).toBeNull();
    expect(ecosystemFromCollectionUrl('not a url')).toBeNull();
  });
});

describe('IDs', () => {
  it('accepts CVE IDs with 4 or more digits', () => {
    expect(CVE_ID.test('CVE-2026-1234')).toBe(true);
    expect(CVE_ID.test('CVE-2026-105096')).toBe(true);
    expect(CVE_ID.test('CVE-2026-123')).toBe(false);
    expect(CVE_ID.test('cve-2026-1234')).toBe(false);
  });

  it('accepts GHSA IDs', () => {
    expect(GHSA_ID.test('GHSA-hmqg-cxww-wqhq')).toBe(true);
    expect(GHSA_ID.test('GHSA-aaaa-bbbb-cccc')).toBe(false);
  });
});

describe('time', () => {
  it('normalises dates and timestamps', () => {
    expect(toIso('2026-10-02')).toBe('2026-10-02T00:00:00.000Z');
    expect(toIso('2026-10-03T09:47:38Z')).toBe('2026-10-03T09:47:38.000Z');
    expect(toIso('garbage')).toBeNull();
    expect(toIso(null)).toBeNull();
  });

  it('rolls over months and years', () => {
    expect(nextDay('2026-09-30')).toBe('2026-10-01');
    expect(nextDay('2026-12-31')).toBe('2027-01-01');
  });
});
