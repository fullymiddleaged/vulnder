import { describe, expect, it } from 'vitest';
import { parseStack } from '../src/stack/format';
import { fallbackKey, forVersion, inLine, lineFor, lineRanges, PRODUCT_LINES } from '../src/resolve/lines';

const keysOf = (name: string, vendor: string | null = null) => lineFor(name, vendor)?.line.keys ?? null;
const RHEL = keysOf('RHEL')!;
const WINDOWS_SERVER = keysOf('Windows Server')!;

describe('lineFor', () => {
  it('knows acronyms and the names people use', () => {
    expect(RHEL).toContain('red_hat/red_hat_enterprise_linux_*');
    expect(keysOf('Red Hat Enterprise Linux')).toBe(RHEL);
    expect(keysOf('MSSQL')).toContain('microsoft/microsoft_sql_server_*');
    expect(keysOf('SCCM')).toBe(keysOf('MECM'));
    expect(keysOf('Apache')).toContain('apache_software_foundation/apache_http_server');
    // Active Directory, WSUS and Hyper-V CVEs are filed under Windows Server.
    for (const name of ['AD', 'Active Directory', 'WSUS', 'Hyper-V']) expect(keysOf(name), name).toBe(WINDOWS_SERVER);
  });

  it('splits a version off the end of the name, longest name first', () => {
    expect(lineFor('RHEL 8', null)).toEqual({ line: lineFor('RHEL', null)!.line, version: '8' });
    expect(lineFor('rhel8', null)?.version).toBe('8');
    expect(lineFor('Windows 11 24H2', null)).toEqual({ line: lineFor('Windows 11', null)!.line, version: '24h2' });
    expect(lineFor('Windows Server 2019', null)).toEqual({ line: lineFor('Windows Server', null)!.line, version: '2019' });
    expect(lineFor('RHEL', null)?.version).toBeNull();
  });

  it('uses only the vendor the model gave, so a first word is never taken for one', () => {
    expect(keysOf('Exchange', 'Microsoft')).toBe(keysOf('Microsoft Exchange'));
    expect(keysOf('Teams', 'Microsoft')).toContain('microsoft/microsoft_teams');
    // A bare "Teams" could be anyone's.
    expect(keysOf('Teams')).toBeNull();
    // "Azure AD" is Entra ID, not Active Directory with "Azure" in front.
    expect(keysOf('Azure AD')).toContain('microsoft/entra');
    expect(keysOf('Contoso AD')).toBeNull();
  });

  it('ignores names it does not know, and prototype keys', () => {
    for (const name of ['Postgres', 'Cisco switches', '', '__proto__', 'constructor', 'toString', 'hasOwnProperty 9']) {
      expect(lineFor(name, '__proto__'), name).toBeNull();
    }
  });
});

describe('inLine and lineRanges', () => {
  const line = lineFor('RHEL', null)!.line;

  it('takes whole keys exactly and prefixes only where keep allows', () => {
    expect(inLine(line, 'redhat/enterprise_linux')).toBe(true);
    expect(inLine(line, 'red_hat/red_hat_enterprise_linux_9')).toBe(true);
    // Add-ons sharing the prefix are left out.
    expect(inLine(line, 'red_hat/red_hat_enterprise_linux_9_4_update_services_for_sap_solutions')).toBe(false);
    expect(inLine(line, 'red_hat/red_hat_enterprise_linux_')).toBe(false);
    expect(inLine(line, 'redhat/enterprise_linux_desktop')).toBe(false);
  });

  it('reads each whole key alone and each prefix to its end', () => {
    expect(lineRanges(line)).toEqual([
      ['redhat/enterprise_linux', 'redhat/enterprise_linux '],
      ['red_hat/red_hat_enterprise_linux_', 'red_hat/red_hat_enterprise_linux`'],
    ]);
    // What a prefix matches sorts inside its range; its neighbours don't.
    const [, [from, to]] = lineRanges(line) as [[string, string], [string, string]];
    const inRange = (key: string) => key >= from && key < to;
    expect(['red_hat/red_hat_enterprise_linux_9', 'red_hat/red_hat_enterprise_linux_10_0_extended_update_support'].every(inRange)).toBe(true);
    expect(['red_hat/red_hat_enterprise_linux', 'red_hat/red_hat_enterprise_linuxx', 'red_hat/red_hat_openshift'].some(inRange)).toBe(false);
  });
});

describe('forVersion', () => {
  const rows = ['red_hat_enterprise_linux_8', 'red_hat_enterprise_linux_9', 'red_hat_enterprise_linux_10', 'windows_11_version_24h2'].map((product) => ({ product }));

  it('keeps the products whose key holds the version as whole segments', () => {
    expect(forVersion(rows, '9').map((r) => r.product)).toEqual(['red_hat_enterprise_linux_9']);
    expect(forVersion(rows, '1')).toEqual([]);
    expect(forVersion(rows, '24H2').map((r) => r.product)).toEqual(['windows_11_version_24h2']);
    expect(forVersion(rows, null)).toEqual([]);
  });
});

describe('PRODUCT_LINES', () => {
  it('gives each name one line', () => {
    const names = PRODUCT_LINES.flatMap((l) => l.names);
    expect(names.filter((n, i) => names.indexOf(n) !== i)).toEqual([]);
  });

  it('lists only keys a stack can hold', () => {
    for (const line of PRODUCT_LINES) {
      for (const key of line.keys) {
        expect(key.replace(/\*$/, ''), key).toMatch(/^[a-z0-9_]+\/[a-z0-9_]+$/);
        if (!key.endsWith('*')) expect(parseStack(`p:${key}`)[0], key).toMatchObject({ kind: 'product' });
      }
    }
  });

  it('watches the first whole key when the catalog has nothing for a line', () => {
    expect(fallbackKey(lineFor('IIS', null)!.line)).toBe('microsoft/internet_information_services');
    expect(fallbackKey(lineFor('Meraki', null)!.line)).toBeNull();
  });
});
