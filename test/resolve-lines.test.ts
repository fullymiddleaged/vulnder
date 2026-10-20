import { describe, expect, it } from 'vitest';
import { parseStack } from '../src/stack/format';
import { fallbackKey, forVersion, inLine, kernelSeries, lineFor, lineRanges, perRelease, PRODUCT_LINES } from '../src/resolve/lines';

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

  it('knows AI runtimes and coding agents under every vendor their CVEs are filed under', () => {
    expect(keysOf('Ollama')).toEqual(['ollama/ollama', 'ollama_ai/ollama']);
    expect(keysOf('vLLM')).toContain('vllm_project/vllm');
    expect(keysOf('LiteLLM')).toEqual(keysOf('LiteLLM proxy'));
    expect(keysOf('Open WebUI')).toEqual(['open_webui/open_webui']);
    expect(keysOf('OpenWebUI')).toBe(keysOf('Open WebUI'));
    expect(keysOf('AnythingLLM')).toContain('mintplex_labs/anything_llm');
    expect(keysOf('Cursor')).toEqual(['cursor/cursor', 'anysphere_inc/cursor']);
    expect(keysOf('Claude Code')).toContain('anthropics/claude_code');
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

  it('falls back to the leading parts with digits: an edition or update after the release', () => {
    expect(forVersion(rows, '9 Server').map((r) => r.product)).toEqual(['red_hat_enterprise_linux_9']);
    expect(forVersion(rows, '24H2 Pro').map((r) => r.product)).toEqual(['windows_11_version_24h2']);
    // Only words before the first one without a digit count.
    expect(forVersion(rows, 'Pro 9')).toEqual([]);
  });

  it('tells per-release lines from ones with a single product', () => {
    expect(perRelease(rows)).toBe(true);
    expect(perRelease([{ product: 'ios_xe' }, { product: 'cisco_ios_xe_software' }])).toBe(false);
  });

  it('gives a name that says its release that release', () => {
    expect(lineFor('Windows 10', null)?.version).toBe('10');
    expect(lineFor('Win11', null)?.version).toBe('11');
    // A version written after it still wins.
    expect(lineFor('Windows 10 22H2', null)?.version).toBe('22h2');
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

  it("finds the kernel series a distribution's release ships, and none it doesn't know", () => {
    const series = (name: string, release: string | null) => kernelSeries(lineFor(name, null)!.line, release);
    expect(series('Ubuntu', '24.04')).toBe('6.8');
    expect(series('Ubuntu', '24.04.3')).toBe('6.8');
    expect(series('RHEL', '9.4')).toBe('5.14');
    expect(series('Debian', '12')).toBe('6.1');
    expect(series('AlmaLinux', '10')).toBe('6.12');
    // Not listed, not given, or a line with no table: no guess.
    expect(series('Ubuntu', '23.10')).toBeNull();
    expect(series('Ubuntu', null)).toBeNull();
    expect(series('Fedora', '42')).toBeNull();
    expect(series('Ubuntu', '__proto__')).toBeNull();
    expect(series('Ubuntu', 'constructor')).toBeNull();
  });
});
