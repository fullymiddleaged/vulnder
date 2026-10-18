import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { ROLE_ORDER, roleOf } from '../src/match/roles';

const ALL_HIGH = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const ONLY_A = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H';
const V4_ALL_HIGH = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';

describe('roleOf: what a CVE gives an attacker', () => {
  it('reads the CWE first', () => {
    expect(roleOf(['CWE-78'], null, null)).toBe('code-exec');
    expect(roleOf(['CWE-502'], null, null)).toBe('code-exec');
    expect(roleOf(['CWE-306'], null, null)).toBe('auth-bypass');
    expect(roleOf(['CWE-798'], null, null)).toBe('auth-bypass');
    expect(roleOf(['CWE-269'], null, null)).toBe('priv-esc');
    expect(roleOf(['CWE-22'], null, null)).toBe('info-leak');
    expect(roleOf(['CWE-89'], null, null)).toBe('info-leak');
    expect(roleOf(['CWE-400'], null, null)).toBe('dos');
  });

  it('takes the CWE over the title', () => {
    expect(roleOf(['CWE-400'], 'Remote code execution in Foo', null)).toBe('dos');
  });

  it('picks the role that gives the most when CWEs disagree, whatever their order', () => {
    expect(roleOf(['CWE-400', 'CWE-287', 'CWE-200'], null, null)).toBe('auth-bypass');
    expect(roleOf(['CWE-200', 'CWE-94'], null, null)).toBe('code-exec');
    expect(ROLE_ORDER[0]).toBe('code-exec');
  });

  it('counts memory corruption as code execution only when the vector rates everything high', () => {
    expect(roleOf(['CWE-787'], null, ALL_HIGH)).toBe('code-exec');
    expect(roleOf(['CWE-416'], null, V4_ALL_HIGH)).toBe('code-exec');
    expect(roleOf(['CWE-787'], null, ONLY_A)).toBe('dos');
    expect(roleOf(['CWE-787'], null, null)).toBe('other');
    // A gated CWE that doesn't pass leaves the decision to the rest.
    expect(roleOf(['CWE-787', 'CWE-200'], null, ONLY_A)).toBe('info-leak');
    expect(roleOf(['CWE-416'], 'Use-after-free leads to remote code execution', ONLY_A)).toBe('code-exec');
  });

  it('falls back to the title when no CWE says', () => {
    expect(roleOf([], 'Ivanti Connect Secure authentication bypass', null)).toBe('auth-bypass');
    expect(roleOf(['CWE-20'], 'Command injection in the web UI', null)).toBe('code-exec');
    expect(roleOf([], 'Windows Kernel Elevation of Privilege Vulnerability', null)).toBe('priv-esc');
    expect(roleOf([], 'Path traversal in file download', null)).toBe('info-leak');
    expect(roleOf([], 'Denial-of-service via crafted packet', null)).toBe('dos');
    expect(roleOf([], 'Stored XSS in comments', null)).toBe('other');
    expect(roleOf([], null, null)).toBe('other');
  });

  it("doesn't read inherited keys as CWEs", () => {
    expect(roleOf(['constructor', 'toString', '__proto__', 'hasOwnProperty'], null, null)).toBe('other');
  });

  it('never throws and always returns a role, whatever the input', () => {
    const roles = new Set(ROLE_ORDER);
    const text = fc.oneof(fc.string({ unit: 'binary', maxLength: 200 }), fc.constantFrom('', '__proto__', 'CWE-', 'CVSS:3.1/', 'CVSS:4.0/C:H/I:H/A:H'));
    fc.assert(
      fc.property(fc.array(text, { maxLength: 6 }), fc.option(text, { nil: null }), fc.option(text, { nil: null }), (cwe, title, vector) => {
        expect(roles.has(roleOf(cwe, title, vector))).toBe(true);
      }),
    );
  });

  it('stays fast on a huge title', () => {
    const start = performance.now();
    roleOf([], `${'remote '.repeat(100_000)}x`, null);
    expect(performance.now() - start).toBeLessThan(200);
  });
});
