import { deflateSync } from 'fflate';
import { describe, expect, it } from 'vitest';
import { COMPRESS_ABOVE, MAX_ITEMS, parseStack, serializeStack, StackFormatError, type StackItem } from '../src/stack/format';

describe('parseStack', () => {
  it('reads the example from the brief', () => {
    expect(parseStack('npm:next@14.2.3,pypi:fastapi,p:postgresql/postgresql@16,p:cisco/ios_xe')).toEqual([
      { kind: 'package', ecosystem: 'npm', name: 'next', version: '14.2.3' },
      { kind: 'product', vendor: 'cisco', product: 'ios_xe', version: null },
      { kind: 'product', vendor: 'postgresql', product: 'postgresql', version: '16' },
      { kind: 'package', ecosystem: 'PyPI', name: 'fastapi', version: null },
    ]);
  });

  it('handles npm scopes, Maven coordinates and Go modules', () => {
    expect(parseStack('npm:@angular/core@17.0.0')).toEqual([{ kind: 'package', ecosystem: 'npm', name: '@angular/core', version: '17.0.0' }]);
    expect(parseStack('npm:@angular/core')).toEqual([{ kind: 'package', ecosystem: 'npm', name: '@angular/core', version: null }]);
    expect(parseStack('maven:org.apache.logging.log4j:log4j-core@2.17.1')[0]).toMatchObject({ name: 'org.apache.logging.log4j:log4j-core', version: '2.17.1' });
    expect(parseStack('go:github.com/containers/podman/v5@v5.6.0')[0]).toMatchObject({ ecosystem: 'Go', name: 'github.com/containers/podman/v5', version: 'v5.6.0' });
  });

  it('normalises names and product keys', () => {
    expect(parseStack('PYPI:Django_REST.framework,p:Cisco/IOS XE')).toEqual([
      { kind: 'product', vendor: 'cisco', product: 'ios_xe', version: null },
      { kind: 'package', ecosystem: 'PyPI', name: 'django-rest-framework', version: null },
    ]);
  });

  it('deduplicates and sorts into one canonical form', () => {
    const a = serializeStack(parseStack('pypi:fastapi,npm:next,npm:next'));
    const b = serializeStack(parseStack(' npm:next , pypi:FastAPI '));
    expect(a).toBe('npm:next,pypi:fastapi');
    expect(b).toBe(a);
  });

  it('marks close matches with a leading ?', () => {
    expect(parseStack('?p:nginx/nginx,p:f5/nginx')).toEqual([
      { kind: 'product', vendor: 'f5', product: 'nginx', version: null },
      { kind: 'product', vendor: 'nginx', product: 'nginx', version: null, close: true },
    ]);
    expect(serializeStack(parseStack('?p:nginx/nginx@1.25,npm:next'))).toBe('npm:next,?p:nginx/nginx@1.25');
  });

  it('keeps the exact item when the same thing is both exact and close', () => {
    expect(serializeStack(parseStack('?p:cisco/ios_xe,p:cisco/ios_xe'))).toBe('p:cisco/ios_xe');
    expect(serializeStack(parseStack('p:cisco/ios_xe,?p:cisco/ios_xe'))).toBe('p:cisco/ios_xe');
  });

  it('unescapes commas and percent signs', () => {
    const items = parseStack('p:acme/widget%2C%20pro');
    expect(items).toEqual([{ kind: 'product', vendor: 'acme', product: 'widget_20pro', version: null }]);
  });

  it('round-trips through the compressed form', () => {
    const items: StackItem[] = Array.from({ length: 150 }, (_, i) => ({ kind: 'package', ecosystem: 'npm', name: `package-number-${i}`, version: '1.0.0' }));
    const s = serializeStack(items);
    expect(s.startsWith('~')).toBe(true);
    expect(parseStack(s)).toEqual(parseStack(items.map((i) => `npm:${(i as { name: string }).name}@1.0.0`).join(',')));
  });

  it('keeps short stacks plain', () => {
    let plain = '';
    for (let i = 0; plain.length < COMPRESS_ABOVE - 20; i++) plain += `${plain ? ',' : ''}npm:p${String(i).padStart(4, '0')}`;
    expect(plain.length).toBeLessThanOrEqual(COMPRESS_ABOVE);
    expect(serializeStack(parseStack(plain))).toBe(plain);
  });

  it(`accepts exactly ${MAX_ITEMS} items and rejects ${MAX_ITEMS + 1}`, () => {
    const list = (n: number) => Array.from({ length: n }, (_, i) => `npm:p${i}`).join(',');
    expect(parseStack(serializeStack(parseStack(list(MAX_ITEMS))))).toHaveLength(MAX_ITEMS);
    expect(() => parseStack(serializeStack(Array.from({ length: MAX_ITEMS + 1 }, (_, i) => ({ kind: 'package', ecosystem: 'npm', name: `p${i}`, version: null }))))).toThrow(/at most 200/);
  });

  it('rejects unknown prefixes and malformed items, naming them', () => {
    try {
      parseStack('npm:ok,bogus:x,p:noslash,npm:bad@ver sion');
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(StackFormatError);
      expect((e as StackFormatError).invalid).toEqual(['bogus:x', 'p:noslash', 'npm:bad@ver sion']);
    }
    expect(() => parseStack('')).toThrow(/empty/);
    expect(() => parseStack('v2;npm:next')).toThrow(StackFormatError);
  });

  it('does not treat object property names as prefixes', () => {
    for (const prefix of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
      expect(() => parseStack(`${prefix}:x`), prefix).toThrow(StackFormatError);
    }
  });

  it('rejects oversized and decompression-bomb input', () => {
    expect(() => parseStack('npm:x,'.repeat(3000))).toThrow(/longer than/);
    const bomb = deflateSync(new Uint8Array(10_000_000).fill(44)); // ten million commas
    let bin = '';
    for (const b of bomb) bin += String.fromCharCode(b);
    const b64 = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(() => parseStack(`~${b64}`)).toThrow(/too large/);
    expect(() => parseStack('~not*base64')).toThrow(/base64url/);
    expect(() => parseStack('~AAAA')).toThrow(StackFormatError);
  });
});
