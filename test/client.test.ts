import { describe, expect, it } from 'vitest';
import { clientKey } from '../src/lib/client';

describe('clientKey', () => {
  it('keeps IPv4 addresses whole', () => {
    expect(clientKey('203.0.113.7')).toBe('203.0.113.7');
    expect(clientKey('::ffff:203.0.113.7')).toBe('203.0.113.7');
  });

  it('keys IPv6 by its /64, however it is written', () => {
    const key = '2001:db8:aa:1::/64';
    expect(clientKey('2001:db8:aa:1:0:0:0:1')).toBe(key);
    expect(clientKey('2001:db8:aa:1::ffff')).toBe(key);
    expect(clientKey('2001:0DB8:00AA:0001:dead:beef:1:2')).toBe(key);
    expect(clientKey('2001:db8:aa:2::1')).not.toBe(key);
    expect(clientKey('2001:db8::1')).toBe('2001:db8:0:0::/64');
    expect(clientKey('::1')).toBe('0:0:0:0::/64');
  });

  it('falls back to the raw value for anything malformed, and to "unknown" for nothing', () => {
    expect(clientKey(null)).toBe('unknown');
    expect(clientKey('')).toBe('unknown');
    expect(clientKey('1::2::3')).toBe('1::2::3');
    expect(clientKey('2001:db8:zz::1')).toBe('2001:db8:zz::1');
    expect(clientKey('1:2:3:4:5:6:7:8:9')).toBe('1:2:3:4:5:6:7:8:9');
  });
});
