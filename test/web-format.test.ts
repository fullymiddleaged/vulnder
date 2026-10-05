import { describe, expect, it } from 'vitest';
import { ago, describeChange, ordinal, pct } from '../web/format';

describe('UI formatting', () => {
  it('writes percentages with sensible precision', () => {
    expect(pct(0.45)).toBe('45.0%');
    expect(pct(0.1)).toBe('10.0%');
    expect(pct(0.0042)).toBe('0.42%');
  });

  it('writes ordinals', () => {
    expect([1, 2, 3, 4, 11, 12, 13, 21, 22, 97, 100].map(ordinal)).toEqual(['1st', '2nd', '3rd', '4th', '11th', '12th', '13th', '21st', '22nd', '97th', '100th']);
  });

  it('writes relative times', () => {
    const now = Date.parse('2026-10-05T12:00:00Z');
    expect(ago('2026-10-05T11:15:00Z', now)).toBe('45 min ago');
    expect(ago('2026-10-05T07:00:00Z', now)).toBe('5 h ago');
    expect(ago('2026-10-01T12:00:00Z', now)).toBe('4 days ago');
  });

  it('never calls an EPSS change exploitation', () => {
    const base = { vulnId: 'CVE-2026-1', occurredAt: '2026-10-05T00:00:00Z', title: 'Bug' };
    expect(describeChange({ ...base, type: 'epss_crossed', detail: { to: 0.42 } })).toBe('CVE-2026-1: Bug: EPSS rose to 42.0% (predicted, not observed, exploitation).');
    expect(describeChange({ ...base, type: 'kev_added', detail: {} })).toMatch(/added to CISA KEV \(known exploited\)/);
    expect(describeChange({ ...base, type: 'fix_released', detail: { package: 'next', fixedVersion: '14.2.5' } })).toBe('CVE-2026-1: Bug: fix released in next 14.2.5.');
    expect(describeChange({ ...base, title: null, type: 'published', detail: {} })).toBe('CVE-2026-1 was published.');
  });
});
