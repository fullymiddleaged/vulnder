import { describe, expect, it } from 'vitest';
import { daysBetween, lev, levTerm } from '../src/lib/lev';

const NOW = new Date('2026-10-07T15:00:00Z');

describe('lev: NIST CSWP 41 LEV2', () => {
  it('matches 1 − Π(1 − epss/30) over the held days, today included', () => {
    // 0.3 held since 28 Sep: 28 Sep to 7 Oct is 10 days.
    expect(lev(0, 0.3, '2026-09-28', NOW)).toBeCloseTo(1 - (1 - 0.3 / 30) ** 10, 12);
  });

  it('adds the stored days before epss_date', () => {
    const before = levTerm(0.6, 20);
    expect(lev(before, 0.01, '2026-10-07', NOW)).toBeCloseTo(1 - (1 - 0.6 / 30) ** 20 * (1 - 0.01 / 30), 12);
  });

  it('keeps a cooled score likely exploited: weeks at 60% then 1% now', () => {
    expect(lev(levTerm(0.6, 20), 0.01, '2026-10-01', NOW)!).toBeGreaterThan(0.3);
  });

  it('stays below EPSS for a score held under 30 days, and grows past it after', () => {
    expect(lev(0, 0.1, '2026-10-07', NOW)!).toBeLessThan(0.1);
    expect(lev(0, 0.1, '2026-07-09', NOW)!).toBeGreaterThan(0.2);
  });

  it('is null with no score and no history, and the history alone otherwise', () => {
    expect(lev(0, null, null, NOW)).toBeNull();
    expect(lev(levTerm(0.3, 10), null, null, NOW)).toBeCloseTo(1 - (1 - 0.01) ** 10, 12);
  });

  it('stays finite and inside [0, 1] for out-of-range input', () => {
    for (const p of [-1, 0, 1, 2, Number.NaN]) {
      const v = lev(0, p, '2026-01-01', NOW);
      expect(v === null || (v >= 0 && v <= 1)).toBe(true);
    }
    expect(levTerm(0.5, -3)).toBe(0);
    expect(levTerm(0.5, Number.NaN)).toBe(0);
  });
});

describe('daysBetween', () => {
  it('counts whole UTC days and never goes negative', () => {
    expect(daysBetween('2026-09-24', '2026-10-04')).toBe(10);
    expect(daysBetween('2026-10-04', '2026-10-04T23:59:59Z')).toBe(0);
    expect(daysBetween('2026-10-04', '2026-10-01')).toBe(0);
    expect(daysBetween('nonsense', '2026-10-01')).toBe(0);
  });
});
