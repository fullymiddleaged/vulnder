import { describe, expect, it } from 'vitest';
import { recentKev, targetedName, targetedText, TARGETED_DAYS } from '../src/match/targeted';

const NOW = new Date('2026-10-17T12:00:00Z');
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

describe('recentKev: an item’s CVEs added to KEV lately', () => {
  it('keeps the last 90 days, newest first, ID order on the same day', () => {
    const got = recentKev(
      [
        { id: 'CVE-2026-0003', kev_added_at: daysAgo(10) },
        { id: 'CVE-2026-0002', kev_added_at: daysAgo(1) },
        { id: 'CVE-2026-0001', kev_added_at: daysAgo(1) },
        { id: 'CVE-2026-0004', kev_added_at: null },
      ],
      NOW,
    );
    expect(got).toEqual([
      { id: 'CVE-2026-0001', addedAt: '2026-10-16' },
      { id: 'CVE-2026-0002', addedAt: '2026-10-16' },
      { id: 'CVE-2026-0003', addedAt: '2026-10-07' },
    ]);
  });

  it('counts day 89 and today, not day 90 or a date ahead', () => {
    const ids = (v: { id: string; kev_added_at: string | null }[]) => recentKev(v, NOW).map((k) => k.id);
    expect(TARGETED_DAYS).toBe(90);
    expect(ids([{ id: 'in', kev_added_at: daysAgo(89) }])).toEqual(['in']);
    expect(ids([{ id: 'today', kev_added_at: daysAgo(0) }])).toEqual(['today']);
    expect(ids([{ id: 'out', kev_added_at: daysAgo(90) }])).toEqual([]);
    expect(ids([{ id: 'ahead', kev_added_at: daysAgo(-1) }])).toEqual([]);
    expect(ids([])).toEqual([]);
  });
});

describe('targeted wording', () => {
  it('names the product or package without version or tags', () => {
    expect(targetedName({ items: ['p:ivanti/connect_secure@22.7;network;edge'] })).toBe('ivanti/connect_secure');
    expect(targetedName({ items: ['npm:next@14.2.3'] })).toBe('next');
    expect(targetedName({ items: ['not a stack item'] })).toBe('not a stack item');
    // A listed CVE's product goes by its label.
    expect(targetedName({ items: ['p:ivanti/connect_secure'], label: 'Ivanti Connect Secure' })).toBe('Ivanti Connect Secure');
  });

  it('says how many and the latest, and stays on KEV’s word', () => {
    const one = targetedText({ items: ['p:cisco/ios_xe'], kev: [{ id: 'CVE-2026-1005', addedAt: '2026-10-16' }] });
    expect(one[0]).toBe('CISA added one of its CVEs to its Known Exploited Vulnerabilities catalog in the last 90 days, most recently CVE-2026-1005 on 2026-10-16.');
    const two = targetedText({
      items: ['p:cisco/ios_xe'],
      kev: [
        { id: 'CVE-2026-1005', addedAt: '2026-10-16' },
        { id: 'CVE-2026-1001', addedAt: '2026-09-01' },
      ],
    });
    expect(two[0]).toContain('CISA added 2 of its CVEs');
    // Never calls EPSS or anything else "exploited"; never claims more than the backtest showed.
    expect(two.join(' ')).not.toMatch(/EPSS|will be exploited|guarantee/i);
  });
});
