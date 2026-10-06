import { describe, expect, it } from 'vitest';
import { assess, comparePriority, fixFirst, reach, severity, type Assessment, type Signals } from '../src/match/priority';

const base: Signals = { kevAddedAt: null, knownRansomware: false, epss: null, cvss: null, cvssVector: null, ssvc: null };
const ssvc = (exploitation: string | null, automatable: string | null = 'no', technicalImpact: string | null = 'partial') => ({
  exploitation,
  automatable,
  technicalImpact,
});

/** Network, no login, no user action. */
const OPEN = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';

describe('reach: what stands between an attacker and the bug', () => {
  it('finds no barriers on a network bug that needs no login or help', () => {
    expect(reach(OPEN)).toEqual({ barriers: [] });
    expect(reach('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/AU:Y')).toEqual({ barriers: [] });
    // Metrics out of the standard order, as some records have them.
    expect(reach('CVSS:3.0/UI:N/C:H/PR:N/AV:N/AC:H/S:U/I:H/A:H')).toEqual({ barriers: [] });
  });

  it('names each barrier', () => {
    expect(reach('CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toEqual({ barriers: ['local access'] });
    expect(reach('CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toEqual({ barriers: ['local access'] });
    expect(reach('CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H')).toEqual({ barriers: ['adjacent network access', 'a login', 'user action'] });
    expect(reach('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toEqual({ barriers: ['user action'] });
  });

  it('reads nothing from a missing, unversioned or partial vector', () => {
    expect(reach(null)).toBeNull();
    expect(reach('')).toBeNull();
    expect(reach('AV:N/AC:L/Au:N/C:P/I:P/A:P')).toBeNull();
    expect(reach('CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P')).toBeNull();
    expect(reach('CVSS:3.1/AV:N/AC:L/UI:N')).toBeNull();
    expect(reach('CVSS:3.1/AV/PR/UI//__proto__:x')).toBeNull();
  });
});

describe('assess: priority bands', () => {
  it('acts on KEV or on CISA-reported active exploitation, whatever the severity', () => {
    expect(assess({ ...base, kevAddedAt: '2026-10-01', cvss: 4 }).priority).toBe('act');
    expect(assess({ ...base, ssvc: ssvc('active') }).priority).toBe('act');
  });

  it('attends to likely exploitation, critical severity, or a PoC that is automatable or total-impact', () => {
    expect(assess({ ...base, epss: 0.1 }).priority).toBe('attend');
    expect(assess({ ...base, cvss: 9.0, epss: 0.001 }).priority).toBe('attend');
    expect(assess({ ...base, ssvc: ssvc('poc', 'yes') }).priority).toBe('attend');
    expect(assess({ ...base, ssvc: ssvc('PoC', 'no', 'Total') }).priority).toBe('attend');
  });

  it('attends to a critical only when an attacker can reach it', () => {
    const critical = { ...base, cvss: 9.0, epss: 0.001 };
    expect(assess({ ...critical, cvssVector: OPEN }).priority).toBe('attend');
    expect(assess({ ...critical, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' }).priority).toBe('watch');
    expect(assess({ ...critical, cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' }).priority).toBe('watch');
    expect(assess({ ...critical, cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }).priority).toBe('watch');
    // CISA judging it automatable outweighs the vector.
    expect(assess({ ...critical, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', ssvc: ssvc('none', 'yes') }).priority).toBe('attend');
    // No vector to read: the critical keeps the benefit of the doubt.
    expect(assess({ ...critical, cvssVector: 'AV:N/AC:L/Au:N/C:C/I:C/A:C' }).priority).toBe('attend');
  });

  it('watches CVSS 8.0 to 8.9, a bare PoC, or automatable with total impact', () => {
    expect(assess({ ...base, cvss: 8.0, epss: 0.001 }).priority).toBe('watch');
    expect(assess({ ...base, cvss: 8.9, epss: 0.09 }).priority).toBe('watch');
    expect(assess({ ...base, ssvc: ssvc('poc') }).priority).toBe('watch');
    expect(assess({ ...base, ssvc: ssvc('none', 'yes', 'total') }).priority).toBe('watch');
  });

  it('tracks everything else, including total impact on its own', () => {
    expect(assess({ ...base, cvss: 7.9, epss: 0.09 }).priority).toBe('track');
    expect(assess({ ...base, ssvc: ssvc('none', 'no', 'total') }).priority).toBe('track');
    expect(assess(base).priority).toBe('track');
  });
});

describe('assess: score and reasons', () => {
  it('multiplies threat by impact, with KEV as full threat', () => {
    expect(assess({ ...base, kevAddedAt: '2026-10-01', cvss: 9.1 }).score).toBe(91);
    expect(assess({ ...base, epss: 0.4, cvss: 5 }).score).toBe(20);
    // No CVSS: impact is the middle of the scale.
    expect(assess({ ...base, kevAddedAt: '2026-10-01' }).score).toBe(50);
  });

  it('counts a PoC as at least 0.2 threat, and total impact as at least 0.9 impact', () => {
    expect(assess({ ...base, epss: 0.01, cvss: 5, ssvc: ssvc('poc') }).score).toBe(10);
    expect(assess({ ...base, epss: 0.5, cvss: 3, ssvc: ssvc('none', 'no', 'total') }).score).toBe(45);
  });

  it('boosts automatable and ransomware, capped at 100', () => {
    expect(assess({ ...base, epss: 0.4, cvss: 5, ssvc: ssvc('none', 'yes') }).score).toBe(25);
    expect(assess({ ...base, kevAddedAt: 'x', knownRansomware: true, cvss: 5 }).score).toBe(60);
    expect(assess({ ...base, kevAddedAt: 'x', knownRansomware: true, cvss: 10, ssvc: ssvc('active', 'yes') }).score).toBe(100);
  });

  it('explains itself, most important first', () => {
    expect(assess({ ...base, kevAddedAt: 'x', knownRansomware: true, epss: 0.5, cvss: 9.8, ssvc: ssvc('active', 'yes', 'total') }).reasons).toEqual([
      'On CISA KEV',
      'Used in ransomware',
      'EPSS 50%',
      'Automatable',
      'Total technical impact',
      'CVSS 9.8 (critical)',
    ]);
    expect(assess({ ...base, ssvc: ssvc('active') }).reasons).toEqual(['Active exploitation (CISA)']);
    // Reachability is explained from CVSS 7.0 up, just before the score.
    expect(assess({ ...base, cvss: 7.0, cvssVector: OPEN }).reasons).toEqual(['Reachable over the network without a login', 'CVSS 7.0 (high)']);
    expect(assess({ ...base, cvss: 9.8, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H' }).reasons).toEqual(['Needs a login and user action', 'CVSS 9.8 (critical)']);
    expect(assess({ ...base, cvss: 6.9, cvssVector: OPEN }).reasons).toEqual(['CVSS 6.9 (medium)']);
    expect(assess({ ...base, epss: 0.123, ssvc: ssvc('poc') }).reasons).toEqual(['EPSS 12%', 'Proof-of-concept exploit']);
    expect(assess(base).reasons).toEqual([]);
  });

  it('uses the CVSS qualitative bands', () => {
    expect([10, 9, 8.9, 7, 6.9, 4, 3.9, 0.1, 0].map(severity)).toEqual(['critical', 'critical', 'high', 'high', 'medium', 'medium', 'low', 'low', 'none']);
  });

  it('never lets a score lift a result above a more urgent band', () => {
    const act: Assessment = { priority: 'act', score: 5, reasons: [] };
    const watch: Assessment = { priority: 'watch', score: 99, reasons: [] };
    expect([watch, act].sort(comparePriority)).toEqual([act, watch]);
  });
});

describe('fixFirst', () => {
  const r = (id: string, priority: Assessment['priority'], score: number, matched: string[], fixed: string[] = []) => ({
    id,
    matched,
    fixedVersions: fixed,
    assessment: { priority, score, reasons: [] },
  });

  it('ranks items by their most urgent band, then by summed score', () => {
    const ranked = fixFirst([
      r('CVE-1', 'watch', 95, ['npm:a@1']),
      r('CVE-2', 'watch', 90, ['npm:a@1'], ['1.2.0']),
      r('CVE-3', 'act', 20, ['p:x/y']),
      r('CVE-4', 'track', 1, ['npm:a@1', '?p:f5/nginx']),
      r('CVE-5', 'attend', 30, ['?p:f5/nginx'], ['1.27.1']),
    ]);
    expect(ranked).toEqual([
      { item: 'p:x/y', score: 20, counts: { act: 1, attend: 0, watch: 0, track: 0 }, vulns: ['CVE-3'], fixable: 0 },
      { item: '?p:f5/nginx', score: 31, counts: { act: 0, attend: 1, watch: 0, track: 1 }, vulns: ['CVE-5', 'CVE-4'], fixable: 1 },
      { item: 'npm:a@1', score: 186, counts: { act: 0, attend: 0, watch: 2, track: 1 }, vulns: ['CVE-1', 'CVE-2', 'CVE-4'], fixable: 1 },
    ]);
  });

  it('handles an empty stack', () => {
    expect(fixFirst([])).toEqual([]);
  });
});

describe('assess: unscored CVEs', () => {
  it('gives a CVE that EPSS has not scored yet a small threat, so severity still orders it', () => {
    expect(assess({ ...base, cvss: 9.5 }).score).toBe(1);
    expect(assess({ ...base, cvss: 5 }).score).toBe(0.5);
    expect(assess({ ...base, epss: 0, cvss: 9.5 }).score).toBe(0);
  });
});
