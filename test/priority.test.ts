import { describe, expect, it } from 'vitest';
import { mitigationFor } from '../src/match/match';
import { assess, comparePriority, fixFirst, reach, severity, type Assessment, type Signals } from '../src/match/priority';

const base: Signals = { kevAddedAt: null, knownRansomware: false, epss: null, lev: null, exploitedSibling: null, cvss: null, cvssVector: null, ssvc: null };
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

  it('attends to a NIST LEV estimate of 20% or more, as a prediction, never as evidence', () => {
    const r = assess({ ...base, epss: 0.02, lev: 0.34, cvss: 6 });
    expect(r.priority).toBe('attend');
    expect(r.reasons[0]).toBe('NIST LEV estimate: 34% chance it has already been exploited');
    // Its threat is the LEV, since that beats the current EPSS.
    expect(r.score).toBe(20.4);
    expect(assess({ ...base, epss: 0.02, lev: 0.19, cvss: 6 }).priority).toBe('track');
    // Never Act on an estimate; and with real evidence the estimate goes unsaid.
    expect(assess({ ...base, lev: 0.99 }).priority).toBe('attend');
    expect(assess({ ...base, lev: 0.99, kevAddedAt: '2026-10-01' }).reasons).not.toContainEqual(expect.stringContaining('LEV'));
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

  it('leaves CVSS 7.x with nothing else in Track, however reachable', () => {
    expect(assess({ ...base, cvss: 7.9, cvssVector: OPEN }).priority).toBe('track');
    expect(assess({ ...base, cvss: 8.0, cvssVector: OPEN }).priority).toBe('watch');
  });

  it("watches an unscored CVE its advisory calls critical or high, and says that's why", () => {
    const critical = assess({ ...base, severityLabel: 'critical' });
    expect(critical.priority).toBe('watch');
    expect(critical.why.decisive).toEqual({ kind: 'severity', text: 'Rated critical by its advisory (no CVSS score yet)' });
    expect(critical.why.missing).toContain('No CVSS score yet: NVD now scores only a fraction of new CVEs');
    // Impact 0.9 instead of the unknown 0.5, at the unscored threat of 0.01.
    expect(critical.score).toBe(0.9);
    expect(assess({ ...base, severityLabel: 'high' }).priority).toBe('watch');
    expect(assess({ ...base, severityLabel: 'medium' }).priority).toBe('track');
    expect(assess({ ...base, severityLabel: 'low' }).priority).toBe('track');
  });

  it('lets a CVSS score, or evidence, outrank a severity word', () => {
    // A score always wins over the word, both ways.
    expect(assess({ ...base, cvss: 5, severityLabel: 'critical' }).priority).toBe('track');
    expect(assess({ ...base, cvss: 5, severityLabel: 'critical' }).reasons).not.toContainEqual(expect.stringContaining('Rated'));
    // A word alone never reaches Attend; evidence still puts it in Act now.
    expect(assess({ ...base, severityLabel: 'critical', ssvc: ssvc('none', 'yes') }).priority).toBe('watch');
    expect(assess({ ...base, severityLabel: 'critical', kevAddedAt: '2026-10-01' }).priority).toBe('act');
    expect(assess({ ...base, severityLabel: 'high', epss: 0.2 }).priority).toBe('attend');
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

  it('lifts an edge device’s score, capped at 100, and says why without deciding anything', () => {
    const open = { ...base, epss: 0.4, cvss: 5 };
    expect(assess(open).score).toBe(20);
    expect(assess({ ...open, edge: true }).score).toBe(25);
    expect(assess({ ...base, kevAddedAt: 'x', knownRansomware: true, cvss: 10, ssvc: ssvc('active', 'yes'), edge: true }).score).toBe(100);
    const lifted = assess({ ...base, kevAddedAt: 'x', cvss: 9.8, edge: true });
    expect(lifted.reasons).toContain('Edge device: VPNs, firewalls and gateways are a top target');
    expect(lifted.why.decisive!.text).toBe('On CISA KEV');
  });

  it('never moves a result to another priority for being an edge device', () => {
    const cases: Signals[] = [
      { ...base, kevAddedAt: 'x' },
      { ...base, epss: 0.2 },
      { ...base, cvss: 8.5, cvssVector: OPEN },
      { ...base, cvss: 7.5, cvssVector: OPEN },
      { ...base, cvss: 5 },
      base,
    ];
    for (const s of cases) {
      const plain = assess(s);
      const edge = assess({ ...s, edge: true });
      expect(edge.priority).toBe(plain.priority);
      expect(edge.score).toBeGreaterThanOrEqual(plain.score);
      expect(edge.respondWithinHours).toBe(plain.respondWithinHours);
    }
  });

  it('says whether an attacker can reach a high-severity bug, without changing its score', () => {
    const open = { ...base, epss: 0.4, cvss: 5, cvssVector: OPEN };
    expect(assess(open).score).toBe(20);
    expect(assess({ ...open, cvss: 7.5 }).reasons).toEqual(['EPSS 40%', 'Reachable over the network without a login', 'CVSS 7.5 (high)']);
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
    const act: Pick<Assessment, 'priority' | 'score'> = { priority: 'act', score: 5 };
    const watch: Pick<Assessment, 'priority' | 'score'> = { priority: 'watch', score: 99 };
    expect([watch, act].sort(comparePriority)).toEqual([act, watch]);
  });
});

describe('mitigationFor', () => {
  it('suggests what to do meanwhile only for urgent CVEs with no fixed version known', () => {
    expect(mitigationFor('act', [], ' Apply mitigations per vendor instructions. ', 'https://a')).toEqual({
      action: 'Apply mitigations per vendor instructions.',
      advisory: 'https://a',
    });
    expect(mitigationFor('attend', [], null, null)).toEqual({ action: null, advisory: null });
    expect(mitigationFor('attend', [], '  ', null)).toEqual({ action: null, advisory: null });
    expect(mitigationFor('act', ['1.2.3'], 'x', null)).toBeNull();
    expect(mitigationFor('watch', [], 'x', null)).toBeNull();
    expect(mitigationFor('track', [], null, null)).toBeNull();
  });
});

describe('assess: why and when', () => {
  it('names the rule that decided the band, apart from the rest', () => {
    const kev = assess({ ...base, kevAddedAt: 'x', epss: 0.5, cvss: 9.8, cvssVector: OPEN });
    expect(kev.why.decisive).toEqual({ text: 'On CISA KEV', kind: 'evidence' });
    expect(kev.why.others.map((r) => r.text)).toEqual(['EPSS 50%', 'Reachable over the network without a login', 'CVSS 9.8 (critical)']);
    // The list order stays the same; only the decisive one is singled out.
    expect([kev.why.decisive!.text, ...kev.why.others.map((r) => r.text)]).toEqual(kev.reasons);

    expect(assess({ ...base, epss: 0.02, cvss: 9.8, cvssVector: OPEN }).why.decisive).toEqual({ text: 'CVSS 9.8 (critical)', kind: 'severity' });
    expect(assess({ ...base, epss: 0.3, cvss: 9.8, cvssVector: OPEN }).why.decisive).toEqual({ text: 'EPSS 30%', kind: 'prediction' });
    expect(assess({ ...base, exploitedSibling: 'CVE-1', epss: 0.3 }).why.decisive!.text).toBe('Similar to exploited CVE-1 in the same product');
    expect(assess({ ...base, lev: 0.4 }).why.decisive!.kind).toBe('prediction');
    expect(assess({ ...base, ssvc: ssvc('poc', 'yes') }).why.decisive!.text).toBe('Proof-of-concept exploit');
    expect(assess({ ...base, ssvc: ssvc('none', 'yes', 'total') }).why.decisive!.text).toBe('Total technical impact');
    expect(assess({ ...base, cvss: 5 }).why.decisive).toBeNull();
  });

  it('says what data it could not use', () => {
    expect(assess(base).why.missing).toEqual([
      'No CISA assessment of exploitation, automation or impact yet',
      'No CVSS score yet: NVD now scores only a fraction of new CVEs',
      'Not scored by EPSS yet',
    ]);
    expect(assess({ ...base, cvss: 8.1, epss: 0.01, ssvc: ssvc('none') }).why.missing).toEqual(['No CVSS vector to tell whether an attacker can reach it']);
    // Exploitation evidence makes the predictions moot.
    expect(assess({ ...base, kevAddedAt: 'x', cvss: 5, cvssVector: OPEN }).why.missing).toEqual([]);
  });

  it('suggests a response window by band, a day for anything exploited', () => {
    expect(assess({ ...base, kevAddedAt: 'x' }).respondWithinHours).toBe(24);
    expect(assess({ ...base, epss: 0.2 }).respondWithinHours).toBe(168);
    expect(assess({ ...base, cvss: 8.5 }).respondWithinHours).toBe(720);
    expect(assess(base).respondWithinHours).toBeNull();
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
