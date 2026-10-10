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

  it('attends to every critical, however low its EPSS and whatever an attacker needs to reach it', () => {
    const critical = { ...base, cvss: 9.0, epss: 0.001 };
    for (const cvssVector of [
      OPEN,
      'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
      'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
      'AV:N/AC:L/Au:N/C:C/I:C/A:C',
      null,
    ]) {
      const r = assess({ ...critical, cvssVector });
      expect(r.priority).toBe('attend');
      expect(r.why.decisive).toEqual({ text: 'CVSS 9.0 (critical)', kind: 'severity' });
    }
  });

  it('leaves CVSS 7.x with nothing else in Track, however reachable', () => {
    expect(assess({ ...base, cvss: 7.9, cvssVector: OPEN }).priority).toBe('track');
    expect(assess({ ...base, cvss: 8.0, cvssVector: OPEN }).priority).toBe('watch');
  });

  it("attends to an unscored CVE its advisory calls critical, watches one it calls high, and says that's why", () => {
    const critical = assess({ ...base, severityLabel: 'critical' });
    expect(critical.priority).toBe('attend');
    expect(critical.why.decisive).toEqual({ kind: 'severity', text: 'Rated critical by its advisory (no CVSS score yet)' });
    expect(critical.why.missing).toContain('No CVSS score yet: NVD now scores only a fraction of new CVEs');
    // Impact 0.9 instead of the unknown 0.5, at the critical's threat floor of 0.1.
    expect(critical.score).toBe(9);
    const high = assess({ ...base, severityLabel: 'high' });
    expect(high.priority).toBe('watch');
    expect(high.why.decisive!.text).toBe('Rated high by its advisory (no CVSS score yet)');
    expect(high.score).toBe(0.7);
    expect(assess({ ...base, severityLabel: 'medium' }).priority).toBe('track');
    expect(assess({ ...base, severityLabel: 'low' }).priority).toBe('track');
  });

  it('lets a CVSS score, or evidence, outrank a severity word', () => {
    // A score always wins over the word, both ways.
    expect(assess({ ...base, cvss: 5, severityLabel: 'critical' }).priority).toBe('track');
    expect(assess({ ...base, cvss: 5, severityLabel: 'critical' }).reasons).not.toContainEqual(expect.stringContaining('Rated'));
    // A word reaches Attend only when it says critical; evidence still puts it in Act now.
    expect(assess({ ...base, severityLabel: 'high', ssvc: ssvc('none', 'yes') }).priority).toBe('watch');
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

  it('never moves a result to another priority for being an edge device, except up to BOD 26-04 (tested below)', () => {
    const cases: Signals[] = [
      { ...base, kevAddedAt: 'x' },
      { ...base, epss: 0.2 },
      { ...base, cvss: 8.5, cvssVector: OPEN },
      { ...base, cvss: 7.5, cvssVector: OPEN },
      { ...base, cvss: 5 },
      { ...base, cvss: 9.8, ssvc: ssvc('none', 'yes', 'partial') },
      { ...base, cvss: 9.8, ssvc: ssvc('poc', 'no', 'total') },
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

  it('puts exploited results ahead of predicted ones in Act now, whatever their scores', () => {
    const kev = assess({ ...base, kevAddedAt: 'x', cvss: 4 });
    const predicted = assess({ ...base, epss: 0.9, cvss: 10, cvssVector: OPEN, ssvc: ssvc('none', 'yes', 'total') });
    expect(kev.priority).toBe('act');
    expect(predicted.priority).toBe('act');
    expect(predicted.score).toBeGreaterThan(kev.score);
    expect([predicted, kev].sort(comparePriority)).toEqual([kev, predicted]);
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
    expect(assess({ ...base, epss: 0.3, cvss: 8.8, cvssVector: OPEN }).why.decisive).toEqual({ text: 'EPSS 30%', kind: 'prediction' });
    expect(assess({ ...base, epss: 0.3, cvss: 9.8, cvssVector: OPEN }).why.decisive).toEqual({ text: 'EPSS 30% on a critical bug', kind: 'prediction' });
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

  it('suggests a response window by band, a day for anything exploited, 3 days for Act now before exploitation', () => {
    expect(assess({ ...base, kevAddedAt: 'x' }).respondWithinHours).toBe(24);
    expect(assess({ ...base, ssvc: ssvc('active') }).respondWithinHours).toBe(24);
    expect(assess({ ...base, epss: 0.6 }).respondWithinHours).toBe(72);
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
    expect(assess({ ...base, cvss: 6.5 }).score).toBe(0.7);
    expect(assess({ ...base, cvss: 5 }).score).toBe(0.5);
  });

  it('never lets a tiny EPSS score rank a CVE below an unscored one', () => {
    expect(assess({ ...base, epss: 0, cvss: 5 }).score).toBe(assess({ ...base, cvss: 5 }).score);
    expect(assess({ ...base, epss: 0.002, cvss: 5 }).score).toBe(0.5);
  });
});

describe('assess: Act now before exploitation', () => {
  it('acts on a critical that EPSS or LEV rates likely, and says both halves', () => {
    const r = assess({ ...base, epss: 0.12, cvss: 9.1, cvssVector: OPEN });
    expect(r.priority).toBe('act');
    expect(r.why.decisive).toEqual({ text: 'EPSS 12% on a critical bug', kind: 'prediction' });
    expect(r.reasons).toContain('CVSS 9.1 (critical)');
    // Behind a login too: a likely critical is likely whatever stands in the way.
    expect(assess({ ...base, epss: 0.12, cvss: 9.9, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H' }).priority).toBe('act');
    // An advisory's critical rating counts as critical.
    expect(assess({ ...base, epss: 0.12, severityLabel: 'critical' }).priority).toBe('act');
    const lev = assess({ ...base, epss: 0.03, lev: 0.25, cvss: 9.8 });
    expect(lev.priority).toBe('act');
    expect(lev.why.decisive!.text).toBe('NIST LEV estimate: 25% chance it has already been exploited on a critical bug');
  });

  it('leaves a likely high, or an unlikely critical, in Attend', () => {
    expect(assess({ ...base, epss: 0.12, cvss: 8.9, cvssVector: OPEN }).priority).toBe('attend');
    expect(assess({ ...base, epss: 0.09, cvss: 9.8, cvssVector: OPEN }).priority).toBe('attend');
    expect(assess({ ...base, lev: 0.19, cvss: 9.8 }).priority).toBe('attend');
    // A similar CVE's exploitation never reaches Act now.
    expect(assess({ ...base, exploitedSibling: 'CVE-1', cvss: 9.8 }).priority).toBe('attend');
  });

  it('acts on EPSS of 50% or more at any severity', () => {
    const r = assess({ ...base, epss: 0.5, cvss: 5.3 });
    expect(r.priority).toBe('act');
    expect(r.why.decisive).toEqual({ text: 'EPSS 50%', kind: 'prediction' });
    expect(assess({ ...base, epss: 0.49, cvss: 5.3 }).priority).toBe('attend');
  });

  it('acts on an edge device an attacker can take over automatically (BOD 26-04), and on nothing else for that', () => {
    const takeover = { ...base, cvss: 7.5, epss: 0.004, ssvc: ssvc('none', 'yes', 'total'), edge: true };
    const r = assess(takeover);
    expect(r.priority).toBe('act');
    expect(r.respondWithinHours).toBe(72);
    expect(r.why.decisive).toEqual({ text: 'Edge device an attacker can take over automatically: CISA’s 3-day case for internet-facing systems', kind: 'context' });
    expect(r.reasons).not.toContain('Automatable');
    // Scored as if EPSS had reached the Attend line: 0.1 × 0.9 × 1.25 × 1.25.
    expect(r.score).toBe(14.1);
    // Any piece missing: not Act now.
    expect(assess({ ...takeover, edge: false }).priority).toBe('watch');
    expect(assess({ ...takeover, ssvc: ssvc('none', 'yes', 'partial') }).priority).toBe('attend');
    expect(assess({ ...takeover, ssvc: ssvc('none', 'no', 'total') }).priority).toBe('attend');
  });
});

describe('assess: never looser than CISA BOD 26-04', () => {
  // https://certcc.github.io/SSVC/howto/cisa_response/ : days, or null for "fix on system upgrade".
  const bod = (kev: boolean, exposed: boolean, auto: boolean, total: boolean): number | null => {
    if (kev) return exposed ? (auto || total ? 3 : 14) : auto && total ? 3 : auto || total ? 14 : 14;
    if (exposed) return auto && total ? 3 : auto || total ? 14 : 60;
    return auto ? 60 : null;
  };

  it('gives every combination a deadline no longer than BOD, edge devices as exposed and the rest as not', () => {
    for (const kev of [false, true])
      for (const edge of [false, true])
        for (const auto of [false, true])
          for (const total of [false, true]) {
            // Nothing else to go on: no CVSS, no EPSS, no exploit, so only the BOD inputs decide.
            const s: Signals = { ...base, kevAddedAt: kev ? '2026-10-01' : null, edge, ssvc: ssvc('none', auto ? 'yes' : 'no', total ? 'total' : 'partial') };
            const limit = bod(kev, edge, auto, total);
            const hours = assess(s).respondWithinHours;
            if (limit === null) continue;
            expect(hours, JSON.stringify({ kev, edge, auto, total })).not.toBeNull();
            expect(hours!, JSON.stringify({ kev, edge, auto, total })).toBeLessThanOrEqual(limit * 24);
          }
  });

  it('watches anything automatable, and says so', () => {
    const r = assess({ ...base, cvss: 5.3, ssvc: ssvc('none', 'yes', 'partial') });
    expect(r.priority).toBe('watch');
    expect(r.why.decisive).toEqual({ text: 'Automatable: CISA sets a deadline for these even on internal systems', kind: 'context' });
    // When something else decides, it's just a fact on the list.
    expect(assess({ ...base, cvss: 8.5, ssvc: ssvc('none', 'yes', 'partial') }).reasons).toContain('Automatable');
  });

  it('holds edge devices to the deadlines for an internet-facing system, and says why', () => {
    const auto = assess({ ...base, cvss: 6.5, ssvc: ssvc('none', 'yes', 'partial'), edge: true });
    expect(auto.priority).toBe('attend');
    expect(auto.why.decisive!.text).toBe('Edge device with an automatable bug: CISA gives internet-facing systems 14 days');
    // Scores as if EPSS had reached the Attend line: 0.1 × 0.65 × 1.25 × 1.25.
    expect(auto.score).toBe(10.2);
    const total = assess({ ...base, cvss: 6.5, ssvc: ssvc('none', 'no', 'total'), edge: true });
    expect(total.priority).toBe('attend');
    expect(total.why.decisive!.text).toBe('Edge device with a total-impact bug: CISA gives internet-facing systems 14 days');
    const assessed = assess({ ...base, cvss: 4.3, ssvc: ssvc('none', 'no', 'partial'), edge: true });
    expect(assessed.priority).toBe('watch');
    expect(assessed.why.decisive!.text).toBe('Edge device: CISA sets internet-facing systems a deadline for every bug it assesses');
    // Not assessed by CISA: BOD has nothing to go on, so the other rules decide.
    expect(assess({ ...base, cvss: 4.3, edge: true }).priority).toBe('track');
  });
});

describe('assess: a score that agrees with its band', () => {
  it('scores a reachable critical at least as if EPSS had reached the Attend line', () => {
    // CVE-2026-76471, Cisco NX-OS NX-API RCE: 9.8, open to the network, automatable, EPSS 0.5%.
    const nxApi = { ...base, epss: 0.00523, lev: 0.0005, cvss: 9.8, cvssVector: OPEN, ssvc: ssvc('none', 'yes', 'total') };
    expect(assess(nxApi).priority).toBe('attend');
    expect(assess(nxApi).score).toBe(12.3);
    expect(assess({ ...nxApi, edge: true }).score).toBe(15.3);
    // The same as an EPSS of 10% would score, and higher EPSS still counts.
    expect(assess({ ...base, epss: 0.001, cvss: 9.0, cvssVector: OPEN }).score).toBe(assess({ ...base, epss: 0.1, cvss: 9.0 }).score);
    expect(assess({ ...base, epss: 0.4, cvss: 9.0, cvssVector: OPEN }).score).toBe(36);
    // No vector: the critical keeps the benefit of the doubt here too.
    expect(assess({ ...base, cvss: 9.5 }).score).toBe(9.5);
  });

  it('ranks a critical behind a login or a user’s help below one anyone can reach, still in Attend', () => {
    const login = { ...base, epss: 0.001, cvss: 9.9, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H' };
    expect(assess(login).priority).toBe('attend');
    expect(assess(login).score).toBe(5);
    expect(assess(login).score).toBeLessThan(assess({ ...login, cvss: 9.0, cvssVector: OPEN }).score);
    // CISA judging it automatable outweighs the vector.
    expect(assess({ ...login, ssvc: ssvc('none', 'yes') }).score).toBe(12.4);
    // A real EPSS above the floor still counts.
    expect(assess({ ...login, epss: 0.3 }).score).toBe(29.7);
  });
});
