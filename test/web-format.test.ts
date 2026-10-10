import { describe, expect, it } from 'vitest';
import type { Change, Result } from '../web/api';
import { ago, byPriority, changeCounts, countdown, foldFamilies, lockRemaining, componentGroups, cvssSeverity, describeChange, eventDetail, formatScore, groupChanges, itemMarks, matchHeadline, ordinal, passNotice, describeLength, examplePlaceholder, pct, preview, RISK, shortSummary, stackSummary, withItemMarks } from '../web/format';
import { parseStack, serializeStack } from '../src/stack/format';

function result(id: string, tier: Result['tier'], match: Result['match'] = 'exact'): Result {
  return {
    id,
    title: `${id} title`,
    summary: null,
    publishedAt: null,
    tier,
    evidence: { kevAddedAt: null, kevDueDate: null, knownRansomware: false, epss: null, epssPercentile: null, epssDate: null, lev: null },
    confidence: 'product_match',
    match,
    matched: [],
    fixedVersions: [],
    cvss: null,
    links: { advisory: null, patch: null },
    priority: tier === 'exploited' ? 'act' : tier === 'likely' ? 'attend' : 'track',
    score: 0,
    reasons: [],
    family: null,
    related: [],
    why: { decisive: null, others: [], missing: [] },
    respondWithinHours: null,
    mitigation: null,
  };
}

describe('foldFamilies', () => {
  const member = (id: string, family: string, related: string[]) => ({ ...result(id, 'backlog'), family, related });

  it('folds each family under its first member, in list order, dropping nothing', () => {
    const list = [member('A', 'F', ['C']), result('B', 'backlog'), member('C', 'F', ['A']), member('D', 'G', [])];
    const folded = foldFamilies(list);
    expect(folded.map((f) => [f.lead.id, f.related.map((r) => r.id)])).toEqual([
      ['A', ['C']],
      ['B', []],
      ['D', []],
    ]);
    expect(folded.flatMap((f) => [f.lead, ...f.related])).toHaveLength(list.length);
  });

  it('leaves a family with no other member here unfolded', () => {
    // Named only because a member elsewhere is exploited.
    expect(foldFamilies([member('A', 'F', []), member('B', 'F', [])]).map((f) => f.lead.id)).toEqual(['A', 'B']);
  });
});

function change(vulnId: string, type: Change['type'], occurredAt: string, detail: Record<string, unknown> = {}): Change {
  return { vulnId, type, occurredAt, detail, title: null };
}

describe('UI formatting', () => {
  it('writes the match headline for none, one and many', () => {
    expect(matchHeadline(0, 30)).toEqual({ title: 'No matches.', subtitle: "Nobody's been into your stack in the last 30 days. Keep it that way." });
    expect(matchHeadline(1, 7).subtitle).toBe('1 CVE is into your stack from the last 7 days. Red flags, ranked:');
    expect(matchHeadline(3, 30)).toEqual({ title: "It's a match. Unfortunately.", subtitle: '3 CVEs are into your stack from the last 30 days. Red flags, ranked:' });
    // Older results from the safety net are counted apart, so the window isn't misstated.
    expect(matchHeadline(3, 30, 0, 1).subtitle).toBe(
      '2 CVEs are into your stack from the last 30 days, plus 1 older one from the last year that is exploited, likely to be, or critical. Red flags, ranked:',
    );
    expect(matchHeadline(2, 7, 0, 2).subtitle).toBe('2 CVEs from the last year are still into your stack: exploited, likely to be, or critical. Red flags, ranked:');
  });

  it("doesn't call a stack clear when some of its names were never checked", () => {
    expect(matchHeadline(0, 30, 2).subtitle).toBe("Nothing in the last 30 days for the items we recognised, but 2 names couldn't be matched and weren't checked. Add them with Edit stack.");
    expect(matchHeadline(0, 7, 1).subtitle).toContain("1 name couldn't be matched");
    expect(matchHeadline(0, 30, 0).subtitle).toMatch(/^Nobody's been into your stack/);
    // With matches, unmatched names don't change the headline; the stack notes cover them.
    expect(matchHeadline(2, 30, 3).title).toBe("It's a match. Unfortunately.");
  });

  it('sums up a stack by how sure each match is', () => {
    expect(stackSummary([])).toBe('0 items');
    expect(stackSummary([{ close: false }])).toBe('1 item');
    expect(stackSummary([{}, { close: true }, { close: true }, {}])).toBe('4 items: 2 exact, 2 close matches');
    expect(stackSummary([{ close: true }])).toBe('1 item: 1 close match');
  });

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

describe('what changed this week', () => {
  const results = [result('CVE-A', 'backlog'), result('CVE-B', 'exploited'), result('CVE-C', 'likely'), result('CVE-D', 'exploited', 'close'), result('CVE-E', 'exploited')];

  it('groups events per CVE and orders by importance, tier, match, then recency', () => {
    const groups = groupChanges(
      [
        change('CVE-A', 'published', '2026-10-05T00:00:00Z'),
        change('CVE-B', 'published', '2026-10-01T00:00:00Z'),
        change('CVE-B', 'kev_added', '2026-10-03T00:00:00Z'),
        change('CVE-C', 'epss_crossed', '2026-10-04T00:00:00Z', { from: 0.03, to: 0.42 }),
        change('CVE-D', 'kev_added', '2026-10-04T00:00:00Z'),
        change('CVE-E', 'kev_added', '2026-10-02T00:00:00Z'),
      ],
      results,
    );
    expect(groups.map((g) => [g.vulnId, g.events.map((e) => e.type).join('+')])).toEqual([
      ['CVE-B', 'kev_added+published'], // exploited, exact, newest KEV-exact
      ['CVE-E', 'kev_added'], // exploited, exact, older
      ['CVE-D', 'kev_added'], // exploited, but a close match
      ['CVE-C', 'epss_crossed'],
      ['CVE-A', 'published'],
    ]);
    expect(groups[0]!.result?.id).toBe('CVE-B');
  });

  it('counts CVEs per kind of change', () => {
    const groups = groupChanges(
      [
        change('CVE-B', 'kev_added', '2026-10-03T00:00:00Z'),
        change('CVE-B', 'published', '2026-10-01T00:00:00Z'),
        change('CVE-A', 'published', '2026-10-05T00:00:00Z'),
        change('CVE-C', 'fix_released', '2026-10-05T00:00:00Z'),
      ],
      results,
    );
    expect(changeCounts(groups)).toBe('1 added to KEV, 1 fix released, 2 new CVEs');
    expect(changeCounts([])).toBe('');
  });

  it('describes each event', () => {
    expect(eventDetail(change('X', 'kev_added', '2026-10-02T00:00:00.000Z', { dueDate: '2026-10-23T00:00:00.000Z', ransomware: true }))).toBe(
      '2026-10-02, federal due date 2026-10-23, used in ransomware',
    );
    expect(eventDetail(change('X', 'epss_crossed', '2026-10-04T00:00:00.000Z', { from: 0.031, to: 0.42 }))).toBe('3.1% → 42.0% on 2026-10-04');
    expect(eventDetail(change('X', 'epss_crossed', '2026-10-04T00:00:00.000Z', { from: null, to: 0.12 }))).toBe('12.0% on 2026-10-04');
    expect(eventDetail(change('X', 'fix_released', '2026-10-04T00:00:00.000Z', { package: 'next', fixedVersion: '14.2.5' }))).toBe('next 14.2.5');
    expect(eventDetail(change('X', 'published', '2026-10-04T00:00:00.000Z'))).toBe('2026-10-04');
  });

  it('shortens summaries on a word boundary', () => {
    expect(shortSummary(null)).toBeNull();
    expect(shortSummary('### Impact\n\nA  short   one.')).toBe('Impact A short one.');
    expect(shortSummary('word '.repeat(100), 22)).toBe('word word word word…');
  });
});

describe('priority display', () => {
  it('maps priorities to traffic lights, with no green', () => {
    expect(Object.entries(RISK).map(([p, r]) => [p, r.label, r.light])).toEqual([
      ['act', 'Act now', 'red'],
      ['attend', 'Attend', 'amber'],
      ['watch', 'Watch', 'yellow'],
      ['track', 'Track', 'grey'],
    ]);
  });

  it('gives each priority a response window matching the server and How it works', () => {
    expect(Object.values(RISK).map((r) => r.window)).toEqual([
      'Within 24 hours to 3 days',
      'Within 7 days',
      'Within 30 days',
      'In your next routine update',
    ]);
  });

  it('uses the CVSS qualitative bands', () => {
    expect([10, 9, 8.9, 7, 6.9, 4, 3.9, 0.1, 0].map(cvssSeverity)).toEqual(['Critical', 'Critical', 'High', 'High', 'Medium', 'Medium', 'Low', 'Low', 'None']);
  });

  it('shows small scores with a decimal so they do not all read as 0', () => {
    expect([91, 10, 9.96, 0.9, 0].map(formatScore)).toEqual(['91', '10', '10.0', '0.9', '0.0']);
  });

  it('splits results by priority, keeping feed order', () => {
    const groups = byPriority([
      { ...result('CVE-1', 'backlog'), priority: 'watch' },
      { ...result('CVE-2', 'exploited'), priority: 'act' },
      { ...result('CVE-3', 'backlog'), priority: 'watch' },
    ]);
    expect(Object.fromEntries(Object.entries(groups).map(([p, rs]) => [p, rs.map((r) => r.id)]))).toEqual({
      act: ['CVE-2'],
      attend: [],
      watch: ['CVE-1', 'CVE-3'],
      track: [],
    });
  });
});

describe('componentGroups', () => {
  it('attaches results to the fix-first list, in its order, with ranks and close marks', () => {
    const results = [result('CVE-1', 'exploited'), result('CVE-2', 'backlog'), result('CVE-3', 'backlog')];
    const counts = { act: 0, attend: 0, watch: 0, track: 0 };
    const groups = componentGroups(
      [
        { item: 'p:cisco/ios_xe', score: 91, counts: { ...counts, act: 1 }, vulns: ['CVE-1'], fixable: 0 },
        { item: '?p:f5/nginx;platform', score: 2, counts: { ...counts, track: 2 }, vulns: ['CVE-3', 'CVE-2', 'CVE-missing'], fixable: 1 },
      ],
      results,
    );
    expect(groups.map((g) => [g.rank, g.component, g.close, g.team, g.results.map((r) => r.id)])).toEqual([
      [1, 'p:cisco/ios_xe', false, null, ['CVE-1']],
      [2, 'p:f5/nginx', true, 'platform', ['CVE-3', 'CVE-2']],
    ]);
    expect(componentGroups([], results)).toEqual([]);
  });
});

describe('item marks', () => {
  it('splits a stack item into its name and marks', () => {
    expect(itemMarks('p:f5/nginx')).toEqual({ name: 'p:f5/nginx', close: false, team: null, edge: null });
    expect(itemMarks('?p:f5/nginx')).toEqual({ name: 'p:f5/nginx', close: true, team: null, edge: null });
    expect(itemMarks('?npm:@scope/pkg@1.0')).toEqual({ name: 'npm:@scope/pkg@1.0', close: true, team: null, edge: null });
    expect(itemMarks('?p:f5/nginx@1.27;platform')).toEqual({ name: 'p:f5/nginx@1.27', close: true, team: 'platform', edge: null });
    expect(itemMarks('p:f5/nginx;platform;edge')).toEqual({ name: 'p:f5/nginx', close: false, team: 'platform', edge: true });
    expect(itemMarks('p:fortinet/fortios;internal')).toEqual({ name: 'p:fortinet/fortios', close: false, team: null, edge: false });
    // Out of order or unknown: left in the name, as the server would reject it.
    expect(itemMarks('p:f5/nginx;edge;platform').name).toBe('p:f5/nginx;edge');
  });

  it('writes the marks back in canonical order, matching the stack format', () => {
    expect(withItemMarks('p:f5/nginx', { close: true, team: null, edge: null })).toBe('?p:f5/nginx');
    expect(withItemMarks('p:f5/nginx', { close: false, team: 'network', edge: null })).toBe('p:f5/nginx;network');
    expect(withItemMarks('p:f5/nginx', { close: false, team: 'network', edge: true })).toBe('p:f5/nginx;network;edge');
    expect(withItemMarks('p:fortinet/fortios', { close: true, team: null, edge: false })).toBe('?p:fortinet/fortios;internal');
    for (const s of ['?p:f5/nginx', 'p:f5/nginx', '?p:f5/nginx@1.27;platform', 'npm:react;frontend', 'p:f5/nginx;edge', '?p:fortinet/fortios@7.4;network;internal']) {
      const m = itemMarks(s);
      expect(withItemMarks(m.name, m)).toBe(serializeStack(parseStack(s)));
    }
  });
});

describe('preview', () => {
  it('shows the first few and counts the rest, but never hides just one', () => {
    expect(preview([], 3)).toEqual({ shown: [], rest: 0 });
    expect(preview([1, 2, 3], 3)).toEqual({ shown: [1, 2, 3], rest: 0 });
    expect(preview([1, 2, 3, 4], 3)).toEqual({ shown: [1, 2, 3, 4], rest: 0 });
    expect(preview([1, 2, 3, 4, 5], 3)).toEqual({ shown: [1, 2, 3], rest: 2 });
  });
});

describe('passNotice', () => {
  const now = Date.parse('2026-10-08T10:00:00Z');
  const pass = (used: number, minutesLeft: number | null) => ({
    active: true,
    used,
    limit: 2,
    resetsAt: minutesLeft === null ? null : new Date(now + minutesLeft * 60_000).toISOString(),
  });

  it('says nothing while the allowance lasts, or once its hour is over', () => {
    expect(passNotice(null, now)).toBeNull();
    expect(passNotice({ ...pass(2, 30), active: false }, now)).toBeNull();
    expect(passNotice(pass(1, 30), now)).toBeNull();
    expect(passNotice(pass(2, 0), now)).toBeNull();
  });

  it('counts down to the unlock once both stacks are used', () => {
    expect(passNotice(pass(2, 60), now)).toBe("You've looked up 2 stacks this hour, the most it allows. New lookups, edits and time windows unlock in 60:00.");
    expect(passNotice(pass(2, 0.5), now)).toContain('unlock in 0:30.');
    expect(passNotice(pass(2, 37), now)).toContain('unlock in 37:00.');
    expect(lockRemaining(pass(2, 37), now)).toBe(37 * 60_000);
    expect(lockRemaining(pass(1, 37), now)).toBeNull();
  });
});

describe('countdown', () => {
  it('shows minutes and seconds, rounding up so it never reads 0:00 while locked', () => {
    expect(countdown(3_600_000)).toBe('60:00');
    expect(countdown(59 * 60_000 + 32_000)).toBe('59:32');
    expect(countdown(4_001)).toBe('0:05');
    expect(countdown(1)).toBe('0:01');
    expect(countdown(0)).toBe('0:00');
    expect(countdown(-5)).toBe('0:00');
  });
});

describe('describeLength', () => {
  it('allows exactly the limit and greys out one over, counting trimmed text', () => {
    expect(describeLength('x'.repeat(499), false, 500)).toEqual({ label: '499 / 500', over: false });
    expect(describeLength('x'.repeat(500), false, 500)).toEqual({ label: '500 / 500', over: false });
    expect(describeLength('x'.repeat(501), false, 500)).toEqual({ label: '501 / 500: too long. Shorten it, or upload a manifest below', over: true });
    expect(describeLength(`  ${'x'.repeat(500)}\n\n`, false, 500).over).toBe(false);
  });

  it('never limits a manifest', () => {
    expect(describeLength('x'.repeat(100_000), true, 500)).toEqual({ label: 'Manifest detected', over: false });
  });
});

describe('examplePlaceholder', () => {
  const examples = [{ text: 'first' }, { text: 'second' }, { text: 'third' }];

  it('picks each example across the range of random values, including the ends', () => {
    expect(examplePlaceholder(examples, () => 0)).toBe('For example: first');
    expect(examplePlaceholder(examples, () => 0.5)).toBe('For example: second');
    expect(examplePlaceholder(examples, () => 0.999999)).toBe('For example: third');
    // Math.random never returns 1, but a bad source can't index past the end.
    expect(examplePlaceholder(examples, () => 1)).toBe('For example: third');
    expect(examplePlaceholder([], () => 0)).toBe('');
  });
});
