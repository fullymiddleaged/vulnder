import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { afterEach, describe, expect, it } from 'vitest';
import type { Role } from '../../src/match/roles';
import {
  addDays,
  apart,
  byProduct,
  chainPairs,
  chainVector,
  countIn,
  dropLogin,
  kevByProduct,
  productKev,
  loadEpss,
  median,
  mondays,
  onOrBefore,
  rankAt,
  rising,
  runBacktest,
  runTrend,
  signalsAt,
  toCve,
  type Cve,
  type IndexRow,
  type TrendRow,
} from './backtest';

const OPEN = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const LOGIN = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H';

const row = (over: Partial<IndexRow> = {}): IndexRow => ({
  id: 'CVE-2025-0001',
  published_at: '2025-01-10T00:00:00Z',
  title: null,
  product: 'acme/widget',
  cvss_score: 7.5,
  cvss_vector: OPEN,
  severity_label: null,
  ssvc: null,
  kev_added_at: null,
  kev_ransomware: 0,
  ...over,
});
const cve = (over: Partial<IndexRow> = {}, role: Role = 'other'): Cve => toCve(row(over), role);

describe('dates', () => {
  it('lists Mondays and finds the snapshot on or before a day', () => {
    const w = mondays('2025-01-01', '2025-01-31');
    expect(w).toEqual(['2025-01-06', '2025-01-13', '2025-01-20', '2025-01-27']);
    expect(mondays('2025-01-06', '2025-01-06')).toEqual(['2025-01-06']);
    expect(onOrBefore(w, '2025-01-19')).toBe('2025-01-13');
    expect(onOrBefore(w, '2025-01-20')).toBe('2025-01-20');
    expect(onOrBefore(w, '2025-01-05')).toBeNull();
  });

  it('counts in a half-open range and measures days either way', () => {
    const s = ['2025-01-01', '2025-01-02', '2025-01-02', '2025-01-05'];
    expect(countIn(s, '2025-01-02', '2025-01-05')).toBe(2);
    expect(countIn(s, '2025-01-06', '2025-01-01')).toBe(0);
    expect(apart('2025-01-10', '2025-01-03')).toBe(7);
    expect(addDays('2025-03-01', -1)).toBe('2025-02-28');
    expect(median([3, 1, 2])).toBe(2);
    expect(median([1, 2, 3, 4])).toBe(2.5);
    expect(median([])).toBeNull();
  });
});

describe('point in time', () => {
  it('drops SSVC exploitation, which would leak KEV', () => {
    const c = cve({ ssvc: JSON.stringify({ exploitation: 'active', automatable: 'yes', technicalImpact: 'total' }) });
    expect(c.ssvc).toEqual({ exploitation: null, automatable: 'yes', technicalImpact: 'total' });
  });

  it('counts KEV only once added, and age from the day', () => {
    const c = cve({ kev_added_at: '2025-02-01', kev_ransomware: 1 });
    expect(signalsAt(c, '2025-01-31', 0.01)).toMatchObject({ kevAddedAt: null, knownRansomware: false, ageDays: 21, lev: null, exploitedSibling: null });
    expect(signalsAt(c, '2025-02-01', 0.01)).toMatchObject({ kevAddedAt: '2025-02-01', knownRansomware: true });
  });

  it('marks edge devices from the product key', () => {
    expect(cve({ product: 'fortinet/fortios' }).edge).toBe(true);
    expect(cve({ product: 'acme/widget' }).edge).toBe(false);
    expect(cve({ product: null }).edge).toBe(false);
  });
});

describe('rankers', () => {
  const none = new Map<string, Cve[]>();
  it('flags with one signal each for the baselines', () => {
    expect(rankAt(cve({ cvss_score: 9.1 }), '2025-02-01', null, { name: 'c', ranker: 'cvss' }, none).priority).toBe('attend');
    expect(rankAt(cve({ cvss_score: 8.9 }), '2025-02-01', 0.9, { name: 'c', ranker: 'cvss' }, none).priority).toBe('track');
    expect(rankAt(cve(), '2025-02-01', 0.1, { name: 'e', ranker: 'epss' }, none).priority).toBe('attend');
    expect(rankAt(cve(), '2025-02-01', 0.09, { name: 'e', ranker: 'epss' }, none).priority).toBe('track');
  });

  it('uses the real assess() for today', () => {
    expect(rankAt(cve({ cvss_score: 9.8 }), '2025-02-01', 0.2, { name: 't', ranker: 'assess' }, none).priority).toBe('act');
  });
});

describe('chain rule 1', () => {
  const bypass = cve({ id: 'CVE-2025-0001', cvss_vector: OPEN, published_at: '2025-01-05' }, 'auth-bypass');
  const exec = cve({ id: 'CVE-2025-0002', cvss_score: 9.1, cvss_vector: LOGIN, published_at: '2025-01-05' }, 'code-exec');
  const products = byProduct([bypass, exec]);

  it('drops the login from the vector', () => {
    expect(dropLogin(LOGIN)).toBe(OPEN);
    expect(dropLogin('CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H')).toBe('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H');
  });

  it('lifts a login-required code-exec bug when its product has a reachable auth bypass', () => {
    expect(chainVector(exec, '2025-01-06', products)).toEqual({ vector: OPEN, enabler: 'CVE-2025-0001' });
    // Not before the bypass is public, not in another product, not for other roles.
    expect(chainVector(exec, '2025-01-04', products)).toBeNull();
    expect(chainVector({ ...exec, product: 'other/thing' }, '2025-01-06', products)).toBeNull();
    expect(chainVector({ ...exec, role: 'dos' }, '2025-01-06', products)).toBeNull();
    // A bypass that itself needs a login enables nothing.
    expect(chainVector(exec, '2025-01-06', byProduct([{ ...bypass, vector: LOGIN }, exec]))).toBeNull();
  });

  it('raises the score through assess(), never the band', () => {
    const today = rankAt(exec, '2025-01-06', null, { name: 't', ranker: 'assess' }, products);
    const chained = rankAt(exec, '2025-01-06', null, { name: 'c', ranker: 'assess', chain: true }, products);
    expect(chained.priority).toBe(today.priority);
    expect(chained.score).toBeGreaterThan(today.score);
  });

  it('finds same-product KEV pairs added within a week', () => {
    const a = { ...bypass, kevAdded: '2025-02-10' };
    const b = { ...exec, kevAdded: '2025-02-12' };
    const weeks = mondays('2025-01-01', '2025-03-01');
    const pairs = chainPairs([a, b], weeks, byProduct([a, b]));
    expect(pairs).toEqual({ pairs: 1, liftedAtT7: 1, examples: ['CVE-2025-0001 + CVE-2025-0002'] });
    expect(chainPairs([a, { ...b, kevAdded: '2025-03-01' }], weeks, products).pairs).toBe(0);
  });
});

describe('product KEV', () => {
  const onKev = cve({ id: 'CVE-2025-3000', kev_added_at: '2025-03-01' });
  const other = cve({ id: 'CVE-2025-3001', cvss_score: 5, published_at: '2025-01-10' });
  const kev = kevByProduct([onKev, other]);
  const none = new Map<string, Cve[]>();

  it('finds another CVE of the product added in the last 90 days, never itself', () => {
    expect(productKev(other, '2025-03-01', kev)).toBe('CVE-2025-3000');
    expect(productKev(other, '2025-05-29', kev)).toBe('CVE-2025-3000');
    expect(productKev(other, '2025-05-30', kev)).toBeNull(); // 90 days on
    expect(productKev(other, '2025-02-28', kev)).toBeNull(); // not added yet
    expect(productKev(onKev, '2025-03-10', kev)).toBeNull();
    expect(productKev({ ...other, product: 'other/thing' }, '2025-03-10', kev)).toBeNull();
  });

  it('lifts to Attend like a sibling, or weights only the score', () => {
    const today = rankAt(other, '2025-03-10', null, { name: 't', ranker: 'assess' }, none, kev);
    const attend = rankAt(other, '2025-03-10', null, { name: 'a', ranker: 'assess', productKev: 'attend' }, none, kev);
    const score = rankAt(other, '2025-03-10', null, { name: 's', ranker: 'assess', productKev: 'score' }, none, kev);
    expect(today.priority).toBe('track');
    expect(attend.priority).toBe('attend');
    expect(score.priority).toBe('track');
    expect(score.score).toBeGreaterThan(today.score);
  });
});

describe('runBacktest', () => {
  it('scores recall, monthly volume and lead time with point-in-time EPSS', async () => {
    // Two CVEs published early January. A gets a high EPSS from late January and
    // lands on KEV on March 3; B stays quiet.
    const a = cve({ id: 'CVE-2025-1000', cvss_score: 6, published_at: '2025-01-02', kev_added_at: '2025-03-03' });
    const b = cve({ id: 'CVE-2025-1001', cvss_score: 9.5, published_at: '2025-01-03' });
    const loads: string[] = [];
    const report = await runBacktest({
      cves: [a, b],
      variants: [
        { name: 'CVSS only', ranker: 'cvss' },
        { name: 'Today', ranker: 'assess' },
      ],
      kevFrom: '2025-01-01',
      to: '2025-06-30',
      epssFrom: '2024-12-30',
      loadEpss: async (d) => {
        loads.push(d);
        return { day: d, scores: new Map([['CVE-2025-1000', d >= '2025-01-27' ? 0.3 : 0.001]]) };
      },
    });
    // Files load oldest first, each once.
    expect(loads).toEqual([...loads].sort());
    expect(new Set(loads).size).toBe(loads.length);

    const recall = (variant: string, offset: number, group = 'all') => report.kev.find((k) => k.variant === variant && k.offsetDays === offset && k.group === group);
    expect(recall('Today', 7)).toMatchObject({ cases: 1, flagged: 1 });
    expect(recall('CVSS only', 7)).toMatchObject({ cases: 1, flagged: 0 });
    expect(recall('Today', 30, 'new')).toMatchObject({ cases: 1, flagged: 1 });
    expect(recall('Today', 7, 'EPSS v3')).toMatchObject({ cases: 1 });

    // Snapshots on Jan 6, Feb 3 and Mar 3. A counts as a KEV add ahead in January
    // (EPSS still low, so not flagged) and February (flagged); by March it's on KEV.
    const today = report.monthly.find((m) => m.variant === 'Today')!;
    const cvss = report.monthly.find((m) => m.variant === 'CVSS only')!;
    expect(today).toMatchObject({ snapshots: 3, population: 5, positives: 2, positivesFlagged: 1 });
    expect(cvss).toMatchObject({ flagged: 3, positivesFlagged: 0 });
    // In February both are in Attend and A ranks first on its higher score.
    expect(today.top1Hits).toBe(1);

    // Today first flagged A on Jan 27, 35 days before KEV; CVSS never did.
    expect(report.lead.find((l) => l.variant === 'Today')).toEqual({ variant: 'Today', cases: 1, flaggedBefore: 1, medianLeadDays: 35 });
    expect(report.lead.find((l) => l.variant === 'CVSS only')!.flaggedBefore).toBe(0);
  });

  it('counts a KEV CVE published after the snapshot as not yet published, not as a miss', async () => {
    const zeroDay = cve({ id: 'CVE-2025-2000', published_at: '2025-03-01', kev_added_at: '2025-03-02' });
    const report = await runBacktest({
      cves: [zeroDay],
      variants: [{ name: 'Today', ranker: 'assess' }],
      kevFrom: '2025-01-01',
      to: '2025-06-30',
      epssFrom: '2024-12-30',
      loadEpss: async () => null,
    });
    expect(report.kev.find((k) => k.offsetDays === 7 && k.group === 'all')).toMatchObject({ cases: 0, notYetPublished: 1 });
  });
});

describe('product pressure', () => {
  it('calls a rise only well above the prior rate', () => {
    expect(rising(2, 0)).toBe(false); // too few
    expect(rising(3, 0)).toBe(true);
    expect(rising(5, 20)).toBe(false); // about what 20 a year predicts for 90 days
    expect(rising(15, 20)).toBe(true);
  });

  it('compares KEV follow-up rates across groups', () => {
    const rows: TrendRow[] = [];
    // "hot": quiet for a year, then a burst of highs, then a KEV add.
    for (let i = 0; i < 10; i++) rows.push({ product: 'hot', published: addDays('2024-01-15', i * 30), high: false, kevAdded: null });
    for (let i = 0; i < 6; i++) rows.push({ product: 'hot', published: addDays('2025-01-05', i * 10), high: true, kevAdded: null });
    rows.push({ product: 'hot', published: '2023-01-01', high: true, kevAdded: '2025-04-15' });
    // "steady": the same rate all along, never on KEV.
    for (let i = 0; i < 40; i++) rows.push({ product: 'steady', published: addDays('2024-01-01', i * 14), high: i % 2 === 0, kevAdded: null });

    const groups = runTrend(rows, '2025-04-01', '2025-07-31');
    const g = (name: string) => groups.find((x) => x.group === name)!;
    // Two products on April 1 and May 1. "hot" rises both months; its KEV add
    // falls in April's 90 days and inside May's lookback.
    expect(g('all eligible')).toEqual({ group: 'all eligible', productMonths: 4, hits: 1 });
    expect(g('filings rising')).toMatchObject({ productMonths: 2, hits: 1 });
    expect(g('filings rising, no KEV add in last 365 days')).toMatchObject({ productMonths: 1, hits: 1 });
    expect(g('KEV add in last 365 days')).toMatchObject({ productMonths: 1, hits: 0 });
    expect(g('no KEV add in last 365 days')).toMatchObject({ productMonths: 3, hits: 1 });
  });
});

describe('loadEpss', () => {
  let dir: string | null = null;
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = null;
  });

  it('downloads once, caches, keeps only the wanted CVEs and falls back to an earlier day', async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'vulnder-epss-'));
    const csv = '#model_version:v2025.03.14,score_date:2025-01-05T00:00:00Z\ncve,epss,percentile\nCVE-2025-0001,0.5,0.99\nCVE-2025-0002,0.01,0.5\n';
    const calls: string[] = [];
    const fetchFn = (async (url: string) => {
      calls.push(url);
      return url.endsWith('2025-01-05.csv.gz') ? new Response(gzipSync(csv)) : new Response('', { status: 404 });
    }) as unknown as typeof fetch;

    const got = await loadEpss('2025-01-06', new Set(['CVE-2025-0001']), { fetchFn, cacheDir: dir });
    expect(got?.day).toBe('2025-01-05');
    expect([...got!.scores]).toEqual([['CVE-2025-0001', 0.5]]);
    expect(calls).toHaveLength(2);

    await loadEpss('2025-01-05', new Set(['CVE-2025-0002']), { fetchFn, cacheDir: dir });
    expect(calls).toHaveLength(2); // served from the cache
    expect(await loadEpss('2024-06-01', new Set(), { fetchFn, cacheDir: dir })).toBeNull();
  });
});
