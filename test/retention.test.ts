import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { catchUpHighEpss, EPSS_NET_KEY } from '../src/ingest/epss-net';
import { maintenanceStatements } from '../src/ingest/maintenance';
import { mergePatch } from '../src/ingest/merge';
import { cursorKey, setMetaStatement } from '../src/ingest/meta';
import { KEEP_PARAMS, KEEP_SQL, keepStart, keptLonger, type Keepable } from '../src/ingest/retention';
import { RAW_BASE } from '../src/ingest/sources/cve';
import { EPSS_URL } from '../src/ingest/sources/epss';
import { windowStart } from '../src/lib/time';
import { matchStack } from '../src/match/match';
import { parseStack } from '../src/stack/format';
import { FakeFetch, jsonResponse } from './helpers/fake-fetch';
import { cveRecords, withMeta } from './helpers/fixtures';
import { resetDb, rows, sourceContext, store } from './helpers/db';

const NOW = new Date('2026-10-10T12:00:00Z');
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();
const START = keepStart(NOW);

/** One vulns row: published `age` days ago, with whatever else is given. */
interface Row extends Partial<Keepable> {
  id: string;
  age: number;
  lastEventAge?: number;
}

async function insert(...list: Row[]): Promise<void> {
  await env.DB.batch(
    list.flatMap((r) => [
      env.DB.prepare(
        `INSERT INTO vulns (id, title, published_at, last_event_at, kev_added_at, cvss_score, epss, lev_log, ssvc, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        r.id,
        `Bug ${r.id}`,
        daysAgo(r.age),
        r.lastEventAge === undefined ? null : daysAgo(r.lastEventAge),
        r.kevAddedAt ?? null,
        r.cvssScore ?? null,
        r.epss ?? null,
        r.levLog ?? 0,
        r.exploitation ? JSON.stringify({ exploitation: r.exploitation, automatable: 'no', technicalImpact: 'partial' }) : null,
        NOW.toISOString(),
      ),
      env.DB.prepare(`INSERT INTO affected (vuln_id, source, kind, vendor, product) VALUES (?, 'cve', 'product', 'acme', 'gate')`).bind(r.id),
    ]),
  );
}

// A spread of cases either side of every threshold.
const CASES: Row[] = [
  { id: 'CVE-2026-0001', age: 200, cvssScore: 9.9 },
  { id: 'CVE-2026-0002', age: 200, cvssScore: 9.8 },
  { id: 'CVE-2026-0003', age: 200, epss: 0.1 },
  { id: 'CVE-2026-0004', age: 200, epss: 0.0999 },
  { id: 'CVE-2026-0005', age: 200, levLog: Math.log1p(-0.25) },
  { id: 'CVE-2026-0006', age: 200, levLog: Math.log1p(-0.15) },
  { id: 'CVE-2026-0007', age: 200, exploitation: 'Active' },
  { id: 'CVE-2026-0008', age: 200, exploitation: 'poc' },
  { id: 'CVE-2025-0009', age: 400, cvssScore: 10, epss: 0.9 },
  { id: 'CVE-2020-0010', age: 2000, kevAddedAt: daysAgo(300) },
  { id: 'CVE-2020-0011', age: 2000, kevAddedAt: daysAgo(400) },
  { id: 'CVE-2026-0012', age: 30 },
  { id: 'CVE-2026-0013', age: 200, lastEventAge: 10 },
];
const KEPT_LONGER = ['CVE-2026-0001', 'CVE-2026-0003', 'CVE-2026-0005', 'CVE-2026-0007', 'CVE-2020-0010'];

const keepable = (r: Row): Keepable => ({
  publishedAt: daysAgo(r.age),
  kevAddedAt: r.kevAddedAt ?? null,
  exploitation: r.exploitation ?? null,
  cvssScore: r.cvssScore ?? null,
  epss: r.epss ?? null,
  levLog: r.levLog ?? 0,
});

beforeEach(resetDb);

describe('the safety net', () => {
  it('keeps known-exploited, likely-exploited and CVSS 9.9+ CVEs from the last year, in code and in SQL alike', async () => {
    expect(CASES.filter((r) => keptLonger(keepable(r), START)).map((r) => r.id)).toEqual(KEPT_LONGER);
    await insert(...CASES);
    const sql = await rows<{ id: string }>(`SELECT id FROM vulns WHERE ${KEEP_SQL} ORDER BY id`, NOW.toISOString(), START, ...KEEP_PARAMS);
    expect(sql.map((r) => r.id)).toEqual([...KEPT_LONGER].sort());
  });

  it('prunes after 90 days only what the safety net doesn’t keep', async () => {
    await insert(...CASES);
    await env.DB.batch(maintenanceStatements(NOW).map((s) => env.DB.prepare(s.sql).bind(...s.params)));
    const left = (await rows<{ id: string }>('SELECT id FROM vulns ORDER BY id')).map((r) => r.id);
    // The safety net, plus the two still inside the 90 days (one by a recent event).
    expect(left).toEqual([...KEPT_LONGER, 'CVE-2026-0012', 'CVE-2026-0013'].sort());
    expect((await rows<{ n: number }>('SELECT COUNT(*) AS n FROM affected'))[0]!.n).toBe(left.length);
  });

  it('stores a new record from before the 90 days only when it qualifies', () => {
    const opts = { windowStart: windowStart(NOW, 90), keepStart: START, epssEvents: true };
    const patch = (fields: Record<string, unknown>) => ({ source: 'cve' as const, id: 'CVE-2026-0100', aliases: [], fields: { publishedAt: daysAgo(200), ...fields } });
    expect(mergePatch(null, patch({ cvssScore: 9.9 }), opts).record).not.toBeNull();
    expect(mergePatch(null, patch({ cvssScore: 9.8 }), opts).record).toBeNull();
    expect(mergePatch(null, patch({ epss: 0.2, epssPercentile: 0.9, epssDate: '2026-10-09' }), opts).record).not.toBeNull();
    expect(mergePatch(null, patch({ cvssScore: 9.9, publishedAt: daysAgo(400) }), opts).record).toBeNull();
    // Without a keepStart, nothing outside the window, as before.
    expect(mergePatch(null, patch({ cvssScore: 10 }), { windowStart: opts.windowStart, epssEvents: true }).record).toBeNull();
    // No "published" event for an older CVE: it isn't new.
    expect(mergePatch(null, patch({ cvssScore: 9.9 }), opts).events).toEqual([]);
  });

  it('shows safety-net CVEs whatever the window, marked as older', async () => {
    await insert(...CASES);
    const res = await matchStack(store(), parseStack('p:acme/gate'), { now: NOW, days: 7, osv: { affecting: async () => new Map() } });
    expect(res.results.map((r) => r.id).sort()).toEqual([...KEPT_LONGER].sort());
    expect(res.results.every((r) => r.beforeWindow)).toBe(true);
    const month = await matchStack(store(), parseStack('p:acme/gate'), { now: NOW, days: 90, osv: { affecting: async () => new Map() } });
    expect(month.results.filter((r) => !r.beforeWindow).map((r) => r.id).sort()).toEqual(['CVE-2026-0012', 'CVE-2026-0013']);
  });
});

describe('catchUpHighEpss', () => {
  const SCORE_DATE = '2026-10-09';
  // CVE-2026-100107 published 200 days ago comes back; CVE-2026-100148 published 400 days ago doesn't.
  const records: Record<string, unknown> = {
    'CVE-2026-100107': withMeta(cveRecords['CVE-2026-100107']!, { datePublished: daysAgo(200) }),
    'CVE-2026-100148': withMeta(cveRecords['CVE-2026-100148']!, { datePublished: daysAgo(400) }),
  };
  const upstream = () =>
    new FakeFetch()
      .on(EPSS_URL, (req) => {
        const q = new URL(req.url).searchParams.get('q');
        const data =
          q === 'CVE-2026-'
            ? ['CVE-2026-100107', 'CVE-2026-100148', 'CVE-2026-0001'].map((cve) => ({ cve, epss: '0.300000000', percentile: '0.990000000', date: SCORE_DATE }))
            : [];
        return jsonResponse({ status: 'OK', data });
      })
      .on(RAW_BASE, (req) => {
        const id = req.url.split('/').pop()!.replace('.json', '');
        return records[id] ? jsonResponse(records[id]) : new Response('not found', { status: 404 });
      });
  const epssCursor = (scoreDate: string, lastId: string | null) => store().batch([setMetaStatement(cursorKey('epss'), { scoreDate, lastId }, NOW)]);

  it('brings back a high-EPSS CVE from the last year, and fetches each one only once', async () => {
    await insert({ id: 'CVE-2026-0001', age: 20 });
    await epssCursor(SCORE_DATE, null);
    const f = upstream();
    const first = await catchUpHighEpss(sourceContext(f.fetch, NOW), true);
    expect(first).toMatchObject({ candidates: 3, fetched: 2, stored: 1 });
    const stored = await rows<{ id: string; epss: number }>("SELECT id, epss FROM vulns WHERE id LIKE 'CVE-2026-1%'");
    expect(stored).toEqual([{ id: 'CVE-2026-100107', epss: 0.3 }]);
    // Crossing 10% is the change that brought it back.
    expect(await rows("SELECT type FROM events WHERE vuln_id = 'CVE-2026-100107'")).toEqual([{ type: 'epss_crossed' }]);

    // Same score date: nothing to do.
    const again = upstream();
    expect(await catchUpHighEpss(sourceContext(again.fetch, NOW), true)).toMatchObject({ candidates: 0, fetched: 0 });
    expect(again.calls).toHaveLength(0);

    // A new score date: the one that didn't qualify isn't fetched again.
    await epssCursor('2026-10-10', null);
    const next = upstream();
    expect(await catchUpHighEpss(sourceContext(next.fetch, NOW), true)).toMatchObject({ candidates: 3, fetched: 0 });
    expect(next.urls().some((u) => u.startsWith(RAW_BASE))).toBe(false);
    const state = JSON.parse((await rows<{ value: string }>('SELECT value FROM meta WHERE key = ?', EPSS_NET_KEY))[0]!.value);
    expect(state.checked).toEqual(['CVE-2026-100148']);
  });

  it('waits while the EPSS pass is still running', async () => {
    await epssCursor(SCORE_DATE, 'CVE-2026-0005');
    const f = upstream();
    expect(await catchUpHighEpss(sourceContext(f.fetch, NOW), true)).toMatchObject({ candidates: 0, fetched: 0 });
    expect(f.calls).toHaveLength(0);
  });
});
