import { describe, expect, it } from 'vitest';
import { detectFixReleased, emptyRecord, mergePatch, type VulnRecord } from '../src/ingest/merge';
import type { VulnPatch } from '../src/ingest/types';

const opts = { windowStart: '2026-07-06T00:00:00.000Z', epssEvents: true };

const cvePatch = (over: Partial<VulnPatch['fields']> = {}): VulnPatch => ({
  source: 'cve',
  id: 'CVE-2026-0001',
  aliases: [],
  fields: { title: 'CVE title', summary: 'CVE summary', publishedAt: '2026-10-01T00:00:00.000Z', cvssScore: 9.8, cvssVector: 'CVSS:3.1/X', ...over },
});

const ghsaPatch = (over: Partial<VulnPatch['fields']> = {}): VulnPatch => ({
  source: 'ghsa',
  id: 'CVE-2026-0001',
  aliases: ['GHSA-xxxx-yyyy-zzzz'],
  fields: { title: 'GHSA title', summary: 'GHSA summary', publishedAt: '2026-10-02T00:00:00.000Z', cvssScore: 5, cvssVector: 'CVSS:4.0/Y', ...over },
});

function stored(over: Partial<VulnRecord> = {}): VulnRecord {
  return { ...emptyRecord('CVE-2026-0001'), publishedAt: '2026-10-01T00:00:00.000Z', ...over };
}

function epss(value: number, date = '2026-10-04', percentile = 0.5): VulnPatch {
  return { source: 'epss', id: 'CVE-2026-0001', aliases: [], fields: { epss: value, epssPercentile: percentile, epssDate: date } };
}

describe('retention on insert', () => {
  it('creates records published inside the window, with a published event', () => {
    const r = mergePatch(null, cvePatch(), opts);
    expect(r.record?.title).toBe('CVE title');
    expect(r.events).toEqual([
      expect.objectContaining({ type: 'published', occurredAt: '2026-10-01T00:00:00.000Z', dedupeKey: '' }),
    ]);
    expect(r.record?.lastEventAt).toBe('2026-10-01T00:00:00.000Z');
  });

  it('accepts a record published exactly at the window start', () => {
    expect(mergePatch(null, cvePatch({ publishedAt: opts.windowStart }), opts).record).not.toBeNull();
  });

  it('skips records published before the window', () => {
    const r = mergePatch(null, cvePatch({ publishedAt: '2026-07-05T23:59:59.999Z' }), opts);
    expect(r.record).toBeNull();
    expect(r.events).toEqual([]);
  });

  it('keeps an old CVE that was added to KEV inside the window', () => {
    const kev: VulnPatch = {
      source: 'kev',
      id: 'CVE-2020-29583',
      aliases: [],
      fields: { title: 'KEV name', kevAddedAt: '2026-10-02T00:00:00.000Z', kevRansomware: true, kevDueDate: null },
    };
    const r = mergePatch(null, kev, opts);
    expect(r.record?.kevAddedAt).toBe('2026-10-02T00:00:00.000Z');
    expect(r.events.map((e) => e.type)).toEqual(['kev_added']);
    expect(r.events[0]!.detail).toMatchObject({ dateAdded: '2026-10-02', ransomware: true });
  });

  it('never creates a record from EPSS alone', () => {
    expect(mergePatch(null, epss(0.5), opts).record).toBeNull();
  });
});

describe('source ranking', () => {
  it('lets the CVE record override GitHub text', () => {
    const afterGhsa = mergePatch(null, ghsaPatch(), opts).record!;
    const merged = mergePatch(afterGhsa, cvePatch(), opts).record!;
    expect(merged.title).toBe('CVE title');
    expect(merged.cvssScore).toBe(9.8);
    expect(merged.publishedAt).toBe('2026-10-01T00:00:00.000Z');
    expect(merged.provenance).toMatchObject({ title: 'cve', cvss: 'cve' });
    expect(merged.sourceFlags).toBe(1 | 2);
    expect(merged.aliases).toEqual(['GHSA-xxxx-yyyy-zzzz']);
  });

  it('does not let GitHub override the CVE record', () => {
    const afterCve = mergePatch(null, cvePatch(), opts).record!;
    const merged = mergePatch(afterCve, ghsaPatch(), opts).record!;
    expect(merged.title).toBe('CVE title');
    expect(merged.cvssVector).toBe('CVSS:3.1/X');
  });

  it('lets a lower source fill a field the higher one left empty', () => {
    const afterCve = mergePatch(null, cvePatch({ title: null, cvssScore: null, cvssVector: null }), opts).record!;
    const merged = mergePatch(afterCve, ghsaPatch(), opts).record!;
    expect(merged.title).toBe('GHSA title');
    expect(merged.cvssScore).toBe(5);
  });

  it("ranks severity words like scores: the CNA's over GitHub's, and GitHub's when the CNA gives none", () => {
    const fromGhsa = mergePatch(null, ghsaPatch({ severityLabel: 'critical' }), opts).record!;
    expect(mergePatch(fromGhsa, cvePatch({ severityLabel: 'high' }), opts).record!).toMatchObject({ severityLabel: 'high', provenance: { severity: 'cve' } });
    expect(mergePatch(fromGhsa, cvePatch({ severityLabel: null }), opts).record!).toMatchObject({ severityLabel: 'critical', provenance: { severity: 'ghsa' } });
  });

  it('clears a field when the source that set it drops it', () => {
    const first = mergePatch(null, cvePatch(), opts).record!;
    const second = mergePatch(first, cvePatch({ title: null }), opts).record!;
    expect(second.title).toBeNull();
    expect(second.provenance.title).toBeUndefined();
  });

  it('unions CWEs and references, and keeps the newest modifiedAt', () => {
    const a = mergePatch(null, cvePatch({ cwe: ['CWE-79'], refs: [{ url: 'https://a' }], modifiedAt: '2026-10-03T00:00:00.000Z' }), opts).record!;
    const b = mergePatch(a, ghsaPatch({ cwe: ['CWE-79', 'CWE-89'], refs: [{ url: 'https://b' }], modifiedAt: '2026-10-02T00:00:00.000Z' }), opts).record!;
    expect(b.cwe).toEqual(['CWE-79', 'CWE-89']);
    expect(b.refs.map((r) => r.url).sort()).toEqual(['https://a', 'https://b']);
    expect(b.modifiedAt).toBe('2026-10-03T00:00:00.000Z');
  });

  it('reports no change when a patch repeats what is stored', () => {
    const first = mergePatch(null, cvePatch(), opts).record!;
    const again = mergePatch(first, cvePatch(), opts);
    expect(again.changed).toBe(false);
    expect(again.events).toEqual([]);
  });
});

describe('published and kev_added events', () => {
  it('fires published when a KEV stub later gets its publication date', () => {
    const stub = stored({ publishedAt: null, kevAddedAt: '2026-10-02T00:00:00.000Z' });
    const r = mergePatch(stub, cvePatch({ publishedAt: '2026-09-30T00:00:00.000Z' }), opts);
    expect(r.events.map((e) => e.type)).toEqual(['published']);
  });

  it('fires kev_added once, and not for an addition before the window', () => {
    const rec = stored();
    const kev = (date: string): VulnPatch => ({ source: 'kev', id: rec.id, aliases: [], fields: { kevAddedAt: date } });
    const first = mergePatch(rec, kev('2026-10-02T00:00:00.000Z'), opts);
    expect(first.events.map((e) => e.type)).toEqual(['kev_added']);
    expect(mergePatch(first.record, kev('2026-10-02T00:00:00.000Z'), opts).events).toEqual([]);
    expect(mergePatch(rec, kev('2021-11-03T00:00:00.000Z'), opts).events).toEqual([]);
  });
});

describe('EPSS', () => {
  it('fires at exactly the 0.10 threshold', () => {
    const r = mergePatch(stored({ epss: 0.05, epssBaseline: 0.05 }), epss(0.1), opts);
    expect(r.events).toEqual([
      expect.objectContaining({ type: 'epss_crossed', dedupeKey: '2026-10-04', occurredAt: '2026-10-04T00:00:00.000Z' }),
    ]);
    expect(r.events[0]!.detail).toMatchObject({ from: 0.05, to: 0.1, reason: 'threshold' });
    expect(r.record?.epssBaseline).toBe(0.1);
  });

  it('does not fire just below the threshold', () => {
    expect(mergePatch(stored({ epss: 0.05, epssBaseline: 0.05 }), epss(0.0999), opts).events).toEqual([]);
  });

  it('treats a first score at or above the threshold as a crossing', () => {
    expect(mergePatch(stored(), epss(0.1), opts).events).toHaveLength(1);
    expect(mergePatch(stored(), epss(0.0999), opts).events).toHaveLength(0);
  });

  it('does not fire again while staying above the threshold', () => {
    expect(mergePatch(stored({ epss: 0.2, epssBaseline: 0.2 }), epss(0.25), opts).events).toEqual([]);
  });

  it('fires on a rise of exactly 0.10 over the baseline', () => {
    // 0.3 - 0.2 is 0.09999999999999998 in floating point; the rule must still hold.
    const r = mergePatch(stored({ epss: 0.2, epssBaseline: 0.2 }), epss(0.3), opts);
    expect(r.events.map((e) => e.detail.reason)).toEqual(['rise']);
    expect(r.record?.epssBaseline).toBe(0.3);
  });

  it('does not fire on a rise just under 0.10', () => {
    expect(mergePatch(stored({ epss: 0.2, epssBaseline: 0.2 }), epss(0.2999), opts).events).toEqual([]);
  });

  it('measures rises from the lowest point since the last event', () => {
    const dipped = mergePatch(stored({ epss: 0.3, epssBaseline: 0.3 }), epss(0.15, '2026-10-04'), opts).record!;
    expect(dipped.epssBaseline).toBe(0.15);
    const r = mergePatch(dipped, epss(0.25, '2026-10-05'), opts);
    expect(r.events.map((e) => e.detail.reason)).toEqual(['rise']);
  });

  it('records the baseline without events during backfill', () => {
    const r = mergePatch(stored(), epss(0.9), { ...opts, epssEvents: false });
    expect(r.events).toEqual([]);
    expect(r.record).toMatchObject({ epss: 0.9, epssBaseline: 0.9 });
  });

  it('skips writing insignificant movements', () => {
    const rec = stored({ epss: 0.0004, epssPercentile: 0.12, epssDate: '2026-10-03', epssBaseline: 0.0004, sourceFlags: 8 });
    const r = mergePatch(rec, epss(0.00045, '2026-10-04', 0.121), opts);
    expect(r.changed).toBe(false);
    expect(r.record?.epssDate).toBe('2026-10-03');
  });

  it('writes a movement of 0.001 or more', () => {
    const rec = stored({ epss: 0.0004, epssPercentile: 0.12, epssDate: '2026-10-03', epssBaseline: 0.0004, sourceFlags: 8 });
    expect(mergePatch(rec, epss(0.0014, '2026-10-04', 0.12), opts).changed).toBe(true);
  });
});

describe('LEV accumulation', () => {
  it('starts at zero: a first score has no held days behind it', () => {
    expect(mergePatch(stored(), epss(0.3, '2026-10-04'), opts).record!.levLog).toBe(0);
  });

  it('folds the days the old score held into lev_log when the score moves', () => {
    const rec = stored({ epss: 0.3, epssPercentile: 0.9, epssDate: '2026-09-24', epssBaseline: 0.3, sourceFlags: 8, levLog: -0.05 });
    const r = mergePatch(rec, epss(0.6, '2026-10-04', 0.95), opts).record!;
    // 0.3 held 10 days (24 Sep to 3 Oct); 4 Oct is the new score's first day.
    expect(r.levLog).toBeCloseTo(-0.05 + 10 * Math.log1p(-0.3 / 30), 12);
    expect(r.epssDate).toBe('2026-10-04');
  });

  it('leaves lev_log alone when a movement is too small to write', () => {
    const rec = stored({ epss: 0.3, epssPercentile: 0.9, epssDate: '2026-09-24', epssBaseline: 0.3, sourceFlags: 8, levLog: -0.05 });
    const r = mergePatch(rec, epss(0.3004, '2026-10-04', 0.9), opts);
    expect(r.changed).toBe(false);
    expect(r.record!.levLog).toBe(-0.05);
  });

  it('never adds days for a score dated before the one held', () => {
    const rec = stored({ epss: 0.3, epssPercentile: 0.9, epssDate: '2026-10-04', epssBaseline: 0.3, sourceFlags: 8 });
    expect(mergePatch(rec, epss(0.6, '2026-10-01', 0.95), opts).record!.levLog).toBe(0);
  });
});

describe('detectFixReleased', () => {
  const pkg = (fixedVersion: string | null, name = 'podman') => ({
    kind: 'package' as const,
    ecosystem: 'Go',
    packageName: name,
    vendor: null,
    product: null,
    fixedVersion,
  });

  it('fires when a package without a fix gets one', () => {
    const events = detectFixReleased('CVE-1', [pkg(null)], [pkg('5.6.1')], '2026-10-04T00:00:00.000Z');
    expect(events).toEqual([
      expect.objectContaining({ type: 'fix_released', dedupeKey: 'pkg:Go:podman@5.6.1', detail: expect.objectContaining({ fixedVersion: '5.6.1' }) }),
    ]);
  });

  it('fires for a new branch fix alongside an existing one', () => {
    const events = detectFixReleased('CVE-1', [pkg('5.6.1'), pkg(null)], [pkg('5.6.1'), pkg('4.9.6')], 'x');
    expect(events.map((e) => e.dedupeKey)).toEqual(['pkg:Go:podman@4.9.6']);
  });

  it('stays quiet when every row already had a fix', () => {
    expect(detectFixReleased('CVE-1', [pkg('1.0.1')], [pkg('1.0.2')], 'x')).toEqual([]);
  });

  it('stays quiet when nothing was known before', () => {
    expect(detectFixReleased('CVE-1', [], [pkg('1.0.1')], 'x')).toEqual([]);
  });

  it('keeps packages apart', () => {
    expect(detectFixReleased('CVE-1', [pkg(null, 'a'), pkg('1', 'b')], [pkg(null, 'a'), pkg('2', 'b')], 'x')).toEqual([]);
  });
});
