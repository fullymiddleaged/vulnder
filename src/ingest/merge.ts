import { EPSS_HIGH, EPSS_RISE } from '../config';
import { daysBetween, levTerm } from '../lib/lev';
import type { Ref, SourceName, Ssvc, VulnPatch } from './types';

/** A stored vulnerability, with JSON columns parsed. */
export interface VulnRecord {
  id: string;
  aliases: string[];
  title: string | null;
  summary: string | null;
  publishedAt: string | null;
  modifiedAt: string | null;
  cvssScore: number | null;
  cvssVector: string | null;
  cwe: string[];
  refs: Ref[];
  ssvc: Ssvc | null;
  epss: number | null;
  epssPercentile: number | null;
  epssDate: string | null;
  epssBaseline: number | null;
  /** Running LEV sum for the days before epssDate (src/lib/lev.ts). */
  levLog: number;
  kevAddedAt: string | null;
  kevRansomware: boolean;
  kevDueDate: string | null;
  kevRequiredAction: string | null;
  sourceFlags: number;
  provenance: Record<string, SourceName>;
  lastEventAt: string | null;
}

export type EventType = 'published' | 'kev_added' | 'epss_crossed' | 'fix_released';

export interface EventInput {
  vulnId: string;
  type: EventType;
  occurredAt: string;
  dedupeKey: string;
  detail: Record<string, unknown>;
}

export interface MergeOptions {
  /** Start of the retention window (ISO). New records outside it are skipped. */
  windowStart: string;
  /** False during backfill: EPSS values are recorded as the baseline without events. */
  epssEvents: boolean;
}

export interface MergeResult {
  /** The merged record, or null when the patch was skipped. */
  record: VulnRecord | null;
  events: EventInput[];
  /** True when the record differs from what was stored. */
  changed: boolean;
}

export const SOURCE_FLAGS: Record<SourceName, number> = { cve: 1, ghsa: 2, kev: 4, epss: 8 };

/** Higher-ranked sources win for the descriptive fields. */
const RANK: Record<SourceName, number> = { cve: 3, ghsa: 2, kev: 1, epss: 0 };

type RankedField = 'title' | 'summary' | 'publishedAt' | 'cvss' | 'ssvc';

const MAX_REFS = 40;
const FLOAT_EPSILON = 1e-9;

export function emptyRecord(id: string): VulnRecord {
  return {
    id,
    aliases: [],
    title: null,
    summary: null,
    publishedAt: null,
    modifiedAt: null,
    cvssScore: null,
    cvssVector: null,
    cwe: [],
    refs: [],
    ssvc: null,
    epss: null,
    epssPercentile: null,
    epssDate: null,
    epssBaseline: null,
    levLog: 0,
    kevAddedAt: null,
    kevRansomware: false,
    kevDueDate: null,
    kevRequiredAction: null,
    sourceFlags: 0,
    provenance: {},
    lastEventAt: null,
  };
}

/**
 * Folds one source's patch into a stored record (or creates one) and reports
 * the change events this causes. Pure: no I/O.
 */
export function mergePatch(existing: VulnRecord | null, patch: VulnPatch, opts: MergeOptions): MergeResult {
  const f = patch.fields;
  if (!existing) {
    // EPSS only ever updates; other sources create records only inside the window.
    if (patch.source === 'epss') return { record: null, events: [], changed: false };
    const inWindow =
      (f.publishedAt != null && f.publishedAt >= opts.windowStart) ||
      (f.kevAddedAt != null && f.kevAddedAt >= opts.windowStart);
    if (!inWindow) return { record: null, events: [], changed: false };
  }

  const before = existing ?? emptyRecord(patch.id);
  const rec: VulnRecord = structuredClone(before);
  rec.provenance = { ...before.provenance };
  const events: EventInput[] = [];
  const src = patch.source;

  rec.sourceFlags |= SOURCE_FLAGS[src];
  rec.aliases = unionStrings(rec.aliases, patch.aliases).filter((a) => a !== rec.id);

  // Ranked descriptive fields.
  setRanked(rec, src, 'title', 'title' in f, f.title, () => {
    rec.title = f.title ?? null;
  });
  setRanked(rec, src, 'summary', 'summary' in f, f.summary, () => {
    rec.summary = f.summary ?? null;
  });
  setRanked(rec, src, 'publishedAt', 'publishedAt' in f, f.publishedAt, () => {
    rec.publishedAt = f.publishedAt ?? null;
  });
  setRanked(rec, src, 'cvss', 'cvssScore' in f, f.cvssScore, () => {
    rec.cvssScore = f.cvssScore ?? null;
    rec.cvssVector = f.cvssVector ?? null;
  });
  setRanked(rec, src, 'ssvc', 'ssvc' in f, f.ssvc, () => {
    rec.ssvc = f.ssvc ?? null;
  });

  if (f.modifiedAt && (!rec.modifiedAt || f.modifiedAt > rec.modifiedAt)) rec.modifiedAt = f.modifiedAt;
  if (f.cwe) rec.cwe = unionStrings(rec.cwe, f.cwe);
  if (f.refs) rec.refs = unionRefs(rec.refs, f.refs);

  // KEV.
  if (f.kevAddedAt !== undefined) {
    rec.kevAddedAt = f.kevAddedAt;
    rec.kevRansomware = f.kevRansomware ?? false;
    rec.kevDueDate = f.kevDueDate ?? null;
    rec.kevRequiredAction = f.kevRequiredAction ?? null;
  }

  // EPSS.
  if (f.epss !== undefined && f.epssPercentile !== undefined && f.epssDate !== undefined) {
    mergeEpss(rec, before, f.epss, f.epssPercentile, f.epssDate, opts.epssEvents, events);
  }

  // Events that depend on a field appearing for the first time.
  if (!before.publishedAt && rec.publishedAt && rec.publishedAt >= opts.windowStart) {
    events.push({
      vulnId: rec.id,
      type: 'published',
      occurredAt: rec.publishedAt,
      dedupeKey: '',
      detail: { source: src },
    });
  }
  if (!before.kevAddedAt && rec.kevAddedAt && rec.kevAddedAt >= opts.windowStart) {
    events.push({
      vulnId: rec.id,
      type: 'kev_added',
      occurredAt: rec.kevAddedAt,
      dedupeKey: '',
      detail: { dateAdded: rec.kevAddedAt.slice(0, 10), ransomware: rec.kevRansomware, dueDate: rec.kevDueDate },
    });
  }

  for (const e of events) {
    if (!rec.lastEventAt || e.occurredAt > rec.lastEventAt) rec.lastEventAt = e.occurredAt;
  }

  const changed = existing === null || !sameRecord(before, rec);
  return { record: rec, events, changed };
}

/** Sets a ranked field when this source ranks at least as high as the one that set it. */
function setRanked(
  rec: VulnRecord,
  src: SourceName,
  field: RankedField,
  present: boolean,
  value: unknown,
  assign: () => void,
): void {
  if (!present) return;
  const owner = rec.provenance[field];
  if (value !== null && value !== undefined) {
    if (owner === undefined || RANK[src] >= RANK[owner]) {
      assign();
      rec.provenance[field] = src;
    }
  } else if (owner === src) {
    // The owning source dropped the value.
    assign();
    delete rec.provenance[field];
  }
}

/**
 * EPSS rules:
 * - crossing EPSS_HIGH upward is an event (a first-ever score at or above it counts);
 * - so is a rise of EPSS_RISE or more over the baseline, which is the value at the
 *   last event, lowered whenever the score falls below it;
 * - values are only written when they move meaningfully, to save D1 row writes.
 */
function mergeEpss(
  rec: VulnRecord,
  before: VulnRecord,
  value: number,
  percentile: number,
  date: string,
  emitEvents: boolean,
  events: EventInput[],
): void {
  const old = before.epss;
  let baseline = before.epssBaseline ?? old;
  let fired = false;

  if (emitEvents) {
    const crossed = value >= EPSS_HIGH - FLOAT_EPSILON && (old === null || old < EPSS_HIGH - FLOAT_EPSILON);
    const rose = baseline !== null && value - baseline >= EPSS_RISE - FLOAT_EPSILON;
    if (crossed || rose) {
      fired = true;
      events.push({
        vulnId: rec.id,
        type: 'epss_crossed',
        occurredAt: `${date}T00:00:00.000Z`,
        dedupeKey: date,
        detail: { from: old, to: value, percentile, date, reason: crossed ? 'threshold' : 'rise' },
      });
      baseline = value;
    }
  } else {
    baseline = value;
  }
  if (baseline === null || value < baseline) baseline = value;

  const meaningful =
    fired ||
    old === null ||
    Math.abs(value - old) >= 0.001 ||
    Math.abs(percentile - (before.epssPercentile ?? 0)) >= 0.01 ||
    baseline !== before.epssBaseline;
  if (meaningful) {
    // The old score held every day from its date until this one: fold those days into LEV.
    if (old !== null && before.epssDate) rec.levLog = before.levLog + levTerm(old, daysBetween(before.epssDate, date));
    rec.epss = value;
    rec.epssPercentile = percentile;
    rec.epssDate = date;
    rec.epssBaseline = baseline;
  }
}

function unionStrings(a: string[], b: string[]): string[] {
  return [...new Set([...a, ...b])];
}

function unionRefs(existing: Ref[], incoming: Ref[]): Ref[] {
  const byUrl = new Map<string, Ref>();
  for (const r of incoming) byUrl.set(r.url, r);
  for (const r of existing) if (!byUrl.has(r.url)) byUrl.set(r.url, r);
  return [...byUrl.values()].slice(0, MAX_REFS);
}

function sameRecord(a: VulnRecord, b: VulnRecord): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** The bits of an affected row that fix_released compares. */
export interface AffectedKeyed {
  kind: 'package' | 'product';
  ecosystem: string | null;
  packageName: string | null;
  vendor: string | null;
  product: string | null;
  fixedVersion: string | null;
}

/**
 * fix_released: for each package (or product) that previously had at least one
 * row without a fixed version, every fixed version that is new is an event.
 * Only compares rows from the same source.
 */
export function detectFixReleased(
  vulnId: string,
  before: AffectedKeyed[],
  after: AffectedKeyed[],
  occurredAt: string,
): EventInput[] {
  const key = (r: AffectedKeyed) =>
    r.kind === 'package' ? `pkg:${r.ecosystem}:${r.packageName}` : `prod:${r.vendor}/${r.product}`;
  const oldFixes = new Map<string, Set<string>>();
  const hadUnfixed = new Set<string>();
  for (const r of before) {
    const k = key(r);
    if (!oldFixes.has(k)) oldFixes.set(k, new Set());
    if (r.fixedVersion) oldFixes.get(k)!.add(r.fixedVersion);
    else hadUnfixed.add(k);
  }
  const events: EventInput[] = [];
  const seen = new Set<string>();
  for (const r of after) {
    const k = key(r);
    if (!r.fixedVersion || !hadUnfixed.has(k) || oldFixes.get(k)?.has(r.fixedVersion)) continue;
    const dedupeKey = `${k}@${r.fixedVersion}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    events.push({
      vulnId,
      type: 'fix_released',
      occurredAt,
      dedupeKey,
      detail:
        r.kind === 'package'
          ? { ecosystem: r.ecosystem, package: r.packageName, fixedVersion: r.fixedVersion }
          : { vendor: r.vendor, product: r.product, fixedVersion: r.fixedVersion },
    });
  }
  return events;
}
