import { EPSS_HIGH } from '../config';
import type { Ssvc } from '../ingest/types';

/**
 * What to fix first. Two layers, both explained on every result:
 *
 * - A priority band. Act, Attend and Track are CISA's SSVC decisions; Watch
 *   sits between Attend and Track. Evidence of exploitation always outranks
 *   prediction and severity, so the bands never invert:
 *     act     on CISA KEV, or SSVC says exploitation is active
 *     attend  EPSS of 10% or more, CVSS 9.0 or more that an attacker can
 *             reach (see reach()), or a proof-of-concept exploit that is
 *             automatable or gives total control
 *     watch   CVSS 8.0 or more, CVSS 7.0 or more open to attack on an
 *             internet-facing item, a proof-of-concept exploit, or automatable
 *             with total control
 *     track   everything else: affected, but nothing above applies
 *   A critical score alone says how bad a bug is, not whether anyone can get
 *   at it: one that needs local access, a login or a user's help waits in
 *   Watch unless something else lifts it.
 * - A 0–100 score that orders results within a band and ranks components:
 *   threat × impact × ease × exposure × ransomware, in the shape Grype uses (threat from
 *   KEV or EPSS, 1% while EPSS hasn't scored it; impact from CVSS). It is a heuristic for ordering, not a
 *   calibrated probability.
 */

export type Priority = 'act' | 'attend' | 'watch' | 'track';
export const PRIORITIES: Priority[] = ['act', 'attend', 'watch', 'track'];

export interface Assessment {
  priority: Priority;
  score: number;
  /** Why, most important first, e.g. ["On CISA KEV", "CVSS 8.8 (high)"]. */
  reasons: string[];
}

export interface Signals {
  kevAddedAt: string | null;
  knownRansomware: boolean;
  epss: number | null;
  cvss: number | null;
  cvssVector: string | null;
  ssvc: Ssvc | null;
  /** A stack item it matched is marked internet-facing. */
  exposed: boolean;
}

const CRITICAL_CVSS = 9;
const WATCH_CVSS = 8;
/** From here up, results say whether an attacker can reach the bug. */
const HIGH_CVSS = 7;
/** Threat for a CVE that EPSS hasn't scored yet (usually a new one). */
const UNSCORED_THREAT = 0.01;
/** A public proof-of-concept counts as at least this much threat. */
const POC_THREAT = 0.2;
/** Impact when no CVSS score exists: the middle of the scale. */
const UNKNOWN_IMPACT = 0.5;
const TOTAL_IMPACT = 0.9;
const AUTOMATABLE_BOOST = 1.25;
/** An internet-facing item with a bug open to attack: the same weight as automatable. */
const EXPOSED_BOOST = 1.25;
const RANSOMWARE_BOOST = 1.2;

export function assess(s: Signals): Assessment {
  const exploitation = s.ssvc?.exploitation?.toLowerCase() ?? null;
  const active = s.kevAddedAt !== null || exploitation === 'active';
  const poc = exploitation === 'poc';
  const likely = s.epss !== null && s.epss >= EPSS_HIGH - 1e-9;
  const automatable = s.ssvc?.automatable?.toLowerCase() === 'yes';
  const totalImpact = s.ssvc?.technicalImpact?.toLowerCase() === 'total';
  const critical = s.cvss !== null && s.cvss >= CRITICAL_CVSS;
  const severe = s.cvss !== null && s.cvss >= WATCH_CVSS;
  const access = reach(s.cvssVector);
  // CISA judging it automatable means an attacker gets there unaided, whatever
  // the vector says. With no vector to read, a critical keeps the benefit of the doubt.
  const reachable = automatable || access === null || access.barriers.length === 0;
  // On an item facing the internet, only positive evidence that the bug is open
  // to attack counts: no benefit of the doubt for a missing vector.
  const exposedOpen = s.exposed && (automatable || (access !== null && access.barriers.length === 0));
  const high = s.cvss !== null && s.cvss >= HIGH_CVSS;

  const priority: Priority = active
    ? 'act'
    : likely || (critical && reachable) || (poc && (automatable || totalImpact))
      ? 'attend'
      : severe || (high && exposedOpen) || poc || (automatable && totalImpact)
        ? 'watch'
        : 'track';

  const threat = active ? 1 : Math.max(s.epss ?? UNSCORED_THREAT, poc ? POC_THREAT : 0);
  const impact = Math.max(s.cvss !== null ? s.cvss / 10 : UNKNOWN_IMPACT, totalImpact ? TOTAL_IMPACT : 0);
  const raw =
    threat * impact * (automatable ? AUTOMATABLE_BOOST : 1) * (exposedOpen ? EXPOSED_BOOST : 1) * (s.knownRansomware ? RANSOMWARE_BOOST : 1);
  const score = Math.round(Math.min(1, raw) * 1000) / 10;

  const reasons: string[] = [];
  if (s.kevAddedAt) reasons.push('On CISA KEV');
  else if (exploitation === 'active') reasons.push('Active exploitation (CISA)');
  if (s.knownRansomware) reasons.push('Used in ransomware');
  if (likely) reasons.push(`EPSS ${formatPct(s.epss!)}`);
  if (poc) reasons.push('Proof-of-concept exploit');
  if (automatable) reasons.push('Automatable');
  if (totalImpact) reasons.push('Total technical impact');
  if (exposedOpen) reasons.push('Internet-facing');
  if (access && high) reasons.push(describeAccess(access.barriers));
  if (s.cvss !== null) reasons.push(`CVSS ${s.cvss.toFixed(1)} (${severity(s.cvss)})`);
  return { priority, score, reasons };
}

/** What an attacker needs before they can try the bug, from the CVSS vector. */
export type Barrier = 'local access' | 'adjacent network access' | 'a login' | 'user action';

/**
 * Reads a CVSS 3.x or 4.0 vector for what stands between an attacker on the
 * internet and the bug: attack vector, privileges required and user
 * interaction. No barriers means reachable over the network without a login
 * or anyone's help. Null when there's no vector, or it isn't one we read.
 */
export function reach(vector: string | null): { barriers: Barrier[] } | null {
  if (!vector || !/^CVSS:(3\.[01]|4\.0)\//.test(vector)) return null;
  // Records don't always list metrics in the standard order.
  const metrics = new Map(vector.split('/').slice(1).map((m) => m.split(':', 2) as [string, string]));
  const av = metrics.get('AV');
  const pr = metrics.get('PR');
  const ui = metrics.get('UI');
  if (!av || !pr || !ui) return null;
  const barriers: Barrier[] = [];
  if (av === 'L' || av === 'P') barriers.push('local access');
  else if (av === 'A') barriers.push('adjacent network access');
  if (pr !== 'N') barriers.push('a login');
  if (ui !== 'N') barriers.push('user action');
  return { barriers };
}

function describeAccess(barriers: Barrier[]): string {
  if (barriers.length === 0) return 'Reachable over the network without a login';
  const last = barriers[barriers.length - 1];
  return `Needs ${barriers.length === 1 ? last : `${barriers.slice(0, -1).join(', ')} and ${last}`}`;
}

export function severity(cvss: number): 'critical' | 'high' | 'medium' | 'low' | 'none' {
  if (cvss >= 9) return 'critical';
  if (cvss >= 7) return 'high';
  if (cvss >= 4) return 'medium';
  if (cvss > 0) return 'low';
  return 'none';
}

function formatPct(v: number): string {
  return `${(v * 100).toFixed(v < 0.1 ? 1 : 0)}%`;
}

export function comparePriority(a: Assessment, b: Assessment): number {
  return PRIORITIES.indexOf(a.priority) - PRIORITIES.indexOf(b.priority) || b.score - a.score;
}

export interface FixItem {
  /** The stack item, as matched (a leading '?' marks a close match). */
  item: string;
  /** Sum of its CVEs' scores: what fixing this item removes. */
  score: number;
  counts: Record<Priority, number>;
  /** Its CVEs, most urgent first. */
  vulns: string[];
  /** How many of them name a fixed version. */
  fixable: number;
}

/**
 * Stack items ranked by what fixing them removes: the item with the most
 * urgent band first, then by summed score. One upgrade usually closes several
 * CVEs, so this is the order to work in.
 */
export function fixFirst(results: { id: string; matched: string[]; fixedVersions: string[]; assessment: Assessment }[]): FixItem[] {
  const items = new Map<string, FixItem>();
  const sorted = [...results].sort((a, b) => comparePriority(a.assessment, b.assessment));
  for (const r of sorted) {
    for (const m of r.matched) {
      let f = items.get(m);
      if (!f) {
        f = { item: m, score: 0, counts: { act: 0, attend: 0, watch: 0, track: 0 }, vulns: [], fixable: 0 };
        items.set(m, f);
      }
      f.score += r.assessment.score;
      f.counts[r.assessment.priority]++;
      f.vulns.push(r.id);
      if (r.fixedVersions.length > 0) f.fixable++;
    }
  }
  for (const f of items.values()) f.score = Math.round(f.score * 10) / 10;
  const worst = (f: FixItem) => PRIORITIES.findIndex((p) => f.counts[p] > 0);
  return [...items.values()].sort((a, b) => worst(a) - worst(b) || b.score - a.score || a.item.localeCompare(b.item));
}
