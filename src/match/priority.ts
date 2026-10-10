import { EPSS_HIGH, LEV_HIGH } from '../config';
import type { SeverityLabel, Ssvc } from '../ingest/types';

/**
 * What to fix first. Two layers, both explained on every result:
 *
 * - A priority band. Act, Attend and Track are CISA's SSVC decisions; Watch
 *   sits between Attend and Track. Evidence of exploitation always outranks
 *   prediction and severity, so the bands never invert:
 *     act     on CISA KEV, or SSVC says exploitation is active; or, with no
 *             evidence yet, a critical that EPSS or LEV rates likely, EPSS of
 *             50% or more, or an edge device that is automatable with total
 *             impact (CISA BOD 26-04's 3-day case for an internet-facing
 *             system, and edge devices are the one place Vulnder knows that).
 *             Exploited results sort first and get a day; the rest get 3 days.
 *     attend  a similar CVE in the same product (its family) on KEV or
 *             actively exploited,
 *             EPSS of 10% or more, a NIST LEV estimate of 20% or more that
 *             it has already been exploited, CVSS 9.0 or more, or a
 *             proof-of-concept exploit that is automatable or gives total
 *             control, or an edge device that is automatable or gives total
 *             control (BOD 26-04: 14 days for an internet-facing system)
 *     watch   CVSS 8.0 or more, a proof-of-concept exploit, automatable (BOD
 *             26-04: 60 days even when not exposed), or an edge device CISA
 *             has assessed (60 days when exposed)
 *     track   everything else: affected, but nothing above applies
 *   No result ever gets longer than BOD 26-04 would give it, taking every
 *   system as not exposed except edge devices, which are.
 *   A low EPSS never holds a critical back a band: EPSS is often near zero in
 *   a CVE's first days. What an attacker needs to reach it (see reach()) only
 *   orders it within Attend.
 * - A 0–100 score that orders results within a band and ranks components:
 *   threat × impact × ease × edge × ransomware, in the shape Grype uses (threat from
 *   KEV or EPSS, never under 1%; impact from CVSS). Whatever earns a band also
 *   sets a floor under the threat, so a CVE never scores as if the reason for
 *   its band weren't there: a reachable critical counts as at least the EPSS that
 *   earns Attend, and one behind a login or a user's help half that. It is a
 *   heuristic for ordering, not a calibrated probability.
 */

export type Priority = 'act' | 'attend' | 'watch' | 'track';
export const PRIORITIES: Priority[] = ['act', 'attend', 'watch', 'track'];

export interface Assessment {
  priority: Priority;
  score: number;
  /** Why, most important first, e.g. ["On CISA KEV", "CVSS 8.8 (high)"]. */
  reasons: string[];
  /** The same reasons, structured: which one decided the band, and what data is missing. */
  why: Why;
  /** Suggested time to fix or mitigate, in hours; null for Track (the next routine update). */
  respondWithinHours: number | null;
}

export interface Reason {
  text: string;
  /** Evidence of exploitation, a prediction of it, how bad it is, or how reachable. */
  kind: 'evidence' | 'prediction' | 'severity' | 'context';
}

export interface Why {
  /** The rule that put it in its band; null for Track, where no rule did. */
  decisive: Reason | null;
  others: Reason[];
  /** Signals that weren't available, so a reader knows what the band couldn't use. */
  missing: string[];
}

type ReasonKey = 'active' | 'ransomware' | 'sibling' | 'epss' | 'lev' | 'poc' | 'takeover' | 'automatable' | 'total' | 'edge' | 'access' | 'cvss' | 'label';

/**
 * How soon to fix or mitigate, as guidance rather than an SLA. In 2026, working
 * exploits often appear within hours of disclosure and a third arrive on or
 * before it, so exploited bugs get a day: the short end of the 24–48 hour
 * "tier zero" guidance, since Vulnder doesn't know which systems face the
 * internet. Someone with an air-gapped system can decide to wait. Act now with
 * no exploitation yet gets BOD 26-04's 3 days. The rest follow the common 7-
 * and 30-day remediation windows.
 */
export function respondWithin(priority: Priority, exploited = true): number | null {
  switch (priority) {
    case 'act':
      return exploited ? 24 : 72;
    case 'attend':
      return 7 * 24;
    case 'watch':
      return 30 * 24;
    case 'track':
      return null;
  }
}

export interface Signals {
  kevAddedAt: string | null;
  knownRansomware: boolean;
  epss: number | null;
  /** NIST LEV: lower-bound chance it has already been exploited (src/lib/lev.ts). */
  lev: number | null;
  /** An exploited CVE in its family, similar and in the same product (src/ingest/families.ts), if any. */
  exploitedSibling: string | null;
  cvss: number | null;
  cvssVector: string | null;
  /** The CNA's or GitHub's severity word; counts only when there is no CVSS score. */
  severityLabel?: SeverityLabel | null;
  ssvc: Ssvc | null;
  /**
   * A stack item it matched is an edge device (src/stack/teams.ts isEdgeDevice).
   * It lifts the score only: the priority never depends on it, so a wrong
   * guess can't push anything down.
   */
  edge?: boolean;
}

const CRITICAL_CVSS = 9;
/** EPSS that says exploitation within 30 days is more likely than not: Act now on that alone. */
const EPSS_VERY_HIGH = 0.5;
const WATCH_CVSS = 8;
/** From here up, results say whether an attacker can reach the bug. */
const HIGH_CVSS = 7;
/**
 * The least threat anything gets, scored by EPSS or not (usually a new one).
 * A tiny EPSS shouldn't rank a CVE below one EPSS knows nothing about.
 */
const MIN_THREAT = 0.01;
/** A critical that needs a login, a user's help or local access: it's in Attend, below the ones anyone can reach. */
const GUARDED_CRITICAL_THREAT = EPSS_HIGH / 2;
/** A public proof-of-concept counts as at least this much threat. */
const POC_THREAT = 0.2;
/** An exploited CVE in the same family: attackers are already working that code. */
const SIBLING_THREAT = 0.3;
/** Impact when no CVSS score exists: the middle of the scale. */
const UNKNOWN_IMPACT = 0.5;
/**
 * Impact from a severity word when there's no score: the low end of each band
 * (critical is CVSS 9.0+, high 7.0+). The others stay at UNKNOWN_IMPACT.
 */
const LABEL_IMPACT: Partial<Record<SeverityLabel, number>> = { critical: 0.9, high: 0.7 };
const TOTAL_IMPACT = 0.9;
const AUTOMATABLE_BOOST = 1.25;
/** VPNs, edge firewalls and gateways face the internet and fill much of KEV: the same weight as automatable. */
const EDGE_BOOST = 1.25;
const RANSOMWARE_BOOST = 1.2;

export function assess(s: Signals): Assessment {
  const exploitation = s.ssvc?.exploitation?.toLowerCase() ?? null;
  const active = s.kevAddedAt !== null || exploitation === 'active';
  const poc = exploitation === 'poc';
  const likely = s.epss !== null && s.epss >= EPSS_HIGH - 1e-9;
  // An estimate from EPSS history, so it ranks with prediction, never with evidence.
  const likelyBefore = !active && s.lev !== null && s.lev >= LEV_HIGH - 1e-9;
  // Evidence about a similar CVE, not about this one: it lifts to Attend, never to Act.
  const sibling = !active && s.exploitedSibling !== null;
  const automatable = s.ssvc?.automatable?.toLowerCase() === 'yes';
  const totalImpact = s.ssvc?.technicalImpact?.toLowerCase() === 'total';
  const severe = s.cvss !== null && s.cvss >= WATCH_CVSS;
  const access = reach(s.cvssVector);
  // CISA judging it automatable means an attacker gets there unaided, whatever
  // the vector says. With no vector to read, a critical keeps the benefit of the doubt.
  const reachable = automatable || access === null || access.barriers.length === 0;
  const high = s.cvss !== null && s.cvss >= HIGH_CVSS;
  // With no score, a source calling it critical or high still earns a look: a
  // critical rating is the advisory's own CVSS 9.0+, so it counts as critical.
  const labelled = s.cvss === null && (s.severityLabel === 'critical' || s.severityLabel === 'high') ? s.severityLabel : null;
  const critical = (s.cvss !== null && s.cvss >= CRITICAL_CVSS) || labelled === 'critical';
  // Act now with no evidence yet: a prediction strong enough on its own, a
  // critical that a prediction says is likely, or BOD 26-04's 3-day case.
  const veryLikely = !active && s.epss !== null && s.epss >= EPSS_VERY_HIGH - 1e-9;
  const criticalLikely = !active && critical && (likely || likelyBefore);
  const takeover = !active && !!s.edge && automatable && totalImpact;
  const predicted = veryLikely || criticalLikely || takeover;
  // BOD 26-04 as a floor, never looser than CISA: every item gets at least its
  // deadline for a system that isn't exposed (automatable: 60 days, so Watch),
  // and an edge device its deadline for one that is (automatable or total
  // impact: 14 days, so Attend; anything CISA has assessed: 60 days, so Watch).
  const edgeAttend = !!s.edge && (automatable || totalImpact);
  const edgeWatch = !!s.edge && s.ssvc !== null;

  const priority: Priority = active || predicted
    ? 'act'
    : sibling || likely || likelyBefore || critical || (poc && (automatable || totalImpact)) || edgeAttend
      ? 'attend'
      : severe || labelled || poc || automatable || edgeWatch
        ? 'watch'
        : 'track';

  // A critical earns Attend just as EPSS_HIGH does, so it scores at least as if
  // it had that EPSS, or half that when an attacker needs a login or help first.
  // An edge device that BOD 26-04 puts in Attend or Act now scores the same.
  const bandThreat = edgeAttend || (critical && reachable) ? EPSS_HIGH : critical ? GUARDED_CRITICAL_THREAT : 0;
  const threat = active ? 1 : Math.max(MIN_THREAT, s.epss ?? 0, s.lev ?? 0, poc ? POC_THREAT : 0, sibling ? SIBLING_THREAT : 0, bandThreat);
  const unscoredImpact = (s.severityLabel && LABEL_IMPACT[s.severityLabel]) ?? UNKNOWN_IMPACT;
  const impact = Math.max(s.cvss !== null ? s.cvss / 10 : unscoredImpact, totalImpact ? TOTAL_IMPACT : 0);
  const raw = threat * impact * (automatable ? AUTOMATABLE_BOOST : 1) * (s.edge ? EDGE_BOOST : 1) * (s.knownRansomware ? RANSOMWARE_BOOST : 1);
  const score = Math.round(Math.min(1, raw) * 1000) / 10;

  const all: (Reason & { key: ReasonKey })[] = [];
  const add = (key: ReasonKey, kind: Reason['kind'], text: string) => all.push({ key, kind, text });
  if (s.kevAddedAt) add('active', 'evidence', 'On CISA KEV');
  else if (exploitation === 'active') add('active', 'evidence', 'Active exploitation (CISA)');
  if (s.knownRansomware) add('ransomware', 'evidence', 'Used in ransomware');
  if (sibling) add('sibling', 'evidence', `Similar to exploited ${s.exploitedSibling} in the same product`);
  // When the prediction puts a critical in Act now, the reason says both halves.
  const onCritical = criticalLikely && !veryLikely ? ' on a critical bug' : '';
  if (likely) add('epss', 'prediction', `EPSS ${formatPct(s.epss!)}${onCritical}`);
  if (likelyBefore) add('lev', 'prediction', `NIST LEV estimate: ${formatPct(s.lev!)} chance it has already been exploited${likely ? '' : onCritical}`);
  if (poc) add('poc', 'evidence', 'Proof-of-concept exploit');
  if (takeover) add('takeover', 'context', 'Edge device an attacker can take over automatically: CISA’s 3-day case for internet-facing systems');
  else {
    // On its own it decides Watch, so then it says why that's enough.
    const automatableDecides = !totalImpact && !edgeAttend && priority === 'watch' && !severe && !labelled && !poc;
    if (automatable) add('automatable', 'context', automatableDecides ? 'Automatable: CISA sets a deadline for these even on internal systems' : 'Automatable');
    if (totalImpact) add('total', 'severity', 'Total technical impact');
    if (edgeAttend) add('edge', 'context', `Edge device with ${automatable ? 'an automatable' : 'a total-impact'} bug: CISA gives internet-facing systems 14 days`);
    else if (edgeWatch) add('edge', 'context', 'Edge device: CISA sets internet-facing systems a deadline for every bug it assesses');
    else if (s.edge) add('edge', 'context', 'Edge device: VPNs, firewalls and gateways are a top target');
  }
  if (access && high) add('access', 'context', describeAccess(access.barriers));
  if (s.cvss !== null) add('cvss', 'severity', `CVSS ${s.cvss.toFixed(1)} (${severity(s.cvss)})`);
  if (labelled) add('label', 'severity', `Rated ${labelled} by its advisory (no CVSS score yet)`);

  // The first rule that put it in its band, in the order the band checks them.
  const decidedBy: ReasonKey | null =
    priority === 'act'
      ? active ? 'active' : veryLikely || (criticalLikely && likely) ? 'epss' : criticalLikely ? 'lev' : 'takeover'
      : priority === 'attend'
        ? sibling ? 'sibling' : likely ? 'epss' : likelyBefore ? 'lev' : critical ? (labelled ? 'label' : 'cvss') : poc ? 'poc' : 'edge'
        : priority === 'watch'
          ? severe ? 'cvss' : labelled ? 'label' : poc ? 'poc' : automatable ? (totalImpact ? 'total' : 'automatable') : 'edge'
          : null;
  const decisive = all.find((r) => r.key === decidedBy) ?? null;
  const strip = ({ text, kind }: Reason): Reason => ({ text, kind });

  const missing: string[] = [];
  if (!active && !s.ssvc) missing.push('No CISA assessment of exploitation, automation or impact yet');
  if (s.cvss === null) missing.push('No CVSS score yet: NVD now scores only a fraction of new CVEs');
  else if (high && !access) missing.push('No CVSS vector to tell whether an attacker can reach it');
  if (!active && s.epss === null) missing.push('Not scored by EPSS yet');

  return {
    priority,
    score,
    reasons: all.map((r) => r.text),
    why: { decisive: decisive && strip(decisive), others: all.filter((r) => r !== decisive).map(strip), missing },
    respondWithinHours: respondWithin(priority, active),
  };
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

type Ranked = Pick<Assessment, 'priority' | 'score'> & Partial<Pick<Assessment, 'respondWithinHours'>>;

/**
 * Band first, then the sooner response (in Act now, exploited before
 * predicted, so evidence always outranks prediction), then score.
 */
export function comparePriority(a: Ranked, b: Ranked): number {
  const hours = (r: Ranked) => r.respondWithinHours ?? Infinity;
  return PRIORITIES.indexOf(a.priority) - PRIORITIES.indexOf(b.priority) || hours(a) - hours(b) || b.score - a.score;
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
export function fixFirst(results: { id: string; matched: string[]; fixedVersions: string[]; assessment: Ranked }[]): FixItem[] {
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
