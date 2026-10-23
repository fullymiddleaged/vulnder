import { EPSS_HIGH, LEV_HIGH } from '../config';
import type { SeverityLabel, Ssvc } from '../ingest/types';
import type { SupportState } from './support';

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
 *             system, and edge devices are the one place Vulnder knows that),
 *             or a critical that two trusted sources have written up, or one
 *             has called critical or urgent, in the last 30 days, whatever its
 *             EPSS (EPSS and CISA's assessment lag a new CVE; their write-ups
 *             don't).
 *             Exploited results sort first and get a day; the rest get 3 days.
 *     attend  a similar CVE in the same product (its family) on KEV or
 *             actively exploited, a Metasploit exploit module,
 *             EPSS of 10% or more, a NIST LEV estimate of 20% or more that
 *             it has already been exploited, CVSS 9.0 or more, or a
 *             proof-of-concept exploit that is automatable or gives total
 *             control, or an edge device that is automatable or gives total
 *             control (BOD 26-04: 14 days for an internet-facing system),
 *             or CVSS 8.0 or more and public for 60 days (overdue)
 *     watch   CVSS 8.0 or more, a proof-of-concept exploit, automatable (BOD
 *             26-04: 60 days even when not exposed), an edge device CISA
 *             has assessed (60 days when exposed), or CVSS 7.0 or more and
 *             public for 60 days (overdue)
 *   Public exploit code counts as a proof of concept: CISA's SSVC "poc", a
 *   reference the CVE record tags "exploit", or a Metasploit module. A Nuclei
 *   template counts as automatable when CISA hasn't rated it (a scanner
 *   automates finding the bug, the code exploiting it), but never for the edge
 *   rules or reachability, which stay CISA's. None of it is evidence of
 *   exploitation: only KEV and SSVC "active" are.
 *     track   everything else: affected, but nothing above applies
 *   No result ever gets longer than BOD 26-04 would give it, taking every
 *   system as not exposed except edge devices, which are.
 *   A low EPSS never holds a critical back a band: EPSS is often near zero in
 *   a CVE's first days. What an attacker needs to reach it (see reach()) only
 *   orders it within Attend.
 *   Overdue is checked last: an old CVE often has none of the other signals
 *   (CISA assessed it once, EPSS stays low), yet a high-severity bug still
 *   unfixed 60 days on needs fixing. It lifts the band, never the threat.
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

type ReasonKey =
  | 'active'
  | 'ransomware'
  | 'sibling'
  | 'metasploit'
  | 'epss'
  | 'lev'
  | 'poc'
  | 'takeover'
  | 'automatable'
  | 'nuclei'
  | 'total'
  | 'edge'
  | 'reported'
  | 'overdue'
  | 'access'
  | 'cvss'
  | 'label';

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
  /** Whole days since it was published; null when the record has no date. */
  ageDays?: number | null;
  /**
   * Public attack code and scanner templates: an exploit-tagged reference in
   * the CVE record, a Metasploit module (an exploit module, or only auxiliary
   * ones) and a Nuclei template (src/ingest/exploits.ts). Never evidence of exploitation.
   */
  exploit?: { ref: boolean; metasploit: 'exploit' | 'auxiliary' | null; nuclei: boolean };
  /**
   * Trusted sources that have written it up (src/ingest/reporters.ts), by
   * name, earliest first, and whole days since the REPORTS_ACT-th of them did
   * (null with fewer); and those whose post calls it critical or asks for an
   * update now, with days since the first did. Coverage, never evidence of
   * exploitation.
   */
  reported?: { sources: string[]; ageDays: number | null; urgent: string[]; urgentAgeDays: number | null } | null;
}

const CRITICAL_CVSS = 9;
/** EPSS that says exploitation within 30 days is more likely than not: Act now on that alone. */
const EPSS_VERY_HIGH = 0.5;
const WATCH_CVSS = 8;
/** From here up, results say whether an attacker can reach the bug. */
const HIGH_CVSS = 7;
/**
 * Public this long, a high-severity bug is overdue: BOD 26-04's deadline for a
 * system that isn't exposed, and twice Watch's 30 days.
 */
const OVERDUE_DAYS = 60;
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
/** Trusted sources that must have written up a critical anyone can reach, for Act now. */
export const REPORTS_ACT = 2;
/** For this long after the REPORTS_ACT-th write-up; by then EPSS and CISA have caught up. */
export const REPORTS_ACT_DAYS = 30;
/** A write-up by any trusted source orders a result first within its band, like automatable. */
const REPORTED_BOOST = 1.25;

export function assess(s: Signals): Assessment {
  const exploitation = s.ssvc?.exploitation?.toLowerCase() ?? null;
  const active = s.kevAddedAt !== null || exploitation === 'active';
  // Public exploit code, by CISA's word, the record's references or Metasploit.
  const cisaPoc = exploitation === 'poc';
  const x = s.exploit;
  const hasMsfExploit = x?.metasploit === 'exploit';
  const poc = cisaPoc || !!x?.ref || (x?.metasploit ?? null) !== null;
  // A ready-made attack tool lifts to Attend, never to Act: it's availability, not use.
  const msfExploit = !active && hasMsfExploit;
  const likely = s.epss !== null && s.epss >= EPSS_HIGH - 1e-9;
  // An estimate from EPSS history, so it ranks with prediction, never with evidence.
  const likelyBefore = !active && s.lev !== null && s.lev >= LEV_HIGH - 1e-9;
  // Evidence about a similar CVE, not about this one: it lifts to Attend, never to Act.
  const sibling = !active && s.exploitedSibling !== null;
  const automatable = s.ssvc?.automatable?.toLowerCase() === 'yes';
  // A Nuclei template stands in for CISA's "automatable" only where CISA hasn't rated it.
  const scannable = !!x?.nuclei && !s.ssvc?.automatable;
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
  // Written up by trusted sources while EPSS and CISA catch up: Act now for a
  // critical two of them have written up, or one has called critical or
  // urgent, whatever its EPSS. One with EPSS of 10% or more is Act already, so
  // this lifts the ones EPSS hasn't scored or scores low.
  const reporters = s.reported?.sources ?? [];
  const urgentBy = s.reported?.urgent ?? [];
  const recent = (days: number | null | undefined) => days != null && days <= REPORTS_ACT_DAYS;
  const widelyReported = reporters.length >= REPORTS_ACT && recent(s.reported?.ageDays);
  const calledUrgent = urgentBy.length > 0 && recent(s.reported?.urgentAgeDays);
  const reportedCritical = !active && critical && (widelyReported || calledUrgent);
  const predicted = veryLikely || criticalLikely || takeover || reportedCritical;
  // BOD 26-04 as a floor, never looser than CISA: every item gets at least its
  // deadline for a system that isn't exposed (automatable: 60 days, so Watch),
  // and an edge device its deadline for one that is (automatable or total
  // impact: 14 days, so Attend; anything CISA has assessed: 60 days, so Watch).
  const edgeAttend = !!s.edge && (automatable || totalImpact);
  const edgeWatch = !!s.edge && s.ssvc !== null;
  const pocAttend = poc && (automatable || scannable || totalImpact);
  // Still affected long after it was published: Attend from CVSS 8.0, Watch from 7.0.
  const overdue = high && s.ageDays != null && s.ageDays >= OVERDUE_DAYS;

  const priority: Priority = active || predicted
    ? 'act'
    : sibling || msfExploit || likely || likelyBefore || critical || pocAttend || edgeAttend || (overdue && severe)
      ? 'attend'
      : severe || labelled || poc || automatable || scannable || edgeWatch || overdue
        ? 'watch'
        : 'track';

  // A critical earns Attend just as EPSS_HIGH does, so it scores at least as if
  // it had that EPSS, or half that when an attacker needs a login or help first.
  // An edge device that BOD 26-04 puts in Attend or Act now scores the same.
  const bandThreat = edgeAttend || (critical && reachable) ? EPSS_HIGH : critical ? GUARDED_CRITICAL_THREAT : 0;
  // A Metasploit exploit module counts like an exploited sibling: a ready path to attack, short of evidence.
  const threat = active
    ? 1
    : Math.max(MIN_THREAT, s.epss ?? 0, s.lev ?? 0, poc ? POC_THREAT : 0, sibling || msfExploit ? SIBLING_THREAT : 0, bandThreat);
  const unscoredImpact = (s.severityLabel && LABEL_IMPACT[s.severityLabel]) ?? UNKNOWN_IMPACT;
  const impact = Math.max(s.cvss !== null ? s.cvss / 10 : unscoredImpact, totalImpact ? TOTAL_IMPACT : 0);
  const raw =
    threat *
    impact *
    (automatable || scannable ? AUTOMATABLE_BOOST : 1) *
    (s.edge ? EDGE_BOOST : 1) *
    (s.knownRansomware ? RANSOMWARE_BOOST : 1) *
    (reporters.length > 0 ? REPORTED_BOOST : 1);
  const score = Math.round(Math.min(1, raw) * 1000) / 10;

  const all: (Reason & { key: ReasonKey })[] = [];
  const add = (key: ReasonKey, kind: Reason['kind'], text: string) => all.push({ key, kind, text });
  if (s.kevAddedAt) add('active', 'evidence', 'On CISA KEV');
  else if (exploitation === 'active') add('active', 'evidence', 'Active exploitation (CISA)');
  if (s.knownRansomware) add('ransomware', 'evidence', 'Used in ransomware');
  if (sibling) add('sibling', 'evidence', `Similar to exploited ${s.exploitedSibling} in the same product`);
  if (hasMsfExploit) add('metasploit', 'evidence', 'Metasploit module: a ready-made attack tool');
  // When the prediction puts a critical in Act now, the reason says both halves.
  const onCritical = criticalLikely && !veryLikely ? ' on a critical bug' : '';
  if (likely) add('epss', 'prediction', `EPSS ${formatPct(s.epss!)}${onCritical}`);
  if (likelyBefore) add('lev', 'prediction', `NIST LEV estimate: ${formatPct(s.lev!)} chance it has already been exploited${likely ? '' : onCritical}`);
  // A Metasploit exploit module has its own reason; otherwise say where the code is.
  const pocText = cisaPoc
    ? 'Proof-of-concept exploit'
    : x?.ref
      ? 'Public exploit code (reference in the CVE record)'
      : x?.metasploit === 'auxiliary'
        ? 'Public exploit code (Metasploit auxiliary module)'
        : null;
  if (poc && pocText) add('poc', 'evidence', pocText);
  if (takeover) add('takeover', 'context', 'Edge device an attacker can take over automatically: CISA’s 3-day case for internet-facing systems');
  else {
    // On its own it decides Watch, so then it says why that's enough.
    const automatableDecides = !totalImpact && !edgeAttend && priority === 'watch' && !severe && !labelled && !poc;
    if (automatable) add('automatable', 'context', automatableDecides ? 'Automatable: CISA sets a deadline for these even on internal systems' : 'Automatable');
    if (scannable) add('nuclei', 'context', 'Nuclei scanner template: can be mass-scanned');
    if (totalImpact) add('total', 'severity', 'Total technical impact');
    if (edgeAttend) add('edge', 'context', `Edge device with ${automatable ? 'an automatable' : 'a total-impact'} bug: CISA gives internet-facing systems 14 days`);
    else if (edgeWatch) add('edge', 'context', 'Edge device: CISA sets internet-facing systems a deadline for every bug it assesses');
    else if (s.edge) add('edge', 'context', 'Edge device: VPNs, firewalls and gateways are a top target');
  }
  if (reportedCritical) {
    const who = widelyReported ? `reported by ${listNames(reporters)}` : `${listNames(urgentBy)} ${urgentBy.length === 1 ? 'calls' : 'call'} urgent`;
    add('reported', 'context', `Critical bug ${who}: Act now while EPSS and CISA catch up`);
  }
  else if (reporters.length > 0) add('reported', 'context', `Reported by ${listNames(reporters)}`);
  // Said only where it holds the band, so Act now results don't carry it.
  if (overdue && priority === (severe ? 'attend' : 'watch')) {
    add('overdue', 'context', `Public for ${formatAge(s.ageDays!)} at CVSS ${severe ? '8.0' : '7.0'} or more: a fix is overdue`);
  }
  if (access && high) add('access', 'context', describeAccess(access.barriers));
  if (s.cvss !== null) add('cvss', 'severity', `CVSS ${s.cvss.toFixed(1)} (${severity(s.cvss)})`);
  if (labelled) add('label', 'severity', `Rated ${labelled} by its advisory (no CVSS score yet)`);

  // The first rule that put it in its band, in the order the band checks them.
  const first = (rules: [boolean, ReasonKey][]) => rules.find(([holds]) => holds)?.[1] ?? null;
  const decidedBy: ReasonKey | null =
    priority === 'act'
      ? first([[active, 'active'], [veryLikely || (criticalLikely && likely), 'epss'], [criticalLikely, 'lev'], [takeover, 'takeover'], [true, 'reported']])
      : priority === 'attend'
        ? first([
            [sibling, 'sibling'],
            [msfExploit, 'metasploit'],
            [likely, 'epss'],
            [likelyBefore, 'lev'],
            [critical, labelled ? 'label' : 'cvss'],
            [pocAttend, 'poc'],
            [edgeAttend, 'edge'],
            [true, 'overdue'],
          ])
        : priority === 'watch'
          ? first([
              [severe, 'cvss'],
              [!!labelled, 'label'],
              [poc, 'poc'],
              [automatable, totalImpact ? 'total' : 'automatable'],
              [scannable, 'nuclei'],
              [edgeWatch, 'edge'],
              [true, 'overdue'],
            ])
          : null;
  const decisive = all.find((r) => r.key === decidedBy) ?? null;
  const strip = ({ text, kind }: Reason): Reason => ({ text, kind });

  const missing: string[] = [];
  if (!active && !s.ssvc) missing.push('No CISA Vulnrichment assessment of exploitation, automation or impact yet');
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

/** "Huntress", "Huntress and Rapid7", "Huntress, Rapid7 and CERT-EU". */
function listNames(names: string[]): string {
  return names.length <= 1 ? (names[0] ?? '') : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

function formatPct(v: number): string {
  return `${(v * 100).toFixed(v < 0.1 ? 1 : 0)}%`;
}

/** "75 days", "17 months", "3 years". */
export function formatAge(days: number): string {
  if (days < 90) return `${days} days`;
  if (days < 730) return `${Math.floor(days / 30.44)} months`;
  return `${Math.floor(days / 365.25)} years`;
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
  /** Its vendor support (src/match/support.ts), when it's out of support, losing it soon, or on paid extended support. */
  support?: SupportState;
  /** True when it groups listed CVEs rather than naming a stack item: their product, or one CVE with none. */
  listed?: boolean;
  /** The product's display name, for a listed group. */
  label?: string;
}

/**
 * Stack items ranked by what fixing them removes: the item with the most
 * urgent band first, then by summed score. One upgrade usually closes several
 * CVEs, so this is the order to work in. An item out of support ranks with Act
 * and one losing support soon with Attend, whatever its CVEs: no fix will come
 * for the next one. That orders items only; it never changes a CVE's band.
 */
export function fixFirst(
  results: { id: string; matched: string[]; fixedVersions: string[]; assessment: Ranked }[],
  support: ReadonlyMap<string, SupportState> = new Map(),
): FixItem[] {
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
  for (const f of items.values()) {
    f.score = Math.round(f.score * 10) / 10;
    const s = support.get(f.item);
    if (s) f.support = s;
  }
  const lifted = (f: FixItem) => (f.support === 'eol' ? 0 : f.support === 'ending' ? 1 : -1);
  const worst = (f: FixItem) => {
    const byCves = PRIORITIES.findIndex((p) => f.counts[p] > 0);
    const bySupport = lifted(f);
    return bySupport < 0 ? byCves : Math.min(byCves, bySupport);
  };
  return [...items.values()].sort((a, b) => worst(a) - worst(b) || b.score - a.score || a.item.localeCompare(b.item));
}
