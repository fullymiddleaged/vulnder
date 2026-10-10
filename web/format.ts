import { isTeam, type Team } from '../src/stack/format';
import type { Change, FixItem, PassStatus, Priority, Result } from './api';

/** Pure formatting helpers for the UI, kept DOM-free so they can be tested. */

export function describeChange(c: Change): string {
  const name = c.title ? `${c.vulnId}: ${c.title}` : c.vulnId;
  switch (c.type) {
    case 'kev_added':
      return `${name} was added to CISA KEV (known exploited).`;
    case 'epss_crossed':
      return `${name}: EPSS rose to ${pct(c.detail.to as number)} (predicted, not observed, exploitation).`;
    case 'fix_released':
      return `${name}: fix released in ${String(c.detail.package ?? c.detail.product ?? '')} ${String(c.detail.fixedVersion ?? '')}.`;
    default:
      return `${name} was published.`;
  }
}

/**
 * The playful headline above the results. Tier and evidence wording stays plain.
 * With no matches it says so only for what was recognised: `unmatched` names
 * that resolved to nothing were never checked, so "nobody's been into it" would overclaim.
 */
/** `older` of the `count` are from before the window, shown by the year-long safety net. */
export function matchHeadline(count: number, days: number, unmatched = 0, older = 0): { title: string; subtitle: string } {
  if (count === 0 && unmatched > 0) {
    const names = unmatched === 1 ? '1 name' : `${unmatched} names`;
    return { title: 'No matches.', subtitle: `Nothing in the last ${days} days for the items we recognised, but ${names} couldn't be matched and weren't checked. Add them with Edit stack.` };
  }
  if (count === 0) {
    return { title: 'No matches.', subtitle: `Nobody's been into your stack in the last ${days} days. Keep it that way.` };
  }
  const recent = count - older;
  const cves = (n: number) => `${n} ${n === 1 ? 'CVE' : 'CVEs'}`;
  const from =
    older === 0
      ? `${cves(count)} ${count === 1 ? 'is' : 'are'} into your stack from the last ${days} days.`
      : recent === 0
        ? `${cves(older)} from the last year ${older === 1 ? 'is' : 'are'} still into your stack: exploited, likely to be, or critical.`
        : `${cves(recent)} ${recent === 1 ? 'is' : 'are'} into your stack from the last ${days} days, plus ${older} older ${older === 1 ? 'one' : 'ones'} from the last year that ${older === 1 ? 'is' : 'are'} exploited, likely to be, or critical.`;
  return { title: "It's a match. Unfortunately.", subtitle: `${from} Red flags, ranked:` };
}

export function pct(v: number): string {
  return `${(v * 100).toFixed(v < 0.01 ? 2 : 1)}%`;
}

export function ordinal(n: number): string {
  const s = ['th', 'st', 'nd', 'rd'];
  const v = n % 100;
  return `${n}${s[(v - 20) % 10] ?? s[v] ?? s[0]}`;
}

export function ago(iso: string, now = Date.now()): string {
  const minutes = Math.round((now - Date.parse(iso)) / 60_000);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  return hours < 48 ? `${hours} h ago` : `${Math.round(hours / 24)} days ago`;
}

/** The text box's placeholder: one of the examples, picked at random on each visit. */
export function examplePlaceholder(examples: readonly { text: string }[], random = Math.random): string {
  const pick = examples[Math.min(examples.length - 1, Math.floor(random() * examples.length))];
  return pick ? `For example: ${pick.text}` : '';
}

/**
 * The verification widget's size for the width it has. The normal widget is a
 * fixed 300px; any wider than its box and Chrome on Android zooms the page out.
 */
export function turnstileSize(width: number): 'normal' | 'compact' {
  return width >= 300 ? 'normal' : 'compact';
}

/**
 * The description counter's text, and whether the description is too long to
 * send. Counts the trimmed text, as submitting does; manifests have no limit.
 */
export function describeLength(text: string, isManifest: boolean, max: number): { label: string; over: boolean } {
  if (isManifest) return { label: 'Manifest detected', over: false };
  const n = text.trim().length;
  return n > max ? { label: `${n} / ${max}: too long. Shorten it, or upload a manifest below`, over: true } : { label: `${n} / ${max}`, over: false };
}

/**
 * How long until a spent pass unlocks, in ms, or null when it isn't locked:
 * stacks are left this hour, or the hour is over.
 */
export function lockRemaining(pass: PassStatus | null, now = Date.now()): number | null {
  if (!pass?.active || pass.used < pass.limit || !pass.resetsAt) return null;
  const ms = Date.parse(pass.resetsAt) - now;
  return ms > 0 ? ms : null;
}

/** A wait as a clock: "59:32", "0:05". Rounds up, so it never shows 0:00 while still locked. */
export function countdown(ms: number): string {
  const seconds = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}

/** Why looking up, editing or reloading a stack is greyed out, or null when it isn't. */
export function passNotice(pass: PassStatus | null, now = Date.now()): string | null {
  const ms = lockRemaining(pass, now);
  if (ms === null) return null;
  return `You've looked up ${pass!.limit} stacks this hour, the most it allows. New lookups, edits and time windows unlock in ${countdown(ms)}.`;
}

/** Most important first: confirmed exploitation, then a jump in predicted risk, then fixes, then new CVEs. */
const CHANGE_PRIORITY: Record<Change['type'], number> = { kev_added: 0, epss_crossed: 1, fix_released: 2, published: 3 };

export const CHANGE_LABEL: Record<Change['type'], string> = {
  kev_added: 'Added to CISA KEV',
  epss_crossed: 'EPSS jump',
  fix_released: 'Fix released',
  published: 'New',
};

export interface ChangeGroup {
  vulnId: string;
  /** The full result for this CVE; absent only if the feed omitted it. */
  result: Result | undefined;
  title: string | null;
  /** This CVE's events, most important first. */
  events: Change[];
}

/**
 * One group per CVE, ordered by its most important event, then by tier
 * (exact matches before close ones), then newest first.
 */
export function groupChanges(changes: Change[], results: Result[]): ChangeGroup[] {
  const byId = new Map(results.map((r) => [r.id, r]));
  const groups = new Map<string, ChangeGroup>();
  for (const c of changes) {
    let g = groups.get(c.vulnId);
    if (!g) {
      g = { vulnId: c.vulnId, result: byId.get(c.vulnId), title: c.title, events: [] };
      groups.set(c.vulnId, g);
    }
    g.events.push(c);
  }
  const tierRank = { exploited: 0, likely: 1, backlog: 2 } as const;
  const top = (g: ChangeGroup) => Math.min(...g.events.map((e) => CHANGE_PRIORITY[e.type]));
  const latest = (g: ChangeGroup) => g.events.reduce((m, e) => (e.occurredAt > m ? e.occurredAt : m), '');
  for (const g of groups.values()) {
    g.events.sort((a, b) => CHANGE_PRIORITY[a.type] - CHANGE_PRIORITY[b.type] || b.occurredAt.localeCompare(a.occurredAt));
  }
  return [...groups.values()].sort(
    (a, b) =>
      top(a) - top(b) ||
      tierRank[a.result?.tier ?? 'backlog'] - tierRank[b.result?.tier ?? 'backlog'] ||
      (a.result?.match === b.result?.match ? 0 : a.result?.match === 'exact' ? -1 : 1) ||
      latest(b).localeCompare(latest(a)) ||
      a.vulnId.localeCompare(b.vulnId),
  );
}

/** "2 added to KEV, 1 EPSS jump, 3 fixes released, 12 new CVEs", counting CVEs, not events. */
export function changeCounts(groups: ChangeGroup[]): string {
  const count = (t: Change['type']) => groups.filter((g) => g.events.some((e) => e.type === t)).length;
  const parts: [number, string, string][] = [
    [count('kev_added'), 'added to KEV', 'added to KEV'],
    [count('epss_crossed'), 'EPSS jump', 'EPSS jumps'],
    [count('fix_released'), 'fix released', 'fixes released'],
    [count('published'), 'new CVE', 'new CVEs'],
  ];
  return parts.filter(([n]) => n > 0).map(([n, one, many]) => `${n} ${n === 1 ? one : many}`).join(', ');
}

/** The detail for one event, e.g. "2026-10-02, federal due date 2026-10-23" or "3.1% → 42.0% on 2026-10-04". */
export function eventDetail(e: Change): string {
  const day = e.occurredAt.slice(0, 10);
  switch (e.type) {
    case 'kev_added': {
      const due = typeof e.detail.dueDate === 'string' ? `, federal due date ${e.detail.dueDate.slice(0, 10)}` : '';
      const ransomware = e.detail.ransomware === true ? ', used in ransomware' : '';
      return `${day}${due}${ransomware}`;
    }
    case 'epss_crossed': {
      const from = typeof e.detail.from === 'number' ? `${pct(e.detail.from)} → ` : '';
      return typeof e.detail.to === 'number' ? `${from}${pct(e.detail.to)} on ${day}` : day;
    }
    case 'fix_released':
      return `${String(e.detail.package ?? e.detail.product ?? '')} ${String(e.detail.fixedVersion ?? '')}`.trim();
    default:
      return day;
  }
}

/** A summary on one line, without a leading Markdown heading mark. */
export function fullSummary(text: string | null): string | null {
  return text ? text.replace(/\s+/g, ' ').replace(/^#+\s*/, '').trim() || null : null;
}

/** First sentence-ish of a summary, for compact cards. */
export function shortSummary(text: string | null, max = 220): string | null {
  const clean = fullSummary(text);
  if (!clean) return null;
  return clean.length <= max ? clean : `${clean.slice(0, max).replace(/\s+\S*$/, '')}…`;
}

/**
 * Traffic lights for each priority. Colour carries priority and nothing else;
 * green is kept for good news such as a released fix.
 */
export const RISK: Record<Priority, { label: string; light: 'red' | 'amber' | 'yellow' | 'grey'; brief: string; window: string; note: string }> = {
  act: {
    label: 'Act now',
    light: 'red',
    brief: 'Being exploited now, or about to be.',
    window: 'Within 24 hours to 3 days',
    note: 'Being exploited: on CISA KEV (the US government’s list of bugs attacked in the wild), or CISA reports active exploitation. Or not yet, but close: a critical bug with EPSS of 10% or more (or NIST LEV of 20% or more), EPSS of 50% or more, or an edge device an attacker can take over automatically. Exploited ones come first.',
  },
  attend: {
    label: 'Attend',
    light: 'amber',
    brief: 'Likely to be exploited soon.',
    window: 'Within 7 days',
    note: 'Likely to be exploited, or critical: a similar bug in the same product is being exploited, EPSS of 10% or more, NIST LEV of 20% or more, CVSS 9.0 or more, a working exploit that is easy to use or gives full control, or an edge device with a bug that is automatable or gives full control.',
  },
  watch: {
    label: 'Watch',
    light: 'yellow',
    brief: 'Serious, but less pressing.',
    window: 'Within 30 days',
    note: 'High severity, a public exploit, or easy to attack at scale: CVSS 8.0 or more, a proof-of-concept exploit, a bug CISA rates automatable, or any bug CISA has assessed on an edge device.',
  },
  track: {
    label: 'Track',
    light: 'grey',
    brief: 'Affects your stack, nothing urgent.',
    window: 'In your next routine update',
    note: 'Affects your stack, but nothing above applies: lower severity, and nothing suggests exploitation.',
  },
};

/** "14 items: 12 exact, 2 close matches", for the folded stack on the results page. */
export function stackSummary(items: readonly { close?: boolean }[]): string {
  const n = items.length;
  const close = items.filter((i) => i.close).length;
  const parts = [close > 0 && n > close ? `${n - close} exact` : '', close > 0 ? `${close} close ${close === 1 ? 'match' : 'matches'}` : ''].filter(Boolean);
  return `${n} ${n === 1 ? 'item' : 'items'}${parts.length > 0 ? `: ${parts.join(', ')}` : ''}`;
}

/** Results by priority, keeping feed order within each. */
export function byPriority(results: Result[]): Record<Priority, Result[]> {
  const out: Record<Priority, Result[]> = { act: [], attend: [], watch: [], track: [] };
  for (const r of results) out[r.priority].push(r);
  return out;
}

/**
 * Folds each family (similar CVEs in the same product) in a list under its first (highest-ranked) member,
 * keeping list order. Nothing is dropped: the rest go under `related`, to show
 * on request.
 */
export function foldFamilies(results: Result[]): { lead: Result; related: Result[] }[] {
  const out: { lead: Result; related: Result[] }[] = [];
  const byFamily = new Map<string, { lead: Result; related: Result[] }>();
  for (const r of results) {
    const group = r.family && r.related.length > 0 ? byFamily.get(r.family) : undefined;
    if (group) {
      group.related.push(r);
      continue;
    }
    const entry = { lead: r, related: [] as Result[] };
    out.push(entry);
    if (r.family && r.related.length > 0) byFamily.set(r.family, entry);
  }
  return out;
}

/** The first `max` items and how many are left out; never leaves out just one, since "+1 more" takes the space the item would. */
export function preview<T>(items: T[], max: number): { shown: T[]; rest: number } {
  return items.length <= max + 1 ? { shown: items, rest: 0 } : { shown: items.slice(0, max), rest: items.length - max };
}

/** CVSS v3/v4 qualitative severity, for the CVSS badge. */
export function cvssSeverity(score: number): 'Critical' | 'High' | 'Medium' | 'Low' | 'None' {
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  if (score > 0) return 'Low';
  return 'None';
}

/** "87", or "4.2" below 10, so small scores don't all read as 0. */
export function formatScore(score: number): string {
  return score >= 10 ? String(Math.round(score)) : score.toFixed(1);
}

export interface ItemMarks {
  close: boolean;
  team: Team | null;
  /** The user's `;edge` (true) or `;internal` (false) tag; null leaves it to the product. */
  edge: boolean | null;
}

/** A stack item as the feed writes it, split into its name and its marks (`?` close match, `;team` its team, `;edge` or `;internal`). */
export function itemMarks(item: string): { name: string } & ItemMarks {
  const close = item.startsWith('?');
  let name = close ? item.slice(1) : item;
  let team: Team | null = null;
  let edge: boolean | null = null;
  for (let semi = name.lastIndexOf(';'); semi >= 0; semi = name.lastIndexOf(';')) {
    const tag = name.slice(semi + 1);
    if (edge === null && team === null && (tag === 'edge' || tag === 'internal')) edge = tag === 'edge';
    else if (team === null && isTeam(tag)) team = tag;
    else break;
    name = name.slice(0, semi);
  }
  return { name, close, team, edge };
}

/** The item written back with the given marks, in canonical order. */
export function withItemMarks(name: string, marks: ItemMarks): string {
  const edge = marks.edge === null ? '' : marks.edge ? ';edge' : ';internal';
  return `${marks.close ? '?' : ''}${name}${marks.team ? `;${marks.team}` : ''}${edge}`;
}

export interface ComponentGroup extends FixItem {
  /** The stack item, without its marks. */
  component: string;
  close: boolean;
  team: Team | null;
  /** Other stack items with exactly the same CVEs, team and edge tag, shown in this row as written in the feed. */
  also: string[];
  /** 1-based position in the fix-first order. */
  rank: number;
  results: Result[];
}

/**
 * The fix-first list with each item's results attached, in the server's order.
 * Items with exactly the same CVEs share a row, led by an exact item if there is
 * one: usually they are close matches of one vague name ("Windows Server"), and
 * a row each would repeat the same list.
 */
export function componentGroups(fixFirst: FixItem[], results: Result[]): ComponentGroup[] {
  const byId = new Map(results.map((r) => [r.id, r]));
  const rows = new Map<string, FixItem[]>();
  for (const f of fixFirst) {
    const { team, edge } = itemMarks(f.item);
    const key = JSON.stringify([team, edge, [...f.vulns].sort()]);
    rows.set(key, [...(rows.get(key) ?? []), f]);
  }
  return [...rows.values()].map((members, i) => {
    const lead = members.find((m) => !itemMarks(m.item).close) ?? members[0]!;
    const { name, close, team } = itemMarks(lead.item);
    return {
      ...lead,
      component: name,
      close,
      team,
      also: members.filter((m) => m !== lead).map((m) => m.item),
      rank: i + 1,
      results: lead.vulns.flatMap((id) => byId.get(id) ?? []),
    };
  });
}

/**
 * Splits a group's results into those not shown yet and those an earlier group
 * already showed, and records the new ones as shown. Windows SKUs, for one,
 * share most of their CVEs, so the later rows point back rather than repeat them.
 */
export function splitShown(results: Result[], shown: Set<string>): { fresh: Result[]; repeated: Result[] } {
  const fresh = results.filter((r) => !shown.has(r.id));
  const repeated = results.filter((r) => shown.has(r.id));
  for (const r of fresh) shown.add(r.id);
  return { fresh, repeated };
}
