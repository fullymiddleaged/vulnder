import type { Change, FixItem, Priority, Result } from './api';

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

/** The playful headline above the results. Tier and evidence wording stays plain. */
export function matchHeadline(count: number, days: number): { title: string; subtitle: string } {
  if (count === 0) {
    return { title: 'No matches.', subtitle: `Nobody's been into your stack in the last ${days} days. Keep it that way.` };
  }
  return {
    title: "It's a match. Unfortunately.",
    subtitle: `${count} ${count === 1 ? 'CVE is' : 'CVEs are'} into your stack from the last ${days} days. Red flags, ranked:`,
  };
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

/** First sentence-ish of a summary, for compact cards. */
export function shortSummary(text: string | null, max = 220): string | null {
  if (!text) return null;
  const clean = text.replace(/\s+/g, ' ').replace(/^#+\s*/, '').trim();
  return clean.length <= max ? clean : `${clean.slice(0, max).replace(/\s+\S*$/, '')}…`;
}

/**
 * Traffic lights for each priority. Colour carries priority and nothing else;
 * green is kept for good news such as a released fix.
 */
export const RISK: Record<Priority, { label: string; light: 'red' | 'amber' | 'yellow' | 'grey'; note: string }> = {
  act: { label: 'Act now', light: 'red', note: 'Being exploited: on CISA KEV, or CISA reports active exploitation.' },
  attend: { label: 'Attend', light: 'amber', note: 'Likely to be exploited, or critical and within reach: EPSS of 10% or more, CVSS 9.0 or more with no login or user action needed, or a working exploit that is easy to use or gives full control.' },
  watch: { label: 'Watch', light: 'yellow', note: 'High severity or a public exploit: CVSS 8.0 or more, 7.0 or more within reach on an internet-facing item, or a proof-of-concept exploit.' },
  track: { label: 'Track', light: 'grey', note: 'Affects your stack, but nothing above applies: lower severity, and nothing suggests exploitation.' },
};

/** Results by priority, keeping feed order within each. */
export function byPriority(results: Result[]): Record<Priority, Result[]> {
  const out: Record<Priority, Result[]> = { act: [], attend: [], watch: [], track: [] };
  for (const r of results) out[r.priority].push(r);
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

/** A stack item as the feed writes it, split into its name and its marks (`!` internet-facing, `?` close match). */
export function itemMarks(item: string): { name: string; exposed: boolean; close: boolean } {
  const m = /^(!?)(\??)(.*)$/s.exec(item)!;
  return { name: m[3]!, exposed: m[1] === '!', close: m[2] === '?' };
}

/** The item written back with the given marks, in canonical order. */
export function withItemMarks(name: string, marks: { exposed: boolean; close: boolean }): string {
  return `${marks.exposed ? '!' : ''}${marks.close ? '?' : ''}${name}`;
}

export interface ComponentGroup extends FixItem {
  /** The stack item, without its marks. */
  component: string;
  close: boolean;
  exposed: boolean;
  /** 1-based position in the fix-first order. */
  rank: number;
  results: Result[];
}

/** The fix-first list with each item's results attached, in the server's order. */
export function componentGroups(fixFirst: FixItem[], results: Result[]): ComponentGroup[] {
  const byId = new Map(results.map((r) => [r.id, r]));
  return fixFirst.map((f, i) => {
    const { name, close, exposed } = itemMarks(f.item);
    return {
      ...f,
      component: name,
      close,
      exposed,
      rank: i + 1,
      results: f.vulns.flatMap((id) => byId.get(id) ?? []),
    };
  });
}
