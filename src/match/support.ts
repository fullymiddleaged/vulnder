import { addDays } from '../lib/time';
import { candidateReleases, eolTarget } from '../stack/eol';
import type { StackItem } from '../stack/format';
import { isEdge } from '../stack/teams';

/**
 * Whether the vendor still supports a stack item, from endoflife.date's dates
 * (src/ingest/eol.ts) or, for products it has none for, the CVE record's
 * "unsupported-when-assigned" tag. Software past its end of support gets no
 * more fixes, so every new CVE in it stays open: the finding is about the
 * component, not any one CVE, and never changes a CVE's band.
 *
 * Only what the user named counts. An item is out of support when every
 * release it could mean is, so "Windows 7" is and a bare "Windows" never is;
 * a key whose most recent CVE carries the tag is (a later untagged one means
 * the vendor still supports something under it). With `;esu`, a release with
 * paid extended support is covered until that ends.
 */

/** A release line as stored (migrations/0008_eol.sql). */
export interface EolRelease {
  slug: string;
  release: string;
  label: string | null;
  eol_from: string | null;
  is_eol: number;
  eoes_from: string | null;
}

/** A product key's latest CVE and whether its CNA tagged it unsupported. */
export interface CveSupport {
  key: string;
  last_cve: string;
  last_published: string;
  tagged: number;
}

export type SupportState = 'eol' | 'ending' | 'covered';

export interface Support {
  /** eol: out of support; ending: support ends within ENDING_DAYS; covered: past its end, but paid extended support covers it. */
  state: SupportState;
  /** What it is, as the notice names it ("Windows Server 2012 R2"). */
  name: string;
  /** When support ended or ends (YYYY-MM-DD), the latest across the releases it could mean; null when no date is known. */
  date: string | null;
  /** When paid extended support for it ends, when it has some the user hasn't said they have; null otherwise. */
  esuUntil: string | null;
  /** True when the dates counted the user's `;esu`. */
  esu: boolean;
  /** Faces the internet: CISA BOD 26-02 has agencies replace end-of-support edge devices. */
  edge: boolean;
  source: 'endoflife' | 'cve';
  /** For source 'cve': the CVE whose record said so. */
  cve: string | null;
}

/** Support ending this soon is worth planning for now. */
export const ENDING_DAYS = 90;

export function supportFor(item: StackItem, releases: EolRelease[], cve: CveSupport | null, now: Date): Support | null {
  if (item.kind !== 'product') return null;
  const today = now.toISOString().slice(0, 10);
  const soon = addDays(now, ENDING_DAYS).toISOString().slice(0, 10);
  const edge = isEdge(item);
  const target = eolTarget(item);
  const candidates = target ? candidateReleases(target, releases.filter((r) => r.slug === target.slug)) : [];

  // endoflife.date has this product: its dates decide, whatever any CVE says.
  if (target && candidates.length > 0) {
    const esu = !!item.esu || target.esu;
    const ends = candidates.map((r) => {
      const covered = esu && r.eoes_from !== null;
      const end = covered ? r.eoes_from : r.eol_from;
      // No date: endoflife.date's own flag, for old releases it gives none for.
      const ended = end ? end <= today : r.is_eol === 1;
      return { r, end, ended, covered };
    });
    const latest = (xs: (string | null)[]) => xs.filter((d): d is string => d !== null).sort().at(-1) ?? null;
    const name = target.release ? `${target.name} ${target.release}` : target.name;
    const base = { name, edge, source: 'endoflife' as const, cve: null };
    if (ends.every((e) => e.ended)) {
      // Paid extended support it has and the user hasn't claimed: worth saying, it buys time.
      const esuUntil = !esu && candidates.every((r) => r.eoes_from !== null && r.eoes_from > today) ? latest(candidates.map((r) => r.eoes_from)) : null;
      return { ...base, state: 'eol', date: latest(ends.map((e) => e.end)), esuUntil, esu: ends.some((e) => e.covered) };
    }
    if (ends.every((e) => e.ended || (e.end !== null && e.end <= soon))) {
      return { ...base, state: 'ending', date: latest(ends.map((e) => e.end)), esuUntil: null, esu: ends.some((e) => e.covered) };
    }
    // Past its own end, kept going by paid extended support the user has.
    if (ends.every((e) => e.covered && e.r.eol_from !== null && e.r.eol_from <= today)) {
      return { ...base, state: 'covered', date: latest(ends.map((e) => e.end)), esuUntil: null, esu: true };
    }
    return null;
  }

  if (cve?.tagged === 1 && !item.close) {
    return { state: 'eol', name: `${item.vendor} ${item.product}`.replace(/_/g, ' '), date: null, esuUntil: null, esu: false, edge, source: 'cve', cve: cve.last_cve };
  }
  return null;
}

/** The notice's sentences, for the Atom feed and exports (the page builds its own from the same fields). */
export function supportText(s: Support): string[] {
  const out: string[] = [];
  const since = s.date ? ` since ${s.date}` : '';
  if (s.state === 'eol') {
    out.push(
      s.esu
        ? `${s.name}: paid extended support ended${s.date ? ` on ${s.date}` : ''}, so it gets no more security updates. Upgrade to a supported release urgently.`
        : `${s.name} is out of support${since}: it gets no more security updates. Upgrade to a supported release urgently.`,
    );
    if (s.esuUntil) out.push(`Paid extended security updates run until ${s.esuUntil}; if you have them, add ;esu to the item.`);
    if (s.source === 'cve' && s.cve) out.push(`Its vendor said it is no longer supported in ${s.cve}.`);
  } else if (s.state === 'ending') {
    out.push(
      s.esu
        ? `${s.name}: paid extended support ends ${s.date ?? 'soon'}. Plan the upgrade to a supported release now.`
        : `${s.name}: support ends ${s.date ?? 'soon'}. Plan the upgrade to a supported release now.`,
    );
  } else {
    out.push(`${s.name}: covered by paid extended support until ${s.date ?? 'its end date'}. Plan the upgrade before then.`);
  }
  if (s.edge && s.state !== 'covered') out.push('CISA BOD 26-02 has US federal agencies replace end-of-support edge devices.');
  return out;
}
