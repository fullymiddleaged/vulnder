import { z } from 'zod';
import { isEdgeProduct, type Chip } from './catalog';
import { formatItem, parseStack, withMarks } from '../stack/format';

/**
 * What kind of stack a description is about, on two axes: scale (enterprise,
 * small business or home) and hosting (cloud or on-premises). Jev reads both
 * from the person's own words (jev.ts); manifests get no profile.
 *
 * The profile decides only whether close matches are worth reordering. When
 * one axis is clear enough, Jev judges how well each close match fits the
 * description, and fixed logic sorts by that: a home lab asking about "Cisco
 * switches" sees small-business gear first. Nothing is hidden or added, and
 * exact matches are left alone.
 */

export const SCALES = ['enterprise', 'smb', 'home'] as const;
export type Scale = (typeof SCALES)[number];
export const HOSTINGS = ['cloud', 'on_prem'] as const;
export type Hosting = (typeof HOSTINGS)[number];

export interface AxisGuess<T> {
  value: T | null;
  /** 0 to 1: Jev's confidence in the value. */
  confidence: number;
}

export interface StackProfile {
  scale: AxisGuess<Scale>;
  hosting: AxisGuess<Hosting>;
}

export const NO_PROFILE: StackProfile = { scale: { value: null, confidence: 0 }, hosting: { value: null, confidence: 0 } };

/** Below this, an axis doesn't count as known. */
export const MIN_RANK_CONFIDENCE = 0.5;

/** A close match Jev wasn't asked about fits as well as a coin toss. */
export const NEUTRAL_FIT = 0.5;

const confidence = z.number().min(0).max(1);
const StoredProfile = z.object({
  scale: z.object({ value: z.enum(SCALES).nullable(), confidence }),
  hosting: z.object({ value: z.enum(HOSTINGS).nullable(), confidence }),
});

/** A profile read back from the parse cache, or no profile if it doesn't validate. */
export function parseProfile(raw: unknown): StackProfile {
  const parsed = StoredProfile.safeParse(raw);
  return parsed.success ? parsed.data : NO_PROFILE;
}

/** True when at least one axis is known well enough to judge fit against. */
export function canRank(profile: StackProfile): boolean {
  return [profile.scale, profile.hosting].some((a) => a.value !== null && a.confidence >= MIN_RANK_CONFIDENCE);
}

/** Chips whose items are all close matches, with more than one to order. */
export function rankableChips(chips: Chip[]): Chip[] {
  return chips.filter((chip) => chip.items.length > 1 && chip.items.every((i) => i.close));
}

/**
 * Each rankable chip's close matches, best fit first. Items without a fit
 * count as neutral, and the sort is stable, so catalog order breaks ties.
 */
export function orderByFit(chips: Chip[], fit: ReadonlyMap<string, number>): Chip[] {
  const rankable = new Set(rankableChips(chips));
  return chips.map((chip) => {
    if (!rankable.has(chip)) return chip;
    const items = chip.items
      .map((item) => ({ item, fit: fit.get(item.item) ?? NEUTRAL_FIT }))
      .sort((a, b) => b.fit - a.fit)
      .map(({ item }) => item);
    return { ...chip, items };
  });
}

/**
 * Jev's answer at or above which a component is marked internet-facing. Its
 * answers are calibrated, so this means fairly sure; a mark raises rankings
 * and goes into the shareable link, so a guess shouldn't set one.
 */
export const EXPOSED_AT = 0.7;

/**
 * Marks items internet-facing: every item of a chip whose input Jev judged
 * internet-facing, and any item that faces the internet by what it is (a VPN
 * gateway, an edge firewall), whatever Jev said or if it didn't answer.
 * Nothing is added, removed or reordered; the person can untick a mark on the
 * Edit page.
 */
export function markExposed(chips: Chip[], exposure: ReadonlyMap<string, number>): Chip[] {
  return chips.map((chip) => {
    const judged = (exposure.get(chip.input) ?? 0) >= EXPOSED_AT;
    const items = chip.items.map((i) => {
      const parsed = parseStack(i.item)[0]!;
      if (!judged && !isEdgeProduct(parsed)) return i;
      return { ...i, item: formatItem(withMarks(parsed, { close: parsed.close, exposed: true })), exposed: true as const };
    });
    return items.some((item, n) => item !== chip.items[n]) ? { ...chip, items } : chip;
  });
}
