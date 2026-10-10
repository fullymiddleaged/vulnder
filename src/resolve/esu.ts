import { normalizeKey } from '../lib/normalize';
import { eolTarget } from '../stack/eol';
import { formatItem, parseStack, withMarks } from '../stack/format';
import type { Chip } from './catalog';

/**
 * Marks `;esu` on what the user says they have paid extended support for
 * ("Windows Server 2012 R2 with ESU", "RHEL 7 on ELS"). Fixed logic, no model:
 * a line or sentence that mentions extended support marks the products named
 * in it that src/stack/eol.ts has support dates for. A product is named in it
 * when every word of its input with a digit (2012, R2) and one other word of
 * three letters or more (Windows) are there. The mark only counts once a
 * release is past its normal end and has extended support to cover it
 * (src/match/support.ts), so a stray one changes nothing else.
 */

const EXTENDED_SUPPORT = /\b(esus?|extended security updates?|extended (life ?cycle )?support|els|ltss|ubuntu pro|esm)\b/i;

/** Lines, and sentences within them. A dot inside a version ("18.04") doesn't end one. */
const SEGMENTS = /\n+|[.!?;](?=\s|$)/;

export function markEsu(chips: Chip[], text: string): Chip[] {
  const segments = text
    .split(SEGMENTS)
    .filter((s) => EXTENDED_SUPPORT.test(s))
    .map((s) => new Set((normalizeKey(s) ?? '').split('_')));
  if (segments.length === 0) return chips;
  return chips.map((chip) => {
    const words = (normalizeKey(chip.input) ?? '').split('_').filter(Boolean);
    const numbered = words.filter((w) => /\d/.test(w));
    const named = words.filter((w) => !/\d/.test(w) && w.length >= 3);
    const mentioned = segments.some((seg) => numbered.length > 0 && numbered.every((w) => seg.has(w)) && named.some((w) => seg.has(w)));
    if (!mentioned) return chip;
    const items = chip.items.map((i) => {
      const parsed = parseStack(i.item)[0]!;
      if (parsed.kind !== 'product' || parsed.esu || !eolTarget(withMarks(parsed, { team: parsed.team, edge: parsed.edge }))) return i;
      return { ...i, item: formatItem(withMarks(parsed, { close: parsed.close, team: parsed.team, edge: parsed.edge, esu: true })) };
    });
    return items.some((item, n) => item !== chip.items[n]) ? { ...chip, items } : chip;
  });
}
