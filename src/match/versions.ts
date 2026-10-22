/**
 * What a CVE record says a product version is NOT affected by, kept small
 * enough to read on every match. Records list ranges (CVE JSON 5 `versions`);
 * ingest keeps two bounds from the explicitly unaffected ones:
 *
 * - `below`: unaffected before this version ("0" lessThan X), where the bug
 *   was introduced;
 * - `from`: unaffected from this version on (X lessThanOrEqual "*"), where it
 *   was fixed for good. The Linux kernel CNA writes both on every record.
 *
 * A match is dropped only when one of these says so for the version named:
 * a record that says nothing, or says it in words we can't compare (git
 * hashes, rpm versions), never hides one. Per-branch fixes ("6.6.145" up to
 * "6.6.*") aren't kept: a version named as a series ("6.8") is its first
 * release, which they don't cover.
 */

export interface UnaffectedBounds {
  below: string | null;
  from: string | null;
}

/** The bounds a record's `versions` give, as written (compared only at match time). */
export function unaffectedBounds(ranges: unknown[]): UnaffectedBounds {
  let below: string | null = null;
  let from: string | null = null;
  for (const r of ranges) {
    if (!r || typeof r !== 'object') continue;
    const v = r as Record<string, unknown>;
    if (v.status !== 'unaffected' || v.versionType === 'git' || typeof v.version !== 'string') continue;
    if (below === null && v.version === '0' && typeof v.lessThan === 'string') below = v.lessThan;
    if (from === null && v.lessThanOrEqual === '*') from = v.version;
  }
  return { below, from };
}

const DOTTED = /^\d{1,9}(\.\d{1,9}){0,5}$/;

/** -1, 0 or 1 for dotted numeric versions, missing parts as 0 ("6.8" = "6.8.0"); null when either isn't one. */
export function compareDotted(a: string, b: string): number | null {
  if (!DOTTED.test(a) || !DOTTED.test(b)) return null;
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

/** A record listing more fixes than this is left without any, rather than cut short. */
export const MAX_FIXES = 8;

/**
 * The fixed versions a record's `versions` give: each affected range's
 * `lessThan`, the first unaffected version. One bound is kept as written. Several
 * (one per release branch: PHP's 8.2.* < 8.2.35, 8.3.* < 8.3.36) are kept only
 * when every one is the next release on its own range's branch, so a kernel
 * range that ends where the next mainline series starts (5.13.19 < 5.14) leaves
 * the record with none rather than a fix that isn't one. Stored joined with
 * ", " (migration 0013 derives the same in SQL).
 */
export function fixedVersionOf(ranges: unknown[]): string | null {
  const bounds = new Set<string>();
  let branched = true;
  for (const r of ranges) {
    if (!r || typeof r !== 'object') continue;
    const v = r as Record<string, unknown>;
    if (v.status !== 'affected' || v.versionType === 'git' || typeof v.lessThan !== 'string' || v.lessThan === '' || v.lessThan.includes('*')) continue;
    bounds.add(v.lessThan);
    if (typeof v.version !== 'string' || !onBranch(v.version, v.lessThan) || v.lessThan.includes(',')) branched = false;
  }
  if (bounds.size === 1) return [...bounds][0]!;
  return bounds.size > 1 && bounds.size <= MAX_FIXES && branched ? [...bounds].join(', ') : null;
}

/**
 * "8.2.*", "8.2" or "5.10.67" up to "8.2.35" or "5.10.271": the bound is the
 * range's branch plus one more number.
 */
function onBranch(version: string, lessThan: string): boolean {
  const plusOne = (prefix: string) => prefix.length > 1 && prefix.endsWith('.') && lessThan.startsWith(prefix) && /^[0-9]+$/.test(lessThan.slice(prefix.length));
  return plusOne(version.endsWith('.*') ? version.slice(0, -1) : version.replace(/[0-9]+$/, '')) || plusOne(`${version}.`);
}

/** A stored `fixed_version`, as its fixes. */
export function splitFixes(fixed: string | null): string[] {
  return fixed ? fixed.split(', ').filter((f) => f !== '') : [];
}

/**
 * The fixes that apply to a version: the one on its branch when one is (8.3.10
 * or 8.3 → 8.3.36), otherwise all of them, so a version on no listed branch
 * still sees where to go.
 */
export function fixesFor(version: string | null | undefined, fixes: string[]): string[] {
  if (!version || fixes.length < 2) return fixes;
  const own = fixes.filter((f) => {
    const branch = f.replace(/\.[0-9]+$/, '');
    return branch !== f && (version === branch || version.startsWith(`${branch}.`));
  });
  return own.length > 0 ? own : fixes;
}

/** True only when the record's bounds say this version is unaffected. */
export function explicitlyUnaffected(bounds: UnaffectedBounds, version: string): boolean {
  if (bounds.below !== null && compareDotted(version, bounds.below) === -1) return true;
  if (bounds.from !== null) {
    const c = compareDotted(version, bounds.from);
    if (c !== null && c >= 0) return true;
  }
  return false;
}
