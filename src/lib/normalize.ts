/**
 * Identifier normalisation shared by ingest and (later) stack resolution.
 * Ecosystem names follow OSV (https://ossf.github.io/osv-schema/#affectedpackage-field).
 */

export type Ecosystem =
  | 'npm'
  | 'PyPI'
  | 'crates.io'
  | 'Go'
  | 'Maven'
  | 'NuGet'
  | 'Packagist'
  | 'RubyGems'
  | 'Hex'
  | 'Pub'
  | 'SwiftURL'
  | 'GitHub Actions';

/** GitHub advisory ecosystem names to OSV names. 'other' has no OSV equivalent. */
const GITHUB_ECOSYSTEMS: Record<string, Ecosystem> = {
  npm: 'npm',
  pip: 'PyPI',
  rust: 'crates.io',
  go: 'Go',
  maven: 'Maven',
  nuget: 'NuGet',
  composer: 'Packagist',
  rubygems: 'RubyGems',
  erlang: 'Hex',
  pub: 'Pub',
  swift: 'SwiftURL',
  actions: 'GitHub Actions',
};

export function ecosystemFromGithub(name: string): Ecosystem | null {
  return ownValue(GITHUB_ECOSYSTEMS, name.toLowerCase()) ?? null;
}

/** Registry hosts seen in CVE `affected[].collectionURL`, to OSV names. */
const COLLECTION_HOSTS: [RegExp, Ecosystem][] = [
  [/(^|\.)npmjs\.(com|org)$/, 'npm'],
  [/(^|\.)(pypi\.org|pypi\.python\.org)$/, 'PyPI'],
  [/(^|\.)crates\.io$/, 'crates.io'],
  [/(^|\.)(pkg\.go\.dev|proxy\.golang\.org|go\.dev)$/, 'Go'],
  [/(^|\.)(repo1?\.maven\.org|repo\.maven\.apache\.org|search\.maven\.org|central\.sonatype\.com)$/, 'Maven'],
  [/(^|\.)nuget\.org$/, 'NuGet'],
  [/(^|\.)packagist\.org$/, 'Packagist'],
  [/(^|\.)rubygems\.org$/, 'RubyGems'],
  [/(^|\.)hex\.pm$/, 'Hex'],
  [/(^|\.)pub\.dev$/, 'Pub'],
];

export function ecosystemFromCollectionUrl(url: string): Ecosystem | null {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
  for (const [re, eco] of COLLECTION_HOSTS) if (re.test(host)) return eco;
  return null;
}

/**
 * Normalises a package name the way its registry compares names, so the same
 * package from different sources lands on one key.
 */
export function normalizePackageName(ecosystem: Ecosystem, name: string): string {
  const n = name.trim();
  switch (ecosystem) {
    case 'PyPI':
      // PEP 503
      return n.toLowerCase().replace(/[-_.]+/g, '-');
    case 'npm':
    case 'crates.io':
    case 'NuGet':
    case 'Packagist':
    case 'Hex':
    case 'Pub':
      return n.toLowerCase();
    default:
      // Go module paths, Maven coordinates, RubyGems and the rest are case-sensitive.
      return n;
  }
}

/**
 * Normalises a vendor or product name into a CPE-style key:
 * lowercase ASCII, runs of anything else collapsed to '_'.
 * Returns null for empty and placeholder values ('n/a', '*', '-').
 */
export function normalizeKey(value: string | null | undefined): string | null {
  if (!value) return null;
  const key = value
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  if (key === '' || key === 'n_a' || key === 'na' || key === 'unknown') return null;
  return key;
}

/** Vendor and product from a CPE 2.3 string, or null if it has neither. */
export function parseCpe(cpe: string): { vendor: string; product: string } | null {
  // cpe:2.3:part:vendor:product:version:...  Colons inside values are escaped as '\:'.
  const parts = cpe.split(/(?<!\\):/);
  if (parts[0] !== 'cpe' || parts[1] !== '2.3') return null;
  const unescape = (s: string | undefined) => (s ?? '').replace(/\\(.)/g, '$1');
  const vendor = normalizeKey(unescape(parts[3]));
  const product = normalizeKey(unescape(parts[4]));
  if (!vendor || !product) return null;
  return { vendor, product };
}

/** A CVE ID, with 4 or more digits in the sequence part. */
export const CVE_ID = /^CVE-\d{4}-\d{4,}$/;
export const GHSA_ID = /^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/;

/**
 * A table lookup that only sees the table's own keys. Plain objects inherit
 * "constructor", "toString" and friends, so `table[userInput]` can return a
 * function instead of undefined.
 */
export function ownValue<T>(table: Readonly<Record<string, T>>, key: string): T | undefined {
  return Object.hasOwn(table, key) ? table[key] : undefined;
}
