import { normalizeKey } from '../lib/normalize';
import type { StackItem } from './format';

/**
 * Which endoflife.date product (and which of its releases) a stack item names.
 * The support dates themselves are fetched daily (src/ingest/eol.ts); this
 * table only maps catalog keys, which follow the CNAs' names, to
 * endoflife.date's products and release names. Release names are compared
 * through normalizeKey, so "2012-r2" is "2012_r2" and "18.04" is "18_04".
 *
 * A key either holds the release (`windows_server_2012_r2`) or leaves it to the
 * item's version (`canonical/ubuntu@18.04`). With neither, every release of the
 * product is a candidate, and src/match/support.ts only calls an item out of
 * support when all of them are, so a bare "Windows" or "macOS" never is.
 *
 * Check new keys against the catalog: `npm run check:names` lists entries that
 * match nothing. endoflife.date has no lifecycle data for some edge lines
 * (Cisco ASA, Junos, NetScaler, Ivanti Connect Secure); the CVE record's
 * "unsupported-when-assigned" tag covers hardware it lacks.
 */
export interface EolProduct {
  /** The endoflife.date product. */
  slug: string;
  /** What to call it in a notice ("Windows Server"). */
  name: string;
  /** Matched against `vendor/product`; the first entry that matches wins. */
  keys: RegExp;
  /** The release prefixes the key's capture groups name, and how to show them; none when only the version can say. */
  fromKey?: (m: RegExpExecArray) => { prefixes: string[]; display: string } | null;
  /** The release prefixes a version names; versionPrefix when left out. */
  fromVersion?: (version: string) => string[];
  /** Releases only some installs run (LTSC, IoT, add-on packs): left out unless the item names one. */
  niche?: RegExp;
  /** Keys that are themselves a paid extended-support line (SLES LTSS): the item has it. */
  esuKey?: RegExp;
}

/** SQL Server's releases go by version; people and catalog keys say the year. */
const SQL_SERVER_YEARS: Record<string, string[]> = {
  '2000': ['8_0'],
  '2005': ['9_0', '9_00'],
  '2008': ['10_0', '10_00'],
  '2008_r2': ['10_50'],
  '2012': ['11_0'],
  '2014': ['12_0'],
  '2016': ['13_0'],
  '2017': ['14_0'],
  '2019': ['15_0'],
  '2022': ['16_0'],
  '2025': ['17_0'],
};

function sqlServerRelease(year: string, sp: string | undefined): string[] {
  const base = Object.hasOwn(SQL_SERVER_YEARS, year) ? SQL_SERVER_YEARS[year]! : [];
  return sp ? base.map((b) => `${b}_sp${sp}`) : base;
}

const key = (prefix: string | undefined, display?: string) => (prefix ? { prefixes: [prefix], display: display ?? showRelease(prefix) } : null);

export const EOL_PRODUCTS: EolProduct[] = [
  // Windows: the release lives in the product key, or in the version of the line's plain key.
  { slug: 'windows', name: 'Windows', keys: /^microsoft\/windows$/, niche: /(^|_)(lts|iot)(_|$)/ },
  { slug: 'windows', name: 'Windows', keys: /^microsoft\/windows_(\d+)_version_([0-9a-z]+)$/, fromKey: (m) => key(`${m[1]}_${m[2]}`), niche: /(^|_)(lts|iot)(_|$)/ },
  { slug: 'windows', name: 'Windows', keys: /^microsoft\/windows_(\d+)$/, fromKey: (m) => key(m[1]), niche: /(^|_)(lts|iot)(_|$)/ },
  // Windows Server 2022's 23H2 edition is its own (Annual Channel) release.
  { slug: 'windows-server', name: 'Windows Server', keys: /^microsoft\/windows_server_\d{4}_(\d{2}h\d)(_|$)/, fromKey: (m) => key(m[1], m[1]!.toUpperCase()) },
  {
    slug: 'windows-server',
    name: 'Windows Server',
    keys: /^microsoft\/windows_server_(\d{4})(_r2)?(?:_service_pack_(\d+))?(_|$)/,
    fromKey: (m) => key(`${m[1]}${m[2] ?? ''}${m[3] ? `_sp${m[3]}` : ''}`),
  },
  { slug: 'windows-server', name: 'Windows Server', keys: /^microsoft\/windows_server$/ },
  {
    slug: 'msexchange',
    name: 'Exchange Server',
    keys: /^microsoft\/(?:microsoft_)?exchange_server(?:_(\d{4}))?(_|$)/,
    fromKey: (m) => key(m[1]),
  },
  {
    slug: 'mssqlserver',
    name: 'SQL Server',
    keys: /^microsoft\/(?:microsoft_)?sql_server(?:_(\d{4})(_r2)?(?:_.*?service_pack_(\d+))?(?:_.*)?)?$/,
    fromKey: (m) => (m[1] ? { prefixes: sqlServerRelease(`${m[1]}${m[2] ?? ''}`, m[3]), display: `${m[1]}${m[2] ? ' R2' : ''}${m[3] ? ` SP${m[3]}` : ''}` } : null),
    fromVersion: (v) => {
      const p = versionPrefix(v);
      return p ? (Object.hasOwn(SQL_SERVER_YEARS, p) ? SQL_SERVER_YEARS[p]! : [p]) : [];
    },
    niche: /(^|_)acp(_|$)/,
  },
  { slug: 'office', name: 'Office', keys: /^microsoft\/(?:microsoft_)?office(?:_(\d{4}))?$/, fromKey: (m) => key(m[1]) },
  { slug: 'sharepoint', name: 'SharePoint Server', keys: /^microsoft\/(?:microsoft_)?sharepoint_server(?:_(\d{4}))?$/, fromKey: (m) => key(m[1]) },

  // Apple
  { slug: 'macos', name: 'macOS', keys: /^apple\/mac_?os(_x)?$/ },
  { slug: 'ios', name: 'iOS', keys: /^apple\/(iphone_os|ios|ios_and_ipados)$/ },
  { slug: 'ipados', name: 'iPadOS', keys: /^apple\/ipados$/ },
  { slug: 'android', name: 'Android', keys: /^google\/android$/ },

  // Linux and Unix
  { slug: 'ubuntu', name: 'Ubuntu', keys: /^canonical\/ubuntu_(\d+)_(\d+)(_lts)?$/, fromKey: (m) => key(`${m[1]}_${m[2]}`) },
  { slug: 'ubuntu', name: 'Ubuntu', keys: /^canonical\/ubuntu(_linux)?$/ },
  { slug: 'debian', name: 'Debian', keys: /^debian\/debian_linux$/ },
  { slug: 'rhel', name: 'Red Hat Enterprise Linux', keys: /^red_hat\/red_hat_enterprise_linux_(\d+)$/, fromKey: (m) => key(m[1]) },
  { slug: 'rhel', name: 'Red Hat Enterprise Linux', keys: /^redhat\/enterprise_linux$/ },
  { slug: 'centos', name: 'CentOS', keys: /^centos\/centos$/ },
  { slug: 'oracle-linux', name: 'Oracle Linux', keys: /^oracle\/linux$/ },
  {
    slug: 'sles',
    name: 'SUSE Linux Enterprise Server',
    keys: /^suse\/suse_linux_enterprise_server_(\d+)_(?:sp)?(\d+)(_ltss)?$/,
    fromKey: (m) => key(`${m[1]}_${m[2]}`),
    esuKey: /_ltss$/,
  },
  { slug: 'sles', name: 'SUSE Linux Enterprise Server', keys: /^suse\/(suse_)?linux_enterprise_server$/ },

  // Virtualisation
  { slug: 'esxi', name: 'ESXi', keys: /^(vmware|broadcom)\/(vmware_)?esxi$/ },
  { slug: 'vcenter', name: 'vCenter Server', keys: /^(vmware|broadcom)\/(vmware_)?vcenter(_server)?$/ },

  // Network and security firmware: edge devices, so BOD 26-02 applies.
  { slug: 'fortios', name: 'FortiOS', keys: /^fortinet\/fortios$/ },
  { slug: 'panos', name: 'PAN-OS', keys: /^palo_?alto_?networks\/pan_os$/ },
  { slug: 'cisco-ios-xe', name: 'Cisco IOS XE', keys: /^cisco\/(cisco_)?ios_xe(_software)?$/ },
  { slug: 'big-ip', name: 'BIG-IP', keys: /^f5\/big_ip(_(?!next)[a-z_]+)?$/ },
];

/** Every endoflife.date product the table maps, for the daily fetch. */
export const EOL_SLUGS = [...new Set(EOL_PRODUCTS.map((p) => p.slug))];

export interface EolTarget {
  slug: string;
  name: string;
  /** Release-name prefixes the item names; empty means every release. */
  prefixes: string[];
  /** The release as the item names it ("2012 R2", "18.04"), or null for every release. */
  release: string | null;
  niche?: RegExp;
  /** The key is itself a paid extended-support line. */
  esu: boolean;
}

/**
 * The endoflife.date product and releases a product item names, or null when
 * the table has no entry for it, or it names nothing particular. An exact item
 * names what its key does, narrowed by its version ("rhel_9" at 9.4). A close
 * match is one of several products a name expanded to ("Windows 10" is every
 * windows_10_version_* key), so only the version the user wrote says which
 * release they mean; without one it names nothing particular.
 */
export function eolTarget(item: StackItem): EolTarget | null {
  if (item.kind !== 'product') return null;
  const k = `${item.vendor}/${item.product}`;
  for (const p of EOL_PRODUCTS) {
    const m = p.keys.exec(k);
    if (!m) continue;
    const fromKey = item.close ? null : (p.fromKey?.(m) ?? null);
    const fromVersion = item.version ? (p.fromVersion ?? ((v: string) => [versionPrefix(v)].filter((x): x is string => !!x)))(item.version) : [];
    if (item.close && fromVersion.length === 0) return null;
    // The version wins when it narrows what the key says, or when the key says nothing.
    const narrows = fromKey && fromVersion.length > 0 && fromVersion.every((v) => fromKey.prefixes.some((k2) => v.startsWith(`${k2}_`)));
    const useVersion = fromVersion.length > 0 && (!fromKey || narrows);
    const prefixes = useVersion ? fromVersion : (fromKey?.prefixes ?? []);
    // A version shows as written ("18.04"), unless it came through normalizeKey ("10_pro").
    const release = useVersion ? (item.version!.includes('_') ? showRelease(fromVersion[0]!) : item.version) : (fromKey?.display ?? null);
    return { slug: p.slug, name: p.name, prefixes, release, niche: p.niche, esu: !!p.esuKey?.test(k) };
  }
  return null;
}

/**
 * The leading parts of a version that name a release: "18.04.6" is "18_04_6",
 * "10 Pro" is "10", "2012 R2" is "2012_r2". Null when no part has a digit.
 */
export function versionPrefix(version: string): string | null {
  const parts = (normalizeKey(version) ?? '').split('_');
  const n = parts.findIndex((s) => !/\d/.test(s));
  const kept = (n < 0 ? parts : parts.slice(0, n)).filter(Boolean);
  return kept.length > 0 ? kept.join('_') : null;
}

/**
 * Whether an endoflife.date release (through normalizeKey) is one a prefix names:
 * the same release, one of its editions ("10_1607" names "10_1607_e"), or the line a
 * more exact version is in ("18_04_6" is in "18_04").
 */
export function releaseMatches(release: string, prefix: string): boolean {
  return release === prefix || release.startsWith(`${prefix}_`) || prefix.startsWith(`${release}_`);
}

/** The releases among `releases` an item's target names, leaving out niche ones it doesn't name. */
export function candidateReleases<T extends { release: string }>(target: EolTarget, releases: T[]): T[] {
  const named = target.prefixes.length === 0 ? releases : releases.filter((r) => target.prefixes.some((p) => releaseMatches(r.release, p)));
  const asksNiche = target.niche && target.prefixes.some((p) => target.niche!.test(p));
  return target.niche && !asksNiche ? named.filter((r) => !target.niche!.test(r.release)) : named;
}

/** "2012_r2" as "2012 R2", "18_04" as "18.04", "10_22h2" as "10 22H2". */
export function showRelease(prefix: string): string {
  const parts = prefix.split('_');
  let out = '';
  parts.forEach((p, i) => {
    const shown = /^\d+$/.test(p) ? p : p.toUpperCase();
    if (i > 0) out += /^\d+$/.test(p) && /^\d+$/.test(parts[i - 1]!) ? '.' : ' ';
    out += shown;
  });
  return out;
}
