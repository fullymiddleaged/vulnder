import { normalizeKey } from '../lib/normalize';
import type { Candidate } from './types';

/**
 * A device inventory (Intune's discovered apps, as Microsoft Graph's
 * `detectedApps` returns them) turned into product candidates. One fleet lists
 * the same product once per version, under display names that carry the
 * version, the architecture and the locale ("Mozilla Firefox (x64 en-US)"),
 * and a stack holds 200 items. So names are cleaned, entries collapse to one
 * per product, and the products on most devices fill the places; the rest are
 * named as not checked, never silently dropped.
 *
 * A product seen at one version keeps it, and is matched exactly. Seen at
 * several, it goes unversioned, so every version's CVEs show: picking one
 * version could hide a CVE that affects another.
 *
 * Pure, with no server imports, so the page can use it for an exported file.
 */

export interface InventoryEntry {
  displayName: string;
  version?: string | null;
  publisher?: string | null;
  /** Devices with this name and version; missing counts as one. */
  deviceCount?: number | null;
}

export interface Inventory {
  candidates: Candidate[];
  /** Products over the limit, most devices first: not checked. */
  notChecked: string[];
  /** Entries that aren't products: Windows updates, language packs, app frameworks. */
  ignored: number;
}

/** Longest name or publisher kept; display names past this are noise, and the catalog's longest product name is shorter. */
const MAX_NAME = 100;

/** Not products: Windows updates and hotfixes, language packs, and the frameworks Store apps install alongside them. */
const NOT_PRODUCTS = [
  /^(?:security\s+|feature\s+|cumulative\s+)?update\s+for\b/i,
  /\bhotfix\b/i,
  /\(KB\d{6,8}\)|^KB\d{6,8}$/i,
  /\blanguage\s+pack\b|\b(?:language|local)\s+experience\s+pack\b/i,
  /^Microsoft\.(?:VCLibs|UI\.Xaml|NET\.Native|Services\.Store\.Engagement|WindowsAppRuntime|WinAppRuntime)\b/i,
];

/** Words in a trailing bracket that only say how it's built or installed: "(x64 en-US)", "(User)", "[64-bit]". */
const BUILD_WORD = /^(?:x64|x86|x86_64|amd64|arm64|aarch64|ia64|64-bit|32-bit|64bit|32bit|bit|user|machine|per-user|system|[a-z]{2}(?:-[a-z]{2,4})?|v?\d+(?:\.\d+)*)$/i;
const TRAILING_BRACKET = /\s*[([]([^()[\]]{0,60})[)\]]\s*$/;
/** " 23.01", " v130.0.6723.92", " - 14.38.33135", " 15.0.1-beta" at the end. */
const TRAILING_VERSION = /\s+(?:-\s+)?v?\d+(?:[._]\d+)+(?:[-+.][0-9a-z]{1,12})?\s*$/i;
/** " - en-us", " - de-de", " - x64" at the end. */
const TRAILING_DASH_TAG = /\s+-\s+(?:[a-z]{2}-[a-z]{2,4}|x64|x86|64-bit|32-bit|arm64)\s*$/i;
const TRAILING_ARCH = /\s+(?:x64|x86|x86_64|amd64|arm64|64-bit|32-bit)\s*$/i;
const COMPANY_SUFFIX = /(?:^|[,\s]+)(?:inc|incorporated|llc|ltd|limited|corp|corporation|co|company|gmbh|ag|sa|s\.a|bv|b\.v|plc|pty|srl|s\.r\.l|kk|oy|ab|as|a\/s)\.?\s*$/i;

/** A display name without its version, architecture, locale and install scope. */
export function productName(displayName: string): string {
  let name = displayName.replace(/\s+/g, ' ').trim().slice(0, 200);
  // A few passes, since the tags stack up: "7-Zip 23.01 (x64)", "Firefox (x64 en-US)".
  for (let pass = 0; pass < 4; pass++) {
    const before = name;
    const bracket = TRAILING_BRACKET.exec(name);
    if (bracket && bracket[1]!.split(/[\s,]+/).filter(Boolean).every((w) => BUILD_WORD.test(w))) name = name.slice(0, bracket.index);
    name = name.replace(TRAILING_VERSION, '').replace(TRAILING_DASH_TAG, '').replace(TRAILING_ARCH, '').trim();
    if (name === before) break;
  }
  return (name || displayName.trim()).slice(0, MAX_NAME);
}

/** A publisher without its company suffix: "Google LLC" is Google, "Mozilla Corporation" is Mozilla. */
export function vendorName(publisher: string | null | undefined): string | null {
  let vendor = (publisher ?? '').replace(/\s+/g, ' ').trim().slice(0, 200);
  for (let pass = 0; pass < 3; pass++) {
    const next = vendor.replace(COMPANY_SUFFIX, '').trim();
    if (next === vendor) break;
    vendor = next;
  }
  return normalizeKey(vendor) ? vendor.slice(0, MAX_NAME) : null;
}

export function isProduct(displayName: string): boolean {
  return !NOT_PRODUCTS.some((re) => re.test(displayName));
}

export function fromInventory(entries: InventoryEntry[], limit: number): Inventory {
  interface Product {
    name: string;
    vendor: string | null;
    versions: Set<string>;
    devices: number;
    first: number;
  }
  const products = new Map<string, Product>();
  let ignored = 0;
  entries.forEach((e, i) => {
    const display = typeof e.displayName === 'string' ? e.displayName : '';
    if (!display.trim() || !isProduct(display)) {
      ignored++;
      return;
    }
    const name = productName(display);
    const key = normalizeKey(name);
    if (!key) {
      ignored++;
      return;
    }
    const vendor = vendorName(e.publisher);
    const id = `${key}|${normalizeKey(vendor) ?? ''}`;
    const devices = typeof e.deviceCount === 'number' && Number.isFinite(e.deviceCount) && e.deviceCount > 0 ? e.deviceCount : 1;
    let p = products.get(id);
    if (!p) products.set(id, (p = { name, vendor, versions: new Set(), devices: 0, first: i }));
    p.devices += devices;
    const version = typeof e.version === 'string' ? e.version.trim() : '';
    // An unknown version among known ones still means "more than one version".
    p.versions.add(version);
  });
  // Most devices first; ties keep inventory order, so the result is stable.
  const ranked = [...products.values()].sort((a, b) => b.devices - a.devices || a.first - b.first);
  const label = (p: Product) => (p.vendor ? `${p.name} (${p.vendor})` : p.name);
  return {
    candidates: ranked.slice(0, limit).map((p): Candidate => {
      const only = p.versions.size === 1 ? [...p.versions][0]! : '';
      return { kind: 'product', name: p.name, vendor: p.vendor, version: only || null, direct: true };
    }),
    notChecked: ranked.slice(limit).map(label),
    ignored,
  };
}
