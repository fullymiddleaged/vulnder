import { deflateSync, inflateSync, strFromU8, strToU8 } from 'fflate';
import { normalizeKey, normalizePackageName, ownValue, type Ecosystem } from '../lib/normalize';

/**
 * The stack URL format, version 1. This is a public contract: people bookmark
 * feeds built from it. See docs/STACK_FORMAT.md before changing anything here.
 */

export const MAX_ITEMS = 200;
/** Longest `s` value accepted, in characters (Cloudflare caps URLs at about 16 KB). */
export const MAX_PARAM_CHARS = 16_000;
export const MAX_PLAIN_CHARS = 65_536;
/** Plain values longer than this are compressed when serialised. */
export const COMPRESS_ABOVE = 1500;

/** Short, stable prefixes for each ecosystem. Never rename one. */
export const PREFIXES: Record<string, Ecosystem> = {
  npm: 'npm',
  pypi: 'PyPI',
  cargo: 'crates.io',
  go: 'Go',
  maven: 'Maven',
  nuget: 'NuGet',
  composer: 'Packagist',
  gem: 'RubyGems',
  hex: 'Hex',
  pub: 'Pub',
  swift: 'SwiftURL',
  actions: 'GitHub Actions',
};
const PREFIX_FOR: Record<string, string> = Object.fromEntries(Object.entries(PREFIXES).map(([p, e]) => [e, p]));

/**
 * `close` marks a close match: something the user's words loosely fit (e.g. one
 * of several Cisco switch products for "Cisco switches"), shown but labelled.
 * `exposed` marks an item reachable from the internet, which raises the
 * priority of bugs an attacker could reach on it.
 */
export interface Marks {
  close?: boolean;
  exposed?: boolean;
}
export type StackItem =
  | ({ kind: 'package'; ecosystem: Ecosystem; name: string; version: string | null } & Marks)
  | ({ kind: 'product'; vendor: string; product: string; version: string | null } & Marks);

/** Marks a close match in the URL: `?p:nginx/nginx`. */
const CLOSE_MARK = '?';
/** Marks an internet-facing item: `!p:f5/nginx`. Written before the close mark: `!?p:f5/nginx`. */
const EXPOSED_MARK = '!';

export class StackFormatError extends Error {
  constructor(
    message: string,
    readonly invalid: string[] = [],
  ) {
    super(message);
    this.name = 'StackFormatError';
  }
}

const VERSION_RE = /^[A-Za-z0-9._+~:\-^*]{1,64}$/;

/** True when a version can appear in a stack item. */
export function isStackVersion(version: string): boolean {
  return VERSION_RE.test(version);
}

/** Parses an `s` parameter (plain or `~`-compressed) into canonical items. */
export function parseStack(param: string): StackItem[] {
  if (param.length > MAX_PARAM_CHARS) throw new StackFormatError(`the stack parameter is longer than ${MAX_PARAM_CHARS} characters`);
  const plain = param.startsWith('~') ? decompress(param.slice(1)) : param;
  const parts = plain
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
  if (parts.length === 0) throw new StackFormatError('the stack is empty');

  const items: StackItem[] = [];
  const invalid: string[] = [];
  for (const part of parts) {
    const item = parseItem(unescape(part));
    if (item) items.push(item);
    else invalid.push(part);
  }
  if (invalid.length > 0) throw new StackFormatError(`unrecognised stack item(s): ${invalid.slice(0, 5).join(', ')}`, invalid);
  const canonical = canonicalize(items);
  if (canonical.length > MAX_ITEMS) {
    throw new StackFormatError(`a stack can have at most ${MAX_ITEMS} items; self-host Vulnder for larger stacks`);
  }
  return canonical;
}

/** Serialises items in canonical order; compresses long stacks. */
export function serializeStack(items: StackItem[]): string {
  const plain = canonicalize(items).map(formatItem).join(',');
  if (plain.length <= COMPRESS_ABOVE) return plain;
  return `~${base64url(deflateSync(strToU8(plain), { level: 9 }))}`;
}

export function formatItem(item: StackItem): string {
  return `${item.exposed ? EXPOSED_MARK : ''}${item.close ? CLOSE_MARK : ''}${identity(item)}`;
}

/** The item without its marks. */
export function identity(item: StackItem): string {
  const base = item.kind === 'package' ? `${PREFIX_FOR[item.ecosystem]}:${escape(item.name)}` : `p:${escape(item.vendor)}/${escape(item.product)}`;
  return item.version ? `${base}@${escape(item.version)}` : base;
}

/**
 * Deduplicates and sorts, so equivalent stacks share one URL and one cache
 * entry. When the same item appears more than once, exact beats close and
 * internet-facing beats not.
 */
export function canonicalize(items: StackItem[]): StackItem[] {
  const byKey = new Map<string, StackItem>();
  for (const item of items) {
    const key = identity(item);
    const prev = byKey.get(key);
    byKey.set(key, withMarks(item, { close: !!item.close && (!prev || !!prev.close), exposed: !!item.exposed || !!prev?.exposed }));
  }
  return [...byKey.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, item]) => item);
}

/** The item with exactly these marks; a false mark is left out, not stored as false. */
export function withMarks(item: StackItem, marks: Marks): StackItem {
  const { close: _close, exposed: _exposed, ...rest } = item;
  return { ...rest, ...(marks.close && { close: true }), ...(marks.exposed && { exposed: true }) } as StackItem;
}

function parseItem(raw: string): StackItem | null {
  let rest = raw;
  const marks: Marks = {};
  // Each mark at most once, in either order.
  for (let i = 0; i < 2; i++) {
    if (!marks.exposed && rest.startsWith(EXPOSED_MARK)) marks.exposed = true;
    else if (!marks.close && rest.startsWith(CLOSE_MARK)) marks.close = true;
    else break;
    rest = rest.slice(1);
  }
  const item = parseExactItem(rest);
  return item && withMarks(item, marks);
}

function parseExactItem(text: string): StackItem | null {
  const colon = text.indexOf(':');
  if (colon <= 0) return null;
  const prefix = text.slice(0, colon).toLowerCase();
  const rest = text.slice(colon + 1);
  // The version follows the last '@' that is not the first character (npm scopes start with '@').
  const at = rest.lastIndexOf('@');
  const body = at > 0 ? rest.slice(0, at) : rest;
  const rawVersion = at > 0 ? rest.slice(at + 1).trim() : '';
  if (rawVersion && !VERSION_RE.test(rawVersion)) return null;
  const version = rawVersion || null;

  if (prefix === 'p') {
    const slash = body.indexOf('/');
    if (slash <= 0) return null;
    const vendor = normalizeKey(body.slice(0, slash));
    const product = normalizeKey(body.slice(slash + 1));
    if (!vendor || !product) return null;
    return { kind: 'product', vendor, product, version };
  }

  const ecosystem = ownValue(PREFIXES, prefix);
  if (!ecosystem) return null;
  const name = body.trim();
  // eslint-disable-next-line no-control-regex -- reject control characters in names
  if (!name || name.length > 214 || /[\s\u0000-\u001f]/.test(name)) return null;
  return { kind: 'package', ecosystem, name: normalizePackageName(ecosystem, name), version };
}

/** Only ',' and '%' need escaping inside an item; the URL layer handles the rest. */
function escape(s: string): string {
  return s.replace(/%/g, '%25').replace(/,/g, '%2C');
}

function unescape(s: string): string {
  return s.replace(/%2C/gi, ',').replace(/%25/g, '%');
}

function decompress(b64: string): string {
  let bytes: Uint8Array;
  try {
    bytes = fromBase64url(b64);
  } catch {
    throw new StackFormatError('the compressed stack is not valid base64url');
  }
  let out: Uint8Array;
  try {
    // A fixed output buffer bounds memory: anything that fills it is rejected.
    out = inflateSync(bytes, { out: new Uint8Array(MAX_PLAIN_CHARS + 1) });
  } catch {
    throw new StackFormatError('the compressed stack could not be decompressed');
  }
  if (out.length > MAX_PLAIN_CHARS) throw new StackFormatError('the compressed stack is too large');
  return strFromU8(out);
}

function base64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64url(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('bad base64url');
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
