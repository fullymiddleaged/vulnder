import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../src/index';
import { resolveCandidates } from '../src/resolve/catalog';
import { SITEVERIFY_URL } from '../src/resolve/turnstile';
import type { Candidate } from '../src/resolve/types';
import { parseStack, serializeStack } from '../src/stack/format';
import { resetDb, store } from './helpers/db';

/**
 * People type anything, and the model passes it on. Whatever comes in, the
 * resolver must not throw, and every chip it returns must be a valid stack
 * item that the feed accepts.
 */

const PIECES = [
  'nginx', 'Fast API', 'Cisco', 'switches', 'Postgres', 'Next.js', 'FortiGate', 'Cisco Cisco', 'cisco/ios_xe', 'p:evil/x', '?p:f5/nginx',
  '@scope/pkg', 'a,b', '100%', '%2C', 'a@b@c', '../..', '?', '/', '\\', '<script>', '"quoted"', "it's", 'Ü', '名前', 'Ⅻ', '😀', '𝔘𝔫𝔦',
  '​', '\u0000', '\n', '\t', '  ', '', '-', '.', '_', 'x'.repeat(300), 'NaN', 'undefined', '__proto__', 'constructor', 'toString',
];
const VERSIONS = [null, '1.0', '16', '1.0 beta', '^1.2', '~2', 'v2', '1.0,2', 'x@y', '..', '1:2', '%', '1'.repeat(64), '1'.repeat(65), ' 1.0 ', '\n'];
const ECOSYSTEMS = ['npm', 'PyPI', 'crates.io', 'Go', 'Maven', 'NuGet', 'Packagist', 'RubyGems', 'Hex', 'Pub'] as const;

/** A small seeded PRNG (mulberry32), so a failure reproduces. */
function rng(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function candidates(seed: number, n: number): Candidate[] {
  const r = rng(seed);
  const pick = <T>(xs: readonly T[]) => xs[Math.floor(r() * xs.length)]!;
  const name = () =>
    Array.from({ length: 1 + Math.floor(r() * 3) }, () => pick(PIECES))
      .join(pick([' ', '', '/', '-', '.', ',']))
      .slice(0, 214) || 'x';
  return Array.from({ length: n }, (): Candidate => {
    const version = pick(VERSIONS);
    const direct = r() < 0.8;
    if (r() < 0.5) return { kind: 'package', ecosystem: pick(ECOSYSTEMS), name: name(), version, direct };
    return { kind: 'product', name: name().slice(0, 100), vendor: r() < 0.5 ? null : pick(PIECES).slice(0, 100), version, direct };
  });
}

async function seedCatalog(): Promise<void> {
  const rows: [string, string, string | null, string | null, string | null, string | null, string, string][] = [
    ['package', 'npm:next', 'npm', 'next', null, null, 'next', 'next'],
    ['package', 'PyPI:fastapi', 'PyPI', 'fastapi', null, null, 'fastapi', 'fastapi'],
    ['product', 'postgresql/postgresql', null, null, 'postgresql', 'postgresql', 'postgresql', 'PostgreSQL'],
    ['product', 'f5/nginx', null, null, 'f5', 'nginx', 'nginx', 'F5 NGINX'],
    ['product', 'nginx/nginx', null, null, 'nginx', 'nginx', 'nginx', 'nginx'],
    ['product', 'cisco/ios_xe', null, null, 'cisco', 'ios_xe', 'ios_xe', 'Cisco IOS XE'],
    ['product', 'cisco/cisco_industrial_ethernet_switches', null, null, 'cisco', 'cisco_industrial_ethernet_switches', 'cisco_industrial_ethernet_switches', 'Cisco Industrial Ethernet Switches'],
    ['product', 'fortinet/fortios', null, null, 'fortinet', 'fortios', 'fortios', 'Fortinet FortiOS'],
  ];
  await env.DB.batch(
    rows.map((row) =>
      env.DB.prepare('INSERT INTO catalog (kind, key, ecosystem, name, vendor, product, normalized, label, count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)').bind(...row),
    ),
  );
}

beforeEach(async () => {
  await resetDb();
  await seedCatalog();
});
afterEach(() => vi.restoreAllMocks());

describe('resolver under hostile input', () => {
  it('never throws, and every chip item is a valid stack item', async () => {
    for (let seed = 1; seed <= 60; seed++) {
      const input = candidates(seed, 8);
      let chips;
      try {
        chips = (await resolveCandidates(store(), input)).chips;
      } catch (err) {
        throw new Error(`seed ${seed} threw ${String(err)} on ${JSON.stringify(input)}`, { cause: err });
      }
      for (const chip of chips) {
        for (const { item } of chip.items) {
          let parsed;
          try {
            parsed = parseStack(item);
          } catch (err) {
            throw new Error(`seed ${seed}: chip item ${JSON.stringify(item)} is invalid (${String(err)}) for input ${JSON.stringify(chip.input)}`, { cause: err });
          }
          expect(parsed).toHaveLength(1);
          // Round trip: the item is already canonical.
          expect(serializeStack(parsed)).toBe(item);
        }
      }
    }
  });

  it('treats names that are also object properties as plain names', async () => {
    const res = await resolveCandidates(store(), [
      { kind: 'product', name: 'constructor', vendor: 'toString', version: null, direct: true },
      { kind: 'product', name: '__proto__', vendor: null, version: null, direct: true },
      { kind: 'package', ecosystem: 'npm', name: 'constructor', version: '1.0.0', direct: true },
    ]);
    expect(res.chips.map((c) => [c.status, c.items.map((i) => i.item)])).toEqual([
      ['unrecognised', []],
      ['unrecognised', []],
      ['resolved', ['npm:constructor@1.0.0']],
    ]);
  });

  it('answers hand-edited stack links with 200 or 400, never a 500', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json({ results: [] }));
    const r = rng(7);
    const pick = <T>(xs: readonly T[]) => xs[Math.floor(r() * xs.length)]!;
    const prefixes = ['npm:', 'pypi:', 'p:', '?p:', 'constructor:', '__proto__:', 'toString:', '~', '', 'gem:', 'P:', '?'];
    for (let i = 0; i < 80; i++) {
      const s = Array.from({ length: 1 + Math.floor(r() * 4) }, () => pick(prefixes) + pick(PIECES) + (r() < 0.3 ? `@${pick(VERSIONS) ?? ''}` : '')).join(pick([',', ',,', ' , ']));
      for (const path of ['/api/feed', '/feed.xml', '/badge.svg']) {
        const res = await app.request(`${path}?s=${encodeURIComponent(s)}${r() < 0.2 ? '&days=' + pick(['7', '0', '-1', 'x', '90', '1e3']) : ''}`, {}, env);
        expect([200, 400], `${path} for ${JSON.stringify(s)}`).toContain(res.status);
      }
    }
  });

  it('returns 200 or a 4xx from the API, never a 500, and the feed accepts what it returns', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === SITEVERIFY_URL) return Response.json({ success: true });
      // OSV: nothing affected.
      return Response.json({ results: [] });
    });
    const e = { ...env, TURNSTILE_SECRET_KEY: '1x0000000000000000000000000000000AA' };
    for (let seed = 100; seed <= 130; seed++) {
      const res = await app.request(
        '/api/resolve',
        { method: 'POST', body: JSON.stringify({ turnstileToken: 't', candidates: candidates(seed, 10) }), headers: { 'content-type': 'application/json' } },
        e,
      );
      expect(res.status, `seed ${seed}`).toBeLessThan(500);
      if (res.status !== 200) continue;
      const body = (await res.json()) as { chips: { items: { item: string }[] }[] };
      const items = [...new Set(body.chips.flatMap((c) => c.items.map((i) => i.item)))];
      if (items.length === 0) continue;
      const feed = await app.request(`/api/feed?s=${encodeURIComponent(items.join(','))}`, {}, e);
      expect(feed.status, `seed ${seed}: feed for ${items.join(',')}`).toBe(200);
    }
  });
});
