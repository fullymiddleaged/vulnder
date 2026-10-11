import { env } from 'cloudflare:workers';
import fc from 'fast-check';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../src/index';
import { resolveCandidates } from '../src/resolve/catalog';
import { SITEVERIFY_URL } from '../src/resolve/turnstile';
import type { Candidate } from '../src/resolve/types';
import { parseStack, serializeStack, StackFormatError } from '../src/stack/format';
import { resetDb, store } from './helpers/db';

/**
 * People type anything, and the model passes it on. Whatever comes in, the
 * resolver must not throw, and every chip it returns must be a valid stack
 * item that the feed accepts. Property-based with fast-check: a failure prints
 * its seed and the smallest input that still fails, so it reproduces.
 */

const PIECES = [
  'nginx', 'Fast API', 'Cisco', 'switches', 'Postgres', 'Next.js', 'FortiGate', 'Cisco Cisco', 'cisco/ios_xe', 'p:evil/x', '?p:f5/nginx',
  '@scope/pkg', 'a,b', '100%', '%2C', 'a@b@c', '../..', '?', '/', '\\', '<script>', '"quoted"', "it's", 'Ü', '名前', 'Ⅻ', '😀', '𝔘𝔫𝔦',
  '​', '\u0000', '\n', '\t', '  ', '', '-', '.', '_', 'x'.repeat(300), 'NaN', 'undefined', '__proto__', 'constructor', 'toString',
];
const VERSIONS = [null, '1.0', '16', '1.0 beta', '^1.2', '~2', 'v2', '1.0,2', 'x@y', '..', '1:2', '%', '1'.repeat(64), '1'.repeat(65), ' 1.0 ', '\n'];
const ECOSYSTEMS = ['npm', 'PyPI', 'crates.io', 'Go', 'Maven', 'NuGet', 'Packagist', 'RubyGems', 'Hex', 'Pub'] as const;

/** Mostly the hand-picked hostile pieces, sometimes any Unicode at all. */
const piece = fc.oneof({ weight: 4, arbitrary: fc.constantFrom(...PIECES) }, { weight: 1, arbitrary: fc.string({ unit: 'binary', maxLength: 24 }) });
const version = fc.oneof({ weight: 4, arbitrary: fc.constantFrom(...VERSIONS) }, { weight: 1, arbitrary: fc.string({ unit: 'binary', maxLength: 70 }) });
const name = fc
  .tuple(fc.array(piece, { minLength: 1, maxLength: 3 }), fc.constantFrom(' ', '', '/', '-', '.', ','))
  .map(([parts, sep]) => parts.join(sep).slice(0, 214) || 'x');

const candidate: fc.Arbitrary<Candidate> = fc.oneof(
  fc.record({
    kind: fc.constant('package' as const),
    ecosystem: fc.constantFrom(...ECOSYSTEMS),
    name,
    version,
    direct: fc.boolean(),
  }),
  fc.record({
    kind: fc.constant('product' as const),
    name: name.map((n) => n.slice(0, 100)),
    vendor: fc.option(piece.map((p) => p.slice(0, 100)), { nil: null }),
    version,
    direct: fc.boolean(),
  }),
);
const candidates = (max: number) => fc.array(candidate, { minLength: 1, maxLength: max });

/** Hand-edited `s` values: real prefixes, junk prefixes, pieces, versions and separators. */
const stackParam = fc
  .array(
    fc
      .tuple(
        fc.constantFrom('npm:', 'pypi:', 'p:', '?p:', 'constructor:', '__proto__:', 'toString:', '~', '', 'gem:', 'P:', '?'),
        piece,
        fc.option(version.map((v) => `@${v ?? ''}`), { nil: '' }),
      )
      .map(([prefix, p, v]) => prefix + p + v),
    { minLength: 1, maxLength: 4 },
  )
  .chain((parts) => fc.constantFrom(',', ',,', ' , ').map((sep) => parts.join(sep)));

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
    await fc.assert(
      fc.asyncProperty(candidates(8), async (input) => {
        const { chips } = await resolveCandidates(store(), input);
        for (const chip of chips) {
          for (const { item } of chip.items) {
            const parsed = parseStack(item);
            expect(parsed, `chip item ${JSON.stringify(item)} for ${JSON.stringify(chip.input)}`).toHaveLength(1);
            // Round trip: the item is already canonical.
            expect(serializeStack(parsed)).toBe(item);
          }
        }
      }),
      { numRuns: 60 },
    );
  });

  it('parses any stack parameter or rejects it with a StackFormatError, and round-trips what it accepts', () => {
    const anyParam = fc.oneof(
      stackParam,
      fc.string({ unit: 'binary', maxLength: 300 }),
      fc.stringMatching(/^~[A-Za-z0-9_-]{0,200}$/),
    );
    fc.assert(
      fc.property(anyParam, (s) => {
        let items;
        try {
          items = parseStack(s);
        } catch (err) {
          if (err instanceof StackFormatError) return;
          throw err;
        }
        expect(items.length).toBeGreaterThan(0);
        expect(parseStack(serializeStack(items))).toEqual(items);
      }),
      { numRuns: 1000 },
    );
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
    const days = fc.option(fc.constantFrom('7', '0', '-1', 'x', '90', '1e3'), { nil: null, freq: 4 });
    await fc.assert(
      fc.asyncProperty(stackParam, days, async (s, d) => {
        for (const path of ['/api/feed', '/feed.xml', '/badge.svg']) {
          const res = await app.request(`${path}?s=${encodeURIComponent(s)}${d === null ? '' : `&days=${d}`}`, {}, env);
          expect([200, 400], `${path} for ${JSON.stringify(s)}`).toContain(res.status);
        }
      }),
      { numRuns: 80 },
    );
  });

  it('returns 200 or a 4xx from the API, never a 500, and the feed accepts what it returns', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === SITEVERIFY_URL) return Response.json({ success: true });
      // OSV: nothing affected.
      return Response.json({ results: [] });
    });
    const e = { ...env, TURNSTILE_SECRET_KEY: '1x0000000000000000000000000000000AA' };
    await fc.assert(
      fc.asyncProperty(candidates(10), async (input) => {
        const res = await app.request(
          '/api/resolve',
          { method: 'POST', body: JSON.stringify({ turnstileToken: 't', candidates: input }), headers: { 'content-type': 'application/json' } },
          e,
        );
        expect(res.status).toBeLessThan(500);
        if (res.status !== 200) return;
        const body = (await res.json()) as { chips: { items: { item: string }[] }[] };
        const items = [...new Set(body.chips.flatMap((c) => c.items.map((i) => i.item)))];
        if (items.length === 0) return;
        const feed = await app.request(`/api/feed?s=${encodeURIComponent(items.join(','))}`, {}, e);
        expect(feed.status, `feed for ${items.join(',')}`).toBe(200);
      }),
      { numRuns: 31 },
    );
  });
});
