import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { Budget } from '../src/ingest/budget';
import {
  assign,
  assignFamilies,
  BIG_KEY,
  blocksFor,
  checkVectors,
  decodeVector,
  EMBED_DAILY_TOKENS,
  EMBED_DIMS,
  encodeVector,
  FAMILY_SIM,
  familyText,
  similarity,
  titleStem,
  type Embedder,
} from '../src/ingest/families';
import { maintenanceStatements } from '../src/ingest/maintenance';
import { addUsageStatement } from '../src/lib/quota';
import { matchStack } from '../src/match/match';
import { parseStack } from '../src/stack/format';
import calibration from './fixtures/families/calibration.json';
import { resetDb, rows, store, unlimitedBudget } from './helpers/db';

const NOW = new Date('2026-10-07T12:00:00Z');

/** A unit vector along one axis, blended toward a second: similarity to the pure axis is cos(angle). */
function vec(axis: number, toward = axis, mix = 0): number[] {
  const v = new Array<number>(1024).fill(0);
  v[axis] = Math.cos(mix);
  v[toward] = (v[toward] ?? 0) + Math.sin(mix);
  return v;
}
const iv = (v: number[]) => decodeVector(encodeVector(v))!;

describe('calibration: real Workers AI vectors for labelled CVE pairs', () => {
  it.each(calibration.pairs.map((p) => [p.note, p] as const))('%s', (_note, pair) => {
    const [a, b] = pair.vectors.map((v) => decodeVector(v)!);
    const sim = similarity(a!, b!);
    if (pair.same) expect(sim).toBeGreaterThanOrEqual(FAMILY_SIM);
    else expect(sim).toBeLessThan(FAMILY_SIM);
  });
});

describe('vectors', () => {
  it('truncates, normalises and quantises to EMBED_DIMS int8 and back', () => {
    const v = iv(vec(3, 7, 0.4));
    expect(v.length).toBe(EMBED_DIMS);
    expect(similarity(v, v)).toBeCloseTo(1, 6);
    expect(similarity(iv(vec(3)), v)).toBeCloseTo(Math.cos(0.4), 2);
  });

  it('rejects malformed stored vectors and treats a zero vector as unlike anything', () => {
    expect(decodeVector('not base64!')).toBeNull();
    expect(decodeVector(btoa('short'))).toBeNull();
    const zero = new Int8Array(EMBED_DIMS);
    expect(similarity(zero, iv(vec(1)))).toBe(0);
  });

  it('accepts only one finite row per text from the model', () => {
    expect(checkVectors([vec(1)], 1)).toHaveLength(1);
    expect(() => checkVectors([vec(1)], 2)).toThrow(/unexpected/);
    expect(() => checkVectors([[1, 2, 3]], 1)).toThrow(/unexpected/);
    expect(() => checkVectors([[...vec(1).slice(1), Number.NaN]], 1)).toThrow(/unexpected/);
    expect(() => checkVectors(null, 0)).toThrow(/unexpected/);
  });
});

describe('familyText and blocks', () => {
  it('drops a title prefix that only names the product', () => {
    expect(familyText('n8n: Prototype Pollution via Workflow', null, ['n8n'])).toBe('Prototype Pollution via Workflow');
    expect(familyText('Open WebUI: SSRF via redirects', null, ['open-webui'])).toBe('SSRF via redirects');
    // A kernel subsystem prefix is the signal, not the product.
    expect(familyText('staging: rtl8723bs: fix leak', null, ['linux', 'Linux'])).toBe('staging: rtl8723bs: fix leak');
  });

  it('drops the product name, version bounds and platform boilerplate wherever they appear', () => {
    expect(familyText('Mitel MiVoice Office 400 stored Cross-Site Scripting', null, ['mitel', 'mivoice_office_400'])).toBe('stored Cross-Site Scripting');
    expect(familyText('Monta monta.app Insufficient Session Expiration', null, ['Monta', 'monta.app'])).toBe('Insufficient Session Expiration');
    expect(familyText('WordPress WP Event Solution plugin <= 4.1.25 - Broken Access Control vulnerability', null, ['WP Event Solution'])).toBe(
      'Broken Access Control',
    );
    // A part that isn't the product's keeps the word.
    expect(familyText('Drug System add_drug.php sql injection', null, ['drug_system'])).toBe('add_drug.php sql injection');
    // Never stripped down to less than two words.
    expect(familyText('Acme Gate crash', null, ['acme_gate'])).toBe('Acme Gate crash');
  });

  it('falls back to the summary, without the kernel preamble, and to null', () => {
    expect(familyText(null, 'In the Linux kernel, the following vulnerability has been resolved: bpf: fix x', ['linux'])).toBe('bpf: fix x');
    expect(familyText('  ', '  ', [])).toBeNull();
    expect(familyText('x'.repeat(5000), null, [])!.length).toBe(600);
  });

  it('blocks on the key, plus the title stem when the key is big', () => {
    const small = { kind: 'package' as const, key: 'npm:n8n', count: 3 };
    const big = { kind: 'product' as const, key: 'microsoft/windows_11', count: BIG_KEY };
    expect(blocksFor([small, big, small], 'Windows Biometric Service EoP')).toEqual(['package:npm:n8n', 'product:microsoft/windows_11|windows biometric']);
    expect(titleStem('staging: rtl8723bs: fix')).toBe('staging rtl8723bs');
    expect(blocksFor([], 'x')).toEqual([]);
  });
});

describe('assign', () => {
  const block = ['package:npm:x'];

  it('joins the most similar leader at the threshold, otherwise leads', () => {
    const leaders = [
      { block: block[0]!, leader: 'A', vector: iv(vec(0)) },
      { block: block[0]!, leader: 'B', vector: iv(vec(5)) },
    ];
    const { familyOf, newLeaders } = assign(
      [
        { id: 'C', vector: iv(vec(0, 1, 0.2)), blocks: block },
        { id: 'D', vector: iv(vec(9)), blocks: block },
      ],
      leaders,
    );
    expect(familyOf.get('C')).toBe('A');
    expect(familyOf.get('D')).toBe('D');
    expect(newLeaders.map((l) => l.leader)).toEqual(['D']);
  });

  it('never compares across blocks', () => {
    const { familyOf } = assign([{ id: 'C', vector: iv(vec(0)), blocks: ['package:npm:y'] }], [{ block: block[0]!, leader: 'A', vector: iv(vec(0)) }]);
    expect(familyOf.get('C')).toBe('C');
  });

  it('compares with leaders only, so near neighbours cannot chain', () => {
    // B is close to A; C is close to B but not to A.
    const step = Math.acos(FAMILY_SIM) * 0.9;
    const { familyOf } = assign(
      [
        { id: 'A', vector: iv(vec(0)), blocks: block },
        { id: 'B', vector: iv(vec(0, 1, step)), blocks: block },
        { id: 'C', vector: iv(vec(0, 1, step * 2)), blocks: block },
      ],
      [],
    );
    expect([familyOf.get('A'), familyOf.get('B'), familyOf.get('C')]).toEqual(['A', 'A', 'C']);
  });
});

describe('assignFamilies (ingest stage)', () => {
  beforeEach(resetDb);

  async function seed(vulns: { id: string; title: string; published: string; product?: string; kev?: boolean }[]) {
    await env.DB.batch(
      vulns.flatMap((v) => [
        env.DB.prepare(
          `INSERT INTO vulns (id, title, summary, published_at, kev_added_at, updated_at) VALUES (?, ?, NULL, ?, ?, ?)`,
        ).bind(v.id, v.title, v.published, v.kev ? '2026-10-02T00:00:00.000Z' : null, NOW.toISOString()),
        env.DB.prepare(`INSERT INTO affected (vuln_id, source, kind, vendor, product, label) VALUES (?, 'cve', 'product', 'acme', ?, 'Acme Gate')`).bind(
          v.id,
          v.product ?? 'gate',
        ),
      ]),
    );
  }

  /** Texts mentioning "sandbox" point one way, everything else another. */
  const fakeEmbed: Embedder & { calls: string[][] } = Object.assign(
    async (texts: string[]) => {
      fakeEmbed.calls.push(texts);
      return texts.map((t) => (/sandbox/i.test(t) ? vec(0, 1, /again/.test(t) ? 0.1 : 0) : vec(7)));
    },
    { calls: [] as string[][] },
  );
  const run = (embed: Embedder = fakeEmbed, budget = unlimitedBudget()) =>
    assignFamilies({ store: store(), budget, embed, now: () => NOW, log: () => {} });

  beforeEach(() => {
    fakeEmbed.calls = [];
  });

  it('puts variants in one family, leaves others alone, and records leaders and tokens', async () => {
    await seed([
      { id: 'CVE-2026-0001', title: 'Acme Gate: Sandbox escape via templates', published: '2026-10-01T00:00:00Z' },
      { id: 'CVE-2026-0002', title: 'Acme Gate: Sandbox escape again via filters', published: '2026-10-02T00:00:00Z' },
      { id: 'CVE-2026-0003', title: 'Acme Gate: Login rate limit missing', published: '2026-10-03T00:00:00Z' },
      { id: 'CVE-2026-0004', title: 'Sandbox escape in another product', published: '2026-10-04T00:00:00Z', product: 'other' },
    ]);
    const report = await run();
    expect(report).toMatchObject({ assigned: 4, joined: 1 });
    // The product prefix was stripped before embedding.
    expect(fakeEmbed.calls.flat()).toContain('Sandbox escape via templates');
    const fam = await rows<{ id: string; family_id: string }>('SELECT id, family_id FROM vulns ORDER BY id');
    expect(fam.map((r) => r.family_id)).toEqual(['CVE-2026-0001', 'CVE-2026-0001', 'CVE-2026-0003', 'CVE-2026-0004']);
    const leaders = await rows<{ block: string; leader: string }>('SELECT block, leader FROM families ORDER BY leader');
    expect(leaders.map((l) => l.leader)).toEqual(['CVE-2026-0001', 'CVE-2026-0003', 'CVE-2026-0004']);
    const [usage] = await rows<{ count: number }>("SELECT count FROM usage_counters WHERE bucket = 'embed'");
    expect(usage!.count).toBe(report.tokens);

    // A second run finds nothing left to do and calls no model.
    fakeEmbed.calls = [];
    expect(await run()).toMatchObject({ assigned: 0 });
    expect(fakeEmbed.calls).toEqual([]);
  });

  it('joins later CVEs to families made in earlier runs', async () => {
    await seed([{ id: 'CVE-2026-0001', title: 'Sandbox escape via templates', published: '2026-10-01T00:00:00Z' }]);
    await run();
    await seed([{ id: 'CVE-2026-0002', title: 'Sandbox escape again via filters', published: '2026-10-05T00:00:00Z' }]);
    expect(await run()).toMatchObject({ assigned: 1, joined: 1 });
    expect((await rows<{ family_id: string }>("SELECT family_id FROM vulns WHERE id = 'CVE-2026-0002'"))[0]!.family_id).toBe('CVE-2026-0001');
  });

  it('fails open when the model fails, and stops at the daily token cap', async () => {
    await seed([{ id: 'CVE-2026-0001', title: 'Sandbox escape', published: '2026-10-01T00:00:00Z' }]);
    expect(await run(async () => Promise.reject(new Error('2021: Insufficient credits')))).toMatchObject({ assigned: 0, stopped: 'embedding failed' });
    expect((await rows<{ family_id: string | null }>('SELECT family_id FROM vulns'))[0]!.family_id).toBeNull();

    await store().batch([addUsageStatement('embed', EMBED_DAILY_TOKENS, NOW)]);
    expect(await run()).toMatchObject({ assigned: 0, stopped: 'daily token cap' });
    expect(fakeEmbed.calls).toEqual([]);
  });

  it('assigns at most the daily cap, counted across runs', async () => {
    await seed(
      Array.from({ length: 5 }, (_, i) => ({ id: `CVE-2026-000${i + 1}`, title: `Bug number ${i + 1} in parsing`, published: `2026-10-0${i + 1}T00:00:00Z` })),
    );
    const capped = () => assignFamilies({ store: store(), budget: unlimitedBudget(), embed: fakeEmbed, now: () => NOW, log: () => {}, dailyVulns: 3 });
    expect(await capped()).toMatchObject({ assigned: 3, stopped: 'daily cap' });
    expect(await capped()).toMatchObject({ assigned: 0, stopped: 'daily cap' });
    expect(await rows("SELECT count FROM usage_counters WHERE bucket = 'family'")).toEqual([{ count: 3 }]);
    expect(await rows('SELECT id FROM vulns WHERE family_id IS NULL')).toHaveLength(2);
    // Without a cap (the Paid cron), the rest go.
    expect(await run()).toMatchObject({ assigned: 2 });
  });

  it('stops before the budget runs out', async () => {
    await seed([{ id: 'CVE-2026-0001', title: 'Sandbox escape', published: '2026-10-01T00:00:00Z' }]);
    const tight = new Budget({ maxSubrequests: 5, deadline: Number.MAX_SAFE_INTEGER });
    expect(await run(fakeEmbed, tight)).toMatchObject({ assigned: 0, stopped: 'budget' });
  });

  it('drops a pruned leader with its vuln', async () => {
    await seed([{ id: 'CVE-2025-0001', title: 'Sandbox escape', published: '2025-01-01T00:00:00Z' }]);
    await run();
    expect(await rows('SELECT leader FROM families')).toHaveLength(1);
    await store().batch(maintenanceStatements(NOW));
    expect(await rows('SELECT leader FROM families')).toHaveLength(0);
  });
});

describe('families in the feed', () => {
  beforeEach(resetDb);

  it('links family members and lifts a variant of an exploited CVE to Attend, never Act', async () => {
    await env.DB.batch([
      ...[
        ['CVE-2026-0001', '2026-10-01T00:00:00.000Z', null],
        ['CVE-2026-0002', '2026-10-02T00:00:00.000Z', null],
        // Exploited, and outside the window and the year-long safety net: still counts as evidence.
        ['CVE-2026-0003', '2025-01-02T00:00:00.000Z', '2025-01-05T00:00:00.000Z'],
        ['CVE-2026-0004', '2026-10-03T00:00:00.000Z', null],
      ].flatMap(([id, published, kev]) => [
        env.DB.prepare(`INSERT INTO vulns (id, title, published_at, kev_added_at, cvss_score, family_id, updated_at) VALUES (?, ?, ?, ?, 5.0, ?, ?)`).bind(
          id,
          `Bug ${id}`,
          published,
          kev,
          id === 'CVE-2026-0004' ? id : 'CVE-2026-0001',
          NOW.toISOString(),
        ),
        env.DB.prepare(`INSERT INTO affected (vuln_id, source, kind, vendor, product) VALUES (?, 'cve', 'product', 'acme', 'gate')`).bind(id),
      ]),
    ]);
    const res = await matchStack(store(), parseStack('p:acme/gate'), { now: NOW, days: 30, osv: { affecting: async () => new Map() } });
    const byId = new Map(res.results.map((r) => [r.id, r]));
    expect([...byId.keys()].sort()).toEqual(['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0004']);
    for (const id of ['CVE-2026-0001', 'CVE-2026-0002']) {
      const r = byId.get(id)!;
      expect(r.priority).toBe('attend');
      expect(r.reasons[0]).toBe('Similar to exploited CVE-2026-0003 in the same product');
      expect(r.family).toBe('CVE-2026-0001');
    }
    expect(byId.get('CVE-2026-0001')!.related).toEqual(['CVE-2026-0002']);
    expect(byId.get('CVE-2026-0004')).toMatchObject({ priority: 'track', family: null, related: [] });
  });
});
