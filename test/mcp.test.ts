import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../src/index';
import { applyPatches } from '../src/ingest/apply';
import { bumpDataVersionStatement } from '../src/ingest/meta';
import type { VulnPatch } from '../src/ingest/types';
import { OSV_QUERYBATCH_URL } from '../src/match/osv';
import type { MatchedVuln } from '../src/match/match';
import { batchRefusal, cveStack, headline, MAX_BATCH_MESSAGES, MAX_RESULT_LIMIT } from '../src/routes/mcp';
import { parseStack } from '../src/stack/format';
import { resetDb, store } from './helpers/db';

const NOW = new Date();
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();
const GHSA_NEXT = 'GHSA-2222-3333-4444';
const STACK = 'npm:next@14.2.3,pypi:fastapi,p:postgresql/postgresql@16,p:cisco/ios_xe';
const IP = '203.0.113.9';

function seedPatches(): VulnPatch[] {
  return [
    {
      source: 'ghsa',
      id: 'CVE-2026-1001',
      aliases: [GHSA_NEXT],
      fields: { title: 'Next.js middleware bypass', publishedAt: daysAgo(10), cvssScore: 9.1 },
      affected: [{ kind: 'package', ecosystem: 'npm', packageName: 'next', ranges: [{ range: '< 14.2.5' }], fixedVersion: '14.2.5' }],
    },
    { source: 'kev', id: 'CVE-2026-1001', aliases: [], fields: { kevAddedAt: daysAgo(3), kevRansomware: false, kevDueDate: null } },
    {
      source: 'cve',
      id: 'CVE-2026-1003',
      aliases: [],
      fields: { title: 'PostgreSQL privilege escalation', publishedAt: daysAgo(20), cvssScore: 8.8 },
      affected: [{ kind: 'product', vendor: 'postgresql', product: 'postgresql', ranges: [], fixedVersion: null }],
    },
    {
      source: 'kev',
      id: 'CVE-2026-1005',
      aliases: [],
      fields: { title: 'Cisco IOS XE web UI privilege escalation', kevAddedAt: daysAgo(1), kevRansomware: true, kevDueDate: daysAgo(-20) },
      affected: [{ kind: 'product', vendor: 'cisco', product: 'ios_xe', ranges: [], fixedVersion: null }],
    },
  ];
}

/** OSV says next@14.2.3 is affected by CVE-2026-1001 (via its GHSA alias). */
function stubOsvFetch() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const req = new Request(input, init);
    if (req.url !== OSV_QUERYBATCH_URL) throw new Error(`unexpected fetch ${req.url}`);
    const body = (await req.json()) as { queries: { package: { name: string }; version: string }[] };
    return Response.json({ results: body.queries.map((q) => (q.package.name === 'next' && q.version === '14.2.3' ? { vulns: [{ id: GHSA_NEXT, modified: 'x' }] } : {})) });
  });
}

type Era = 'modern' | 'legacy';

/** An MCP client talking to the Worker in-process, as an agent would over HTTP. */
async function connect(era: Era, e: Env = env): Promise<Client> {
  const transport = new StreamableHTTPClientTransport(new URL(`${env.BASE_URL}/mcp`), {
    fetch: async (url, init) => app.request(new Request(url, init), undefined, e),
    requestInit: { headers: { 'cf-connecting-ip': IP } },
  });
  const client = new Client(
    { name: 'test-agent', version: '1.0.0' },
    era === 'modern' ? { versionNegotiation: { mode: { pin: '2026-07-28' } } } : {},
  );
  await client.connect(transport);
  return client;
}

interface Structured {
  stack: string;
  priorities: Record<string, number>;
  totalResults: number;
  resultsShown: number;
  fixFirst: { item: string }[];
  results: { id: string; priority: string; exploited: boolean; reasons: string[] }[];
  listed?: { notFound: string[] };
  links: Record<string, string>;
  note: string;
}

const text = (r: { content: unknown }) => (r.content as { type: string; text: string }[]).map((c) => c.text).join('\n');

// The Cache API outlives each test and cannot be cleared in workerd, so every
// test starts from its own data version, as feeds.test.ts does.
let versionBase = Date.now() * 100 + 50;

beforeEach(async () => {
  await resetDb();
  await applyPatches(store(), seedPatches(), { now: NOW, windowStart: daysAgo(90), epssEvents: true });
  await store().batch([bumpDataVersionStatement(NOW)]);
  versionBase += 100;
  await env.DB.prepare("UPDATE meta SET value = ? WHERE key = 'data_version'").bind(String(versionBase)).run();
});
afterEach(() => vi.restoreAllMocks());

describe.each<Era>(['modern', 'legacy'])('MCP over the %s protocol', (era) => {
  it('lists the two read-only tools', async () => {
    const client = await connect(era);
    const { tools } = await client.listTools();
    expect(client.getNegotiatedProtocolVersion()).toBe(era === 'modern' ? '2026-07-28' : '2025-11-25');
    expect(tools.map((t) => t.name).sort()).toEqual(['rank_cves', 'rank_stack']);
    for (const t of tools) expect(t.annotations?.readOnlyHint).toBe(true);
    await client.close();
  });

  it('ranks a stack exactly as the JSON feed does', async () => {
    stubOsvFetch();
    const client = await connect(era);
    const result = await client.callTool({ name: 'rank_stack', arguments: { stack: STACK } });
    expect(result.isError).toBeFalsy();
    const got = result.structuredContent as unknown as Structured;
    const feed = (await (await app.request(`/api/feed?s=${encodeURIComponent(STACK)}`, {}, env)).json()) as {
      stack: string;
      priorities: Record<string, number>;
      fixFirst: { item: string }[];
      results: { id: string }[];
    };
    expect(got.stack).toBe(feed.stack);
    expect(got.priorities).toEqual(feed.priorities);
    expect(got.fixFirst.map((f) => f.item)).toEqual(feed.fixFirst.map((f) => f.item));
    expect(got.results.map((r) => r.id)).toEqual(feed.results.map((r) => r.id));
    expect(got.results[0]).toMatchObject({ id: 'CVE-2026-1001', priority: 'act', exploited: true });
    // The text block carries the same answer, for clients that only read text.
    expect(text(result)).toContain('3 CVEs affect this stack (Act now 2, Attend 0, Watch 1, Track 0)');
    expect(got.note).toMatch(/EPSS is a predicted probability/);
    await client.close();
  });

  it('takes the stack as an array, and trims results to the limit while counting them all', async () => {
    stubOsvFetch();
    const client = await connect(era);
    const result = await client.callTool({ name: 'rank_stack', arguments: { stack: STACK.split(','), limit: 1 } });
    const got = result.structuredContent as unknown as Structured;
    expect(got.totalResults).toBe(3);
    expect(got.resultsShown).toBe(1);
    expect(got.results).toHaveLength(1);
    expect(got.fixFirst).toHaveLength(3);
    expect(text(result)).toContain(`Showing the top 1 of 3; the rest are at ${got.links.json}`);
    await client.close();
  });

  it('answers a bad stack with an error the agent can correct from', async () => {
    const client = await connect(era);
    const result = await client.callTool({ name: 'rank_stack', arguments: { stack: 'npm:next,bogus:x' } });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/Unrecognised: bogus:x\..*Full format: https:\/\//s);
    await client.close();
  });

  it('ranks a list of CVEs and lists IDs that aren’t published', async () => {
    const client = await connect(era);
    const result = await client.callTool({ name: 'rank_cves', arguments: { cves: ['cve-2026-1005', 'CVE-2026-1001', 'CVE-2026-9999'] } });
    expect(result.isError).toBeFalsy();
    const got = result.structuredContent as unknown as Structured;
    expect(got.results.map((r) => r.id).sort()).toEqual(['CVE-2026-1001', 'CVE-2026-1005']);
    expect(got.listed?.notFound).toEqual(['CVE-2026-9999']);
    // Agents that read only the text still see what wasn't ranked.
    expect(text(result).split('\n')[0]).toMatch(/^3 CVE IDs sent: 2 CVEs ranked \(.*\)\. Not published CVEs \(reserved or mistyped\): CVE-2026-9999\./);
    await client.close();
  });

  it('answers an empty stack in an agent’s terms, not the feed URL’s', async () => {
    const client = await connect(era);
    const result = await client.callTool({ name: 'rank_stack', arguments: { stack: ' ' } });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/^Invalid stack: it's empty\. Comma-separated stack items/);
    expect(text(result)).not.toContain('s parameter');
    await client.close();
  });

  it('refuses strings that aren’t CVE IDs', async () => {
    const client = await connect(era);
    const result = await client.callTool({ name: 'rank_cves', arguments: { cves: ['CVE-2026-1001', 'log4shell'] } });
    expect(result.isError).toBe(true);
    expect(text(result)).toContain('Not CVE IDs: log4shell');
    await client.close();
  });
});

describe('MCP limits', () => {
  it('gives agents their own bucket, and tells the agent when to retry', async () => {
    stubOsvFetch();
    const limit = vi.fn(async () => ({ success: true }));
    const e = { ...env, FEED_LIMITER: { limit } as unknown as RateLimit };
    const client = await connect('modern', e);
    expect((await client.callTool({ name: 'rank_stack', arguments: { stack: 'pypi:fastapi' } })).isError).toBeFalsy();
    expect(limit.mock.calls).toEqual([[{ key: `mcp:${IP}` }]]);

    // A cached answer is free; a new one is refused with a readable error.
    limit.mockResolvedValue({ success: false });
    expect((await client.callTool({ name: 'rank_stack', arguments: { stack: 'pypi:fastapi' } })).isError).toBeFalsy();
    const refused = await client.callTool({ name: 'rank_stack', arguments: { stack: 'npm:next' } });
    expect(refused.isError).toBe(true);
    expect(text(refused)).toMatch(/Rate limited.*Retry in 60 seconds/);
    await client.close();
  });

  it('refuses a result limit above the maximum', async () => {
    const client = await connect('modern');
    const result = await client.callTool({ name: 'rank_stack', arguments: { stack: 'npm:next', limit: MAX_RESULT_LIMIT + 1 } }).catch((err: Error) => ({ isError: true, content: [{ type: 'text', text: err.message }] }));
    expect(result.isError).toBe(true);
    await client.close();
  });

  it('never logs a stack', async () => {
    stubOsvFetch();
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => {}));
    const client = await connect('modern');
    await client.callTool({ name: 'rank_stack', arguments: { stack: STACK } });
    await client.callTool({ name: 'rank_stack', arguments: { stack: 'npm:next,bogus:secret-host' } });
    await client.close();
    const logged = spies.flatMap((s) => s.mock.calls.flat().map(String)).join('\n');
    expect(logged).not.toMatch(/next@14\.2\.3|ios_xe|secret-host/);
  });

  it('refuses batches the client’s protocol revision doesn’t have, and caps the ones it does', async () => {
    const call = (id: number) => ({ jsonrpc: '2.0', id, method: 'tools/list' });
    const send = (body: unknown, version?: string) =>
      app.request(
        `${env.BASE_URL}/mcp`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'cf-connecting-ip': IP, ...(version ? { 'mcp-protocol-version': version } : {}) },
          body: JSON.stringify(body),
        },
        env,
      );
    const refusal = async (res: Response) => {
      expect(res.status).toBe(400);
      return ((await res.json()) as { error: { code: number; message: string } }).error;
    };

    expect(await refusal(await send([call(1), call(2)], '2025-06-18'))).toEqual({ code: -32600, message: "JSON-RPC batches aren't part of MCP 2025-06-18; send one message per POST" });
    expect((await refusal(await send([call(1)], '2026-07-28'))).message).toMatch(/aren't part of MCP 2026-07-28/);
    expect((await refusal(await send(Array.from({ length: MAX_BATCH_MESSAGES + 1 }, (_, i) => call(i))))).message).toMatch(/at most 10 messages/);

    // A 2025-03-26 client sends no version header, and its batches still reach the server.
    const res = await send([call(1), call(2)]);
    expect(res.status).toBe(200);
    expect(await res.text()).not.toMatch(/batch/i);
  });

  it('serves a call without a warning in the logs', async () => {
    stubOsvFetch();
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const client = await connect('modern');
    await client.callTool({ name: 'rank_stack', arguments: { stack: STACK } });
    await client.close();
    expect(warn).not.toHaveBeenCalled();
  });
});

describe('headline', () => {
  const none = { act: 0, attend: 0, watch: 0, track: 0 };
  const result = { id: 'CVE-2026-1001' } as MatchedVuln;

  it('never lets "0 CVEs" read as safe: it says what the window covers and names the quiet items', () => {
    const line = headline({ stack: 'npm:lodash@4.17.20', days: 30, priorities: none, results: [], watching: ['npm:lodash@4.17.20'] });
    expect(line).toBe(
      '0 CVEs affect this stack (Act now 0, Attend 0, Watch 0, Track 0): new in the last 30 days, plus older ones from the past year that CISA reports exploited or that score high on EPSS, LEV or CVSS. Nothing in that window for npm:lodash@4.17.20 ("watching"): older CVEs can still affect them, so don\'t report them as safe.',
    );
  });

  it('names five quiet items and counts the rest', () => {
    const watching = Array.from({ length: 7 }, (_, i) => `npm:pkg-${i}`);
    const line = headline({ stack: watching.join(','), days: 90, priorities: none, results: [], watching });
    expect(line).toContain('Nothing in that window for npm:pkg-0, npm:pkg-1, npm:pkg-2, npm:pkg-3, npm:pkg-4 and 2 more ("watching")');
    expect(line).toContain('new in the last 90 days');
  });

  it('counts a CVE list as sent and ranked, naming rejected and unpublished IDs', () => {
    const line = headline({
      stack: 'cve:2021-44228,cve:2099-99999,cve:2021-45046,cve:2017-0001',
      days: 30,
      priorities: { ...none, act: 1 },
      results: [result],
      watching: [],
      listed: { rejected: [{ id: 'CVE-2021-45046', replacedBy: ['CVE-2021-44228'] }, { id: 'CVE-2017-0001', replacedBy: [] }], notFound: ['CVE-2099-99999'] },
    });
    expect(line).toBe(
      '4 CVE IDs sent: 1 CVE ranked (Act now 1, Attend 0, Watch 0, Track 0). Rejected: CVE-2021-45046 (replaced by CVE-2021-44228, ranked instead), CVE-2017-0001 (no replacement). Not published CVEs (reserved or mistyped): CVE-2099-99999.',
    );
  });

  it('says listed CVEs in a mixed stack count whatever their age', () => {
    const line = headline({ stack: 'npm:next@14.2.3,cve:2021-44228', days: 30, priorities: { ...none, act: 1 }, results: [result], watching: [] });
    expect(line).toMatch(/^1 CVE affects this stack .*, plus the listed CVEs whatever their age\.$/);
  });
});

describe('batchRefusal', () => {
  const call = { jsonrpc: '2.0', id: 1, method: 'tools/call' };

  it('lets single messages through under every revision', () => {
    for (const version of [null, '2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28']) expect(batchRefusal(call, version)).toBeNull();
    expect(batchRefusal(null, null)).toBeNull();
  });

  it('allows small batches from 2025-03-26 clients only, never with initialize', () => {
    expect(batchRefusal([call, call], null)).toBeNull();
    expect(batchRefusal([call, call], '2025-03-26')).toBeNull();
    expect(batchRefusal([call], '2025-11-25')).toMatch(/aren't part of MCP 2025-11-25/);
    expect(batchRefusal(Array<unknown>(MAX_BATCH_MESSAGES + 1).fill(call), null)).toMatch(/at most/);
    expect(batchRefusal([{ ...call, method: 'initialize' }], null)).toMatch(/initialize/);
    expect(batchRefusal([null, 3], null)).toBeNull();
  });
});

describe('cveStack', () => {
  it('normalises IDs into a stack Vulnder can parse', () => {
    const built = cveStack([' cve-2021-44228', '2014-0160', 'CVE-2021-44228']);
    expect(built).toEqual({ s: 'cve:2014-0160,cve:2021-44228' });
  });

  it('compresses a long list so it fits the stack limit', () => {
    const ids = Array.from({ length: 2000 }, (_, i) => `CVE-2025-${String(10000 + i * 7)}`);
    const built = cveStack(ids);
    if (!('s' in built)) throw new Error('expected a stack');
    expect(built.s.startsWith('~')).toBe(true);
    expect(parseStack(built.s)).toHaveLength(2000);
  });

  it('names what isn’t a CVE ID, cut short', () => {
    expect(cveStack(['CVE-2021-44228', 'x'.repeat(100)])).toEqual({ invalid: ['x'.repeat(40)] });
  });
});
