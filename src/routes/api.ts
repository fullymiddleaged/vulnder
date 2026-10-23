import { Hono, type Context } from 'hono';
import { z } from 'zod';
import { D1BindingStore } from '../ingest/d1-store';
import { BodyTooLarge, readCapped } from '../lib/body';
import { clientKey } from '../lib/client';
import { takeDailyQuota } from '../lib/quota';
import type { Listed } from '../match/listed';
import type { ChangeEvent, MatchedVuln } from '../match/match';
import type { FixItem, Priority } from '../match/priority';
import { MAX_PRODUCT_LOOKUPS, resolveCandidates, TooManyProducts, type Chip, type ResolveResult } from '../resolve/catalog';
import { fromInventory } from '../resolve/inventory';
import type { Candidate } from '../resolve/types';
import { MAX_CVE_ITEMS, MAX_ITEMS, MAX_PARAM_CHARS, PREFIXES, parseStack, serializeStack, StackFormatError, type StackItem } from '../stack/format';
import type { AppEnv } from '../types';
import { feedResponse, MAX_DAYS, stackRequest } from './feeds';
import { cveStack } from './mcp';

/**
 * The machine API, for scripts and SIEM runners (an Azure Function, a Logic
 * App) that can't pass Turnstile or build compressed `s` values:
 *
 * - POST /api/v1/stack: product and package names, versions and CVE IDs in,
 *   a stack out. Catalog matching only, never a model, so no free text.
 * - POST /api/v1/rank: a stack and/or CVE IDs in, one flat row per CVE out,
 *   shaped for a log table, ranked exactly as /api/feed ranks.
 *
 * Both take the stack in the body, never a URL, and log neither. Limits are
 * per IP under their own key prefix, apart from the site's and agents'.
 * The response shape is a public contract: `schema` changes only when a
 * field is removed or changes meaning; new fields can appear at any time.
 */

export const API_LIMIT_PREFIX = 'api:';
export const API_SCHEMA = 1;
/** 5,000 products as JSON is about 500 KB; 2,000 CVE IDs about 36 KB. */
const MAX_BODY_BYTES = 1_000_000;
/** Stack lookups a client may make a day: a runner needs one or two, so this only stops a script hammering the catalog. */
export const STACK_DAILY_PER_CLIENT = 200;
const STACK_DAILY_TOTAL = 50_000;
const MAX_INPUTS = 5000;
/** About what fits the body once a runner keeps only the four fields read (around 100 bytes an entry). */
const MAX_INVENTORY = 10_000;

const Product = z.object({
  name: z.string().trim().min(1).max(100),
  vendor: z.string().trim().max(100).nullable().optional(),
  version: z.string().trim().max(64).nullable().optional(),
});

const Package = z.object({
  ecosystem: z.enum(Object.keys(PREFIXES) as [string, ...string[]]),
  name: z.string().trim().min(1).max(214),
  version: z.string().trim().max(64).nullable().optional(),
});

/**
 * One of Microsoft Graph's `detectedApps`, as Graph returns it: other fields
 * (id, sizeInByte, platform) are allowed and ignored, and names are cleaned
 * rather than refused, so a runner can pass Graph's `value` straight on.
 */
const InventoryEntry = z.object({
  displayName: z.string().max(1000),
  version: z.string().max(200).nullable().optional(),
  publisher: z.string().max(1000).nullable().optional(),
  deviceCount: z.number().nullable().optional(),
});

const Cves = z.array(z.string().max(40)).max(MAX_CVE_ITEMS);

const StackBody = z
  .object({
    products: z.array(Product).max(MAX_INPUTS).optional(),
    packages: z.array(Package).max(MAX_INPUTS).optional(),
    inventory: z.array(InventoryEntry).max(MAX_INVENTORY).optional(),
    cves: Cves.optional(),
  })
  .strict()
  .refine((b) => (b.products?.length ?? 0) + (b.packages?.length ?? 0) + (b.inventory?.length ?? 0) + (b.cves?.length ?? 0) > 0, {
    message: 'send products, packages, inventory or cves',
  });

const RankBody = z
  .object({
    stack: z.string().max(20_000).optional(),
    cves: Cves.optional(),
    days: z.number().int().min(1).max(MAX_DAYS).optional(),
  })
  .strict()
  .refine((b) => !!b.stack?.trim() || (b.cves?.length ?? 0) > 0, { message: 'send a stack, cves or both' });

/** The body as JSON checked against a schema, or the response refusing it. */
async function readBody<T extends z.ZodType>(c: Context<AppEnv>, schema: T): Promise<z.infer<T> | Response> {
  let raw: string;
  try {
    raw = await readCapped(c.req.raw, MAX_BODY_BYTES);
  } catch (err) {
    if (err instanceof BodyTooLarge) return c.json({ error: 'request too large' }, 413);
    throw err;
  }
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return c.json({ error: 'invalid JSON' }, 400);
  }
  const parsed = schema.safeParse(json);
  if (!parsed.success) return c.json({ error: 'invalid request', details: parsed.error.issues.map((i) => `${i.path.join('.') || 'body'}: ${i.message}`) }, 400);
  return parsed.data;
}

/** CVE IDs as stack items, or the response naming the ones that aren't IDs. */
function cveItems(c: Context<AppEnv>, ids: string[] | undefined): StackItem[] | Response {
  if (!ids?.length) return [];
  const built = cveStack(ids);
  if ('invalid' in built) return c.json({ error: `not CVE IDs: ${built.invalid.slice(0, 10).join(', ')}; use the form CVE-2021-44228` }, 400);
  return parseStack(built.s);
}

export function toCandidates(body: { products?: z.infer<typeof Product>[]; packages?: z.infer<typeof Package>[] }): Candidate[] {
  return [
    ...(body.packages ?? []).map((p): Candidate => ({ kind: 'package', ecosystem: PREFIXES[p.ecosystem]!, name: p.name, version: p.version || null, direct: true })),
    ...(body.products ?? []).map((p): Candidate => ({ kind: 'product', name: p.name, vendor: p.vendor || null, version: p.version || null, direct: true })),
  ];
}

/**
 * Chips in order until their items would pass the stack's limit; the rest are
 * returned as over it. A close match can expand to several items, so this
 * counts items, and an item two chips share counts once.
 */
export function fitItems(chips: Chip[], limit: number): { kept: Chip[]; over: Chip[] } {
  const seen = new Set<string>();
  const kept: Chip[] = [];
  const over: Chip[] = [];
  for (const chip of chips) {
    const fresh = new Set(chip.items.map((i) => i.item.replace(/^\?/, '')).filter((i) => !seen.has(i)));
    if (seen.size + fresh.size > limit) {
      over.push(chip);
      continue;
    }
    for (const i of fresh) seen.add(i);
    kept.push(chip);
  }
  return { kept, over };
}

/** What a chip resolved to, without the page's display fields. */
function resolution(chip: Chip) {
  return { input: chip.input, items: chip.items.map((i) => ({ item: i.item, label: i.label, close: i.close, known: i.known })) };
}

interface Feed {
  stack: string;
  days: number;
  generatedAt: string;
  dataVersion: number;
  links: Record<string, string>;
  versionCheckUnavailable: boolean;
  priorities: Record<Priority, number>;
  fixFirst: FixItem[];
  support: unknown[];
  targeted: unknown[];
  changes: (ChangeEvent & { title: string | null })[];
  results: MatchedVuln[];
  watching: string[];
  listed?: Listed;
}

/** One CVE as one flat row: scalars and string arrays only, so it maps onto a log table's columns. */
export function toRow(r: MatchedVuln) {
  return {
    cve: r.id,
    title: r.title,
    priority: r.priority,
    score: r.score,
    respondWithinHours: r.respondWithinHours,
    reasons: r.reasons,
    exploited: r.tier === 'exploited',
    kevAddedAt: r.evidence.kevAddedAt,
    kevDueDate: r.evidence.kevDueDate,
    knownRansomware: r.evidence.knownRansomware,
    ssvcExploitation: r.ssvc?.exploitation ?? null,
    epss: r.evidence.epss,
    epssPercentile: r.evidence.epssPercentile,
    cvss: r.cvss?.score ?? null,
    publishedAt: r.publishedAt,
    beforeWindow: r.beforeWindow,
    matched: r.matched,
    match: r.match,
    confidence: r.confidence,
    fixedVersions: r.fixedVersions,
    mitigation: r.mitigation?.action ?? null,
    advisory: r.links.advisory,
    patch: r.links.patch,
    exploitRef: r.links.exploit,
  };
}

/** The feed reshaped for a runner: rows to store, and changes with an ID to deduplicate on. */
export function toRank(feed: Feed) {
  const byId = new Map(feed.results.map((r) => [r.id, r]));
  return {
    schema: API_SCHEMA,
    stack: feed.stack,
    days: feed.days,
    generatedAt: feed.generatedAt,
    dataVersion: feed.dataVersion,
    versionCheckUnavailable: feed.versionCheckUnavailable,
    priorities: feed.priorities,
    rows: feed.results.map(toRow),
    changes: feed.changes.map((e) => ({
      id: `${e.vulnId}/${e.type}/${e.occurredAt}`,
      cve: e.vulnId,
      type: e.type,
      occurredAt: e.occurredAt,
      title: e.title,
      priority: byId.get(e.vulnId)?.priority ?? null,
    })),
    fixFirst: feed.fixFirst,
    support: feed.support,
    targeted: feed.targeted,
    watching: feed.watching,
    ...(feed.listed && { listed: feed.listed }),
    links: feed.links,
  };
}

const noStore = { 'Cache-Control': 'no-store' };

export const api = new Hono<AppEnv>()
  .post('/stack', async (c) => {
    const client = clientKey(c.req.header('cf-connecting-ip') ?? null);
    if (c.env.RESOLVE_LIMITER) {
      const { success } = await c.env.RESOLVE_LIMITER.limit({ key: `${API_LIMIT_PREFIX}${client}` });
      if (!success) return c.json({ error: 'too many requests; try again in a minute' }, 429, { 'Retry-After': '60' });
    }
    const body = await readBody(c, StackBody);
    if (body instanceof Response) return body;
    const cves = cveItems(c, body.cves);
    if (cves instanceof Response) return cves;

    const named = toCandidates(body);
    const productsNamed = named.filter((n) => n.kind === 'product').length;
    // An inventory fills whatever product lookups the named products leave.
    const inventory = body.inventory ? fromInventory(body.inventory, Math.max(0, MAX_PRODUCT_LOOKUPS - productsNamed)) : null;
    const candidates = [...named, ...(inventory?.candidates ?? [])];
    let result: ResolveResult = { chips: [], droppedTransitive: 0 };
    if (candidates.length > 0) {
      const store = new D1BindingStore(c.env.DB);
      const quota = await takeDailyQuota(store, 'api-stack', client, { perClient: STACK_DAILY_PER_CLIENT, total: STACK_DAILY_TOTAL }, new Date());
      if (quota !== 'ok') return c.json({ error: "today's limit for stack lookups is used up; reuse the stack from an earlier lookup" }, 429, { 'Retry-After': '3600' });
      try {
        result = await resolveCandidates(store, candidates);
      } catch (err) {
        if (err instanceof TooManyProducts) return c.json({ error: `${err.message}; a stack holds at most ${MAX_ITEMS} items` }, 413);
        throw err;
      }
    }
    const unrecognised = result.chips.filter((ch) => ch.status === 'unrecognised').map((ch) => ch.input);
    const { kept, over } = fitItems(result.chips.filter((ch) => ch.status === 'resolved'), MAX_ITEMS);
    const notChecked = [...over.map((ch) => ch.input), ...(inventory?.notChecked ?? [])];
    const items = kept.flatMap((ch) => ch.items.map((i) => i.item));
    let components: StackItem[] = [];
    try {
      if (items.length > 0) components = parseStack(items.join(','));
    } catch (err) {
      // fitItems keeps to the limit, so only a resolver bug lands here.
      if (err instanceof StackFormatError) return c.json({ error: err.message, unrecognised }, 413, noStore);
      throw err;
    }
    if (components.length + cves.length === 0) return c.json({ error: 'nothing recognised', unrecognised, notChecked }, 422, noStore);
    const stack = serializeStack([...components, ...cves]);
    if (stack.length > MAX_PARAM_CHARS) return c.json({ error: 'that stack is too long to rank; send fewer products or CVEs', unrecognised }, 413, noStore);
    return c.json(
      {
        schema: API_SCHEMA,
        stack,
        resolved: kept.map(resolution),
        unrecognised,
        notChecked,
        ...(inventory && { inventory: { entries: body.inventory!.length, products: inventory.candidates.length + inventory.notChecked.length, ignored: inventory.ignored } }),
      },
      200,
      noStore,
    );
  })
  .post('/rank', async (c) => {
    const body = await readBody(c, RankBody);
    if (body instanceof Response) return body;
    const cves = cveItems(c, body.cves);
    if (cves instanceof Response) return cves;
    let items: StackItem[] = cves;
    if (body.stack?.trim()) {
      try {
        items = [...parseStack(body.stack), ...cves];
      } catch (err) {
        if (err instanceof StackFormatError) return c.json({ error: err.message, ...(err.invalid && { invalid: err.invalid.slice(0, 10) }) }, 400);
        throw err;
      }
    }
    // Re-parsed together, so the combined stack is held to the stack limits too.
    const req = stackRequest(serializeStack(items), body.days);
    if ('error' in req) return c.json(req, 400);
    const res = await feedResponse(c, req, API_LIMIT_PREFIX);
    // A refusal (429 with Retry-After) goes back as the feed gave it.
    if (!res.ok) return res;
    return c.json(toRank((await res.json()) as Feed), 200, noStore);
  });
