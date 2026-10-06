import { Hono } from 'hono';
import { z } from 'zod';
import { D1BindingStore } from '../ingest/d1-store';
import { limitFromVar, takeDailyQuota, type QuotaResult } from '../lib/quota';
import { resolveCandidates } from '../resolve/catalog';
import { extractCandidates, type Extraction, ExtractionUnavailable, keepMentioned, MAX_TEXT_CHARS, normalizeInput, parseModelOutput, sha256Hex } from '../resolve/extract';
import { parseManifest } from '../resolve/manifests';
import { TURNSTILE_ACTION, verifyTurnstile } from '../resolve/turnstile';
import type { Candidate } from '../resolve/types';
import { PREFIXES } from '../stack/format';
import type { AppEnv } from '../types';

/**
 * POST /api/resolve: free text or parsed manifest candidates in, chips out.
 *
 * - Turnstile is the main gate; a generous per-IP rate limit backs it up.
 * - Model calls (parse-cache misses) have daily caps, per client and in total,
 *   so the Workers AI allowance can't be used up by one client or a crowd.
 * - Text that parses as a manifest is handled without the model.
 * - Neither the text nor the stack is stored or logged. The parse cache is
 *   keyed by a hash of the normalised text and holds only the parsed items.
 */

const MAX_BODY_BYTES = 1_000_000;
const MAX_MANIFEST_TEXT = 200_000;
const PARSE_CACHE_SECONDS = 7 * 86_400;
/** About 13 neurons a parse: the total default stays inside the free 10,000 a day. */
const DEFAULT_PARSE_PER_CLIENT = 30;
const DEFAULT_PARSE_TOTAL = 600;
const MANUAL_HINT = 'add items manually or paste a manifest';

const ECOSYSTEMS = Object.values(PREFIXES) as [string, ...string[]];

const CandidateInput = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('package'),
    ecosystem: z.enum(ECOSYSTEMS),
    name: z.string().trim().min(1).max(214),
    version: z.string().trim().max(64).nullable().default(null),
    direct: z.boolean().default(true),
  }),
  z.object({
    kind: z.literal('product'),
    name: z.string().trim().min(1).max(100),
    vendor: z.string().trim().max(100).nullable().default(null),
    version: z.string().trim().max(64).nullable().default(null),
    direct: z.boolean().default(true),
  }),
]);

const Body = z
  .object({
    turnstileToken: z.string().max(2048),
    text: z.string().max(MAX_MANIFEST_TEXT).optional(),
    filename: z.string().max(255).optional(),
    candidates: z.array(CandidateInput).max(5000).optional(),
  })
  .refine((b) => (b.text === undefined) !== (b.candidates === undefined), { message: 'send either text or candidates' });

export const resolve = new Hono<AppEnv>().post('/', async (c) => {
  const length = Number(c.req.header('content-length') ?? 0);
  if (length > MAX_BODY_BYTES) return c.json({ error: 'request too large' }, 413);

  const ip = c.req.header('cf-connecting-ip') ?? null;
  if (c.env.RESOLVE_LIMITER) {
    const { success } = await c.env.RESOLVE_LIMITER.limit({ key: ip ?? 'unknown' });
    if (!success) return c.json({ error: 'too many requests; try again in a minute' }, 429, { 'Retry-After': '60' });
  }

  let body: z.infer<typeof Body>;
  try {
    const parsed = Body.safeParse(await c.req.json());
    if (!parsed.success) return c.json({ error: 'invalid request', details: parsed.error.issues.map((i) => i.message) }, 400);
    body = parsed.data;
  } catch {
    return c.json({ error: 'invalid JSON' }, 400);
  }

  const secret = c.env.TURNSTILE_SECRET_KEY;
  if (!secret) return c.json({ error: 'Turnstile is not configured on this server' }, 503);
  const check = await verifyTurnstile((i, init) => fetch(i, init), secret, body.turnstileToken, ip, {
    hostname: new URL(c.env.BASE_URL).hostname,
    action: TURNSTILE_ACTION,
  });
  if (!check.success) return c.json({ error: 'verification failed; reload the page and try again', codes: check.errors }, 403);

  let candidates: Candidate[];
  // Manifests are classified by rules alone.
  let modelHint: Extraction['profile'] = null;
  let source: 'manifest' | 'model';
  let format: string | undefined;
  if (body.candidates) {
    candidates = body.candidates as Candidate[];
    source = 'manifest';
  } else {
    const text = body.text!;
    const manifest = parseManifest(text, body.filename);
    if (manifest) {
      candidates = manifest.candidates;
      source = 'manifest';
      format = manifest.format;
    } else {
      if (text.length > MAX_TEXT_CHARS) {
        return c.json({ error: `descriptions are limited to ${MAX_TEXT_CHARS} characters; paste a manifest file instead` }, 413);
      }
      if (!text.trim()) return c.json({ error: 'nothing to resolve' }, 400);
      source = 'model';
      const quota = () =>
        takeDailyQuota(
          new D1BindingStore(c.env.DB),
          'parse',
          ip,
          { perClient: limitFromVar(c.env.PARSE_DAILY_PER_CLIENT, DEFAULT_PARSE_PER_CLIENT), total: limitFromVar(c.env.PARSE_DAILY_TOTAL, DEFAULT_PARSE_TOTAL) },
          new Date(),
        );
      try {
        ({ candidates, profile: modelHint } = await cachedExtraction(c.env, text, quota));
      } catch (err) {
        if (err instanceof QuotaExceeded && err.result === 'client-limit') {
          return c.json({ error: `you've reached today's limit for free-text parsing; ${MANUAL_HINT}`, fallback: 'manual' }, 429);
        }
        if (err instanceof ExtractionUnavailable || err instanceof QuotaExceeded) {
          return c.json({ error: `free-text parsing is unavailable right now; ${MANUAL_HINT}`, fallback: 'manual' }, 503);
        }
        throw err;
      }
    }
  }

  const result = await resolveCandidates(new D1BindingStore(c.env.DB), candidates, { modelHint });
  return c.json({ source, format, ...result }, 200, { 'Cache-Control': 'no-store' });
});

class QuotaExceeded extends Error {
  constructor(readonly result: Exclude<QuotaResult, 'ok'>) {
    super(result);
    this.name = 'QuotaExceeded';
  }
}

/** A cached parse, or a model call once the daily quota allows it. */
async function cachedExtraction(env: Env, text: string, quota: () => Promise<QuotaResult>): Promise<Extraction> {
  const key = new Request(`https://parse-cache.vulnder.invalid/v1/${encodeURIComponent(env.AI_MODEL)}/${await sha256Hex(normalizeInput(text))}`);
  const cache = await caches.open('vulnder-parse').catch(() => null);
  const hit = cache ? await cache.match(key) : undefined;
  // Older cache entries may predate the grounding check, so apply it on hits too.
  if (hit) return keepMentioned(parseModelOutput({ response: await hit.json() }), text);

  const allowed = await quota();
  if (allowed !== 'ok') throw new QuotaExceeded(allowed);
  const extraction = await extractCandidates(env.AI, env.AI_MODEL, text);
  if (cache) {
    const items = extraction.candidates.map((c) =>
      c.kind === 'package'
        ? { name: c.name, version: c.version, type: 'package', ecosystem: c.ecosystem, vendor: null }
        : { name: c.name, version: c.version, type: 'product', ecosystem: null, vendor: c.vendor },
    );
    await cache.put(key, Response.json({ items, profile: extraction.profile }, { headers: { 'Cache-Control': `max-age=${PARSE_CACHE_SECONDS}` } }));
  }
  return extraction;
}
