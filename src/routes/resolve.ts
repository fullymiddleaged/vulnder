import { Hono } from 'hono';
import { z } from 'zod';
import { getCookie, setCookie } from 'hono/cookie';
import { D1BindingStore } from '../ingest/d1-store';
import { BodyTooLarge, readCapped } from '../lib/body';
import { issuePass, lockedStatus, PASS_COOKIE, PASS_TTL_SECONDS, passStatus } from '../lib/pass';
import { passLimited, readLock } from './pass';
import { clientKey } from '../lib/client';
import { limitFromVar, takeDailyQuota, type QuotaResult } from '../lib/quota';
import { resolveCandidates, TooManyProducts, type ResolveResult } from '../resolve/catalog';
import { extractCandidates, ExtractionUnavailable, keepMentioned, MAX_TEXT_CHARS, normalizeInput, parseModelOutput, sha256Hex } from '../resolve/extract';
import { looksLikeInjection } from '../resolve/injection';
import { MAX_MANIFEST_ENTRIES } from '../resolve/limits';
import { blocks, fitTargets, judgeStack, screenText, teamTargets, type Judgement } from '../resolve/jev';
import { parseManifest } from '../resolve/manifests';
import { canRank, isEnterprise, markTeams, NO_PROFILE, orderByFit, parseProfile, type StackProfile } from '../resolve/profile';
import { TURNSTILE_ACTION, verifyTurnstile } from '../resolve/turnstile';
import type { Candidate } from '../resolve/types';
import { isTeam, MAX_ITEMS, PREFIXES, type Team } from '../stack/format';
import type { AppEnv } from '../types';

/**
 * POST /api/resolve: free text or parsed manifest candidates in, chips out.
 *
 * - Turnstile is the main gate; a generous per-IP rate limit backs it up.
 * - Model calls (parse-cache misses) have daily caps, per client and in total,
 *   so the Workers AI allowance can't be used up by one client or a crowd.
 * - Text that parses as a manifest is handled without the model.
 * - Free text aimed at an AI is refused: first by a phrase screen, then by Jev
 *   (jev.ts), which also reads the stack's scale and hosting so close matches
 *   can be ordered by fit. An enterprise stack also gets a team per item:
 *   Jev's answer, else the fixed table's (the person can change it on the
 *   Edit page).
 * - Neither the text nor the stack is stored or logged. The parse cache is
 *   keyed by a hash of the normalised text and holds only the parsed items
 *   and the profile.
 */

const MAX_BODY_BYTES = 1_000_000;
const MAX_MANIFEST_TEXT = 200_000;
const PARSE_CACHE_SECONDS = 7 * 86_400;
/**
 * A parse is about 13 neurons of extraction, so 600 a day stays inside the free
 * 10,000. Jev is billed separately, in AI Gateway credits (about $0.0001 a parse).
 */
const DEFAULT_PARSE_PER_CLIENT = 30;
const DEFAULT_PARSE_TOTAL = 600;
const MANUAL_HINT = 'add items manually or upload a manifest';

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
    candidates: z.array(CandidateInput).max(MAX_MANIFEST_ENTRIES).optional(),
  })
  .refine((b) => (b.text === undefined) !== (b.candidates === undefined), { message: 'send either text or candidates' });

export const resolve = new Hono<AppEnv>().post('/', async (c) => {
  // A declared size over the cap is refused before anything else; readCapped
  // below also stops a body that declares none.
  const length = Number(c.req.header('content-length') ?? 0);
  if (length > MAX_BODY_BYTES) return c.json({ error: 'request too large' }, 413);
  // A browser whose pass is spent couldn't load the result; refuse before Turnstile or D1.
  const now = new Date();
  const locked = readLock(c, now);
  if (locked) return passLimited(c, lockedStatus(locked), now);

  const ip = c.req.header('cf-connecting-ip') ?? null;
  // Limits and daily counts go by IPv6 /64, not the full address (src/lib/client.ts).
  const client = clientKey(ip);
  if (c.env.RESOLVE_LIMITER) {
    const { success } = await c.env.RESOLVE_LIMITER.limit({ key: client });
    if (!success) return c.json({ error: 'too many requests; try again in a minute' }, 429, { 'Retry-After': '60' });
  }

  let raw: string;
  try {
    raw = await readCapped(c.req.raw, MAX_BODY_BYTES);
  } catch (err) {
    if (err instanceof BodyTooLarge) return c.json({ error: 'request too large' }, 413);
    throw err;
  }
  let body: z.infer<typeof Body>;
  try {
    const parsed = Body.safeParse(JSON.parse(raw));
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

  // Passing Turnstile earns a feed pass (src/lib/pass.ts), unless this browser has a live one.
  const passId = getCookie(c, PASS_COOKIE);
  const passStore = new D1BindingStore(c.env.DB);
  if (!passId || !(await passStatus(passStore, passId, new Date()))) {
    setCookie(c, PASS_COOKIE, await issuePass(passStore, new Date()), { path: '/', maxAge: PASS_TTL_SECONDS, httpOnly: true, secure: true, sameSite: 'Strict' });
  }

  let candidates: Candidate[];
  // Only free text gets a profile; manifests keep catalog order.
  let profile = NO_PROFILE;
  let text: string | null = null;
  let source: 'manifest' | 'model';
  let format: string | undefined;
  if (body.candidates) {
    candidates = body.candidates as Candidate[];
    source = 'manifest';
  } else {
    const input = body.text!;
    const manifest = parseManifest(input, body.filename);
    if (manifest) {
      candidates = manifest.candidates;
      source = 'manifest';
      format = manifest.format;
    } else {
      text = input;
      if (text.length > MAX_TEXT_CHARS) {
        return c.json({ error: `descriptions are limited to ${MAX_TEXT_CHARS} characters; upload a manifest file instead` }, 413);
      }
      if (!text.trim()) return c.json({ error: 'nothing to resolve' }, 400);
      if (looksLikeInjection(text)) return c.json(BLOCKED, 422);
      source = 'model';
      const quota = () =>
        takeDailyQuota(
          new D1BindingStore(c.env.DB),
          'parse',
          client,
          { perClient: limitFromVar(c.env.PARSE_DAILY_PER_CLIENT, DEFAULT_PARSE_PER_CLIENT), total: limitFromVar(c.env.PARSE_DAILY_TOTAL, DEFAULT_PARSE_TOTAL) },
          new Date(),
        );
      try {
        ({ candidates, profile } = await cachedParse(c.env, text, quota));
      } catch (err) {
        if (err instanceof InjectionBlocked) return c.json(BLOCKED, 422);
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

  let result: ResolveResult;
  try {
    result = await resolveCandidates(new D1BindingStore(c.env.DB), candidates);
  } catch (err) {
    if (err instanceof TooManyProducts) return c.json({ error: `${err.message}; a stack holds at most ${MAX_ITEMS} items` }, 413);
    throw err;
  }
  let chips = result.chips;
  // Only free text gets judged: manifests aren't sent to Jev. Only enterprise stacks get teams.
  if (text !== null) {
    const enterprise = isEnterprise(profile);
    const fitAsk = canRank(profile) ? fitTargets(chips) : [];
    const teamAsk = enterprise ? teamTargets(chips) : [];
    const { fit, team } =
      fitAsk.length + teamAsk.length > 0 ? await cachedJudgement(c.env, text, profile, fitAsk, teamAsk) : { fit: new Map<string, number>(), team: new Map<string, Team>() };
    chips = orderByFit(chips, fit);
    // The fixed table fills what Jev left out, so teams appear even when Jev doesn't answer.
    if (enterprise) chips = markTeams(chips, team);
  }
  return c.json({ source, format, ...result, chips, profile }, 200, { 'Cache-Control': 'no-store' });
});

const BLOCKED = {
  error: `that reads like instructions for an AI rather than a list of what you run; describe your stack, or ${MANUAL_HINT}`,
  fallback: 'manual',
  reason: 'injection',
} as const;

class QuotaExceeded extends Error {
  constructor(readonly result: Exclude<QuotaResult, 'ok'>) {
    super(result);
    this.name = 'QuotaExceeded';
  }
}

class InjectionBlocked extends Error {
  constructor() {
    super('injection');
    this.name = 'InjectionBlocked';
  }
}

interface Parse {
  candidates: Candidate[];
  profile: StackProfile;
}

const cacheHeaders = { 'Cache-Control': `max-age=${PARSE_CACHE_SECONDS}` };

async function openParseCache(): Promise<Cache | null> {
  return caches.open('vulnder-parse').catch(() => null);
}

/**
 * A cached parse, or, once the daily quota allows: Jev screens the text, then
 * the extraction model lists its components. A refusal is cached too, so
 * repeating the text costs nothing.
 */
async function cachedParse(env: Env, text: string, quota: () => Promise<QuotaResult>): Promise<Parse> {
  const key = new Request(`https://parse-cache.vulnder.invalid/v2/${encodeURIComponent(env.AI_MODEL)}/${await sha256Hex(normalizeInput(text))}`);
  const cache = await openParseCache();
  const hit = cache ? await cache.match(key) : undefined;
  if (hit) {
    const entry = (await hit.json()) as { blocked?: unknown; profile?: unknown };
    if (entry.blocked === true) throw new InjectionBlocked();
    return { ...keepMentioned(parseModelOutput({ response: entry }), text), profile: parseProfile(entry.profile) };
  }

  const allowed = await quota();
  if (allowed !== 'ok') throw new QuotaExceeded(allowed);
  // Fails open: without an answer, the fence and grounding still apply.
  const screen = await screenText(env.AI, text);
  if (blocks(screen)) {
    if (cache) await cache.put(key, Response.json({ blocked: true }, { headers: cacheHeaders }));
    throw new InjectionBlocked();
  }
  const profile = screen?.profile ?? NO_PROFILE;
  const { candidates } = await extractCandidates(env.AI, env.AI_MODEL, text);
  if (cache) {
    const items = candidates.map((c) =>
      c.kind === 'package'
        ? { name: c.name, version: c.version, type: 'package', ecosystem: c.ecosystem, vendor: null }
        : { name: c.name, version: c.version, type: 'product', ecosystem: null, vendor: c.vendor },
    );
    await cache.put(key, Response.json({ items, profile }, { headers: cacheHeaders }));
  }
  return { candidates, profile };
}

/**
 * Jev's fit for each close match and team for each component, cached by
 * text and what was asked. It follows a parse of the same text, so the
 * parse's quota covers it; a repeat costs nothing unless the catalog has
 * changed the matches.
 */
async function cachedJudgement(env: Env, text: string, profile: StackProfile, fitAsk: { item: string; label: string }[], teamAsk: string[]): Promise<Judgement> {
  const asked = await sha256Hex(JSON.stringify([fitAsk.map((t) => t.item), teamAsk]));
  const key = new Request(`https://parse-cache.vulnder.invalid/judge/v2/${await sha256Hex(normalizeInput(text))}/${asked}`);
  const cache = await openParseCache();
  const hit = cache ? await cache.match(key) : undefined;
  if (hit) {
    const stored = (await hit.json()) as { fit?: unknown; team?: unknown } | null;
    return { fit: entries(stored?.fit, (v): v is number => typeof v === 'number'), team: entries(stored?.team, (v): v is Team => typeof v === 'string' && isTeam(v)) };
  }
  const judged = await judgeStack(env.AI, text, profile, fitAsk, teamAsk);
  // Nothing is cached when Jev didn't answer, so the next request asks again.
  if (cache && judged.fit.size + judged.team.size > 0) {
    await cache.put(key, Response.json({ fit: [...judged.fit], team: [...judged.team] }, { headers: cacheHeaders }));
  }
  return judged;
}

/** A cached [key, value] list read back as a map, dropping anything malformed. */
function entries<T>(stored: unknown, valid: (v: unknown) => v is T): Map<string, T> {
  if (!Array.isArray(stored)) return new Map();
  return new Map(stored.filter((e): e is [string, T] => Array.isArray(e) && typeof e[0] === 'string' && valid(e[1])));
}
