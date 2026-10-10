import type { Candidate } from '../src/resolve/types';

export interface AppConfig {
  displayName: string;
  baseUrl: string;
  turnstileSiteKey: string;
}

export interface Chip {
  input: string;
  status: 'resolved' | 'unrecognised';
  /** Exact items, or every close match for a vague name. Close items start with '?'; for an enterprise stack, each ends with ';team'. */
  items: { item: string; label: string; close: boolean; known: boolean; team?: string }[];
}

export interface ResolveResponse {
  source: 'manifest' | 'model';
  format?: string;
  chips: Chip[];
  droppedTransitive: number;
  /** What kind of stack this looks like; only used to order close matches. */
  profile: {
    scale: { value: 'enterprise' | 'smb' | 'home' | null; confidence: number };
    hosting: { value: 'cloud' | 'on_prem' | null; confidence: number };
  };
}

export interface Result {
  id: string;
  title: string | null;
  summary: string | null;
  publishedAt: string | null;
  tier: 'exploited' | 'likely' | 'backlog';
  evidence: {
    kevAddedAt: string | null;
    kevDueDate: string | null;
    knownRansomware: boolean;
    epss: number | null;
    epssPercentile: number | null;
    epssDate: string | null;
    /** NIST LEV: lower-bound chance it has already been exploited. */
    lev: number | null;
  };
  confidence: 'version_confirmed' | 'product_match';
  match: 'exact' | 'close';
  matched: string[];
  fixedVersions: string[];
  cvss: { score: number; vector: string | null } | null;
  links: { advisory: string | null; patch: string | null };
  priority: Priority;
  /** 0–100: orders results within a priority. */
  score: number;
  /** Why it got this priority, most important first. */
  reasons: string[];
  /** Its family (similar CVEs in the same product), when this feed has other members or one is exploited. */
  family: string | null;
  /** Other results in this feed from the same family. */
  related: string[];
  why: {
    /** The rule that decided the band; null for Track. */
    decisive: Reason | null;
    others: Reason[];
    /** Signals the band couldn't use. */
    missing: string[];
  };
  /** Suggested time to fix or mitigate, in hours (guidance); null for Track. */
  respondWithinHours: number | null;
  /** For urgent CVEs with no fixed version known: what to do meanwhile. */
  mitigation: { action: string | null; advisory: string | null } | null;
  /** Older than the chosen window, shown because it's exploited, likely to be, or CVSS 9.9+ in the last year. */
  beforeWindow?: boolean;
}

export interface Reason {
  text: string;
  kind: 'evidence' | 'prediction' | 'severity' | 'context';
}

export type Priority = 'act' | 'attend' | 'watch' | 'track';

export interface FixItem {
  /** Stack item; a leading '?' marks a close match. */
  item: string;
  score: number;
  counts: Record<Priority, number>;
  vulns: string[];
  fixable: number;
  /** Set when it's out of support, losing it soon, or kept going by paid extended support. */
  support?: SupportState;
}

export type SupportState = 'eol' | 'ending' | 'covered';

/** A stack item's vendor support finding (src/match/support.ts). */
export interface SupportNotice {
  state: SupportState;
  /** "Windows Server 2012 R2". */
  name: string;
  /** When support ended or ends (YYYY-MM-DD); null when no date is known. */
  date: string | null;
  /** When paid extended support it could have ends; null when there is none or the user has it. */
  esuUntil: string | null;
  /** The dates counted the user's ESU. */
  esu: boolean;
  edge: boolean;
  source: 'endoflife' | 'cve';
  cve: string | null;
  /** The stack items it's about. */
  items: string[];
}

export interface Change {
  vulnId: string;
  type: 'published' | 'kev_added' | 'epss_crossed' | 'fix_released';
  occurredAt: string;
  detail: Record<string, unknown>;
  title: string | null;
  tier?: Result['tier'];
}

export interface Feed {
  stack: string;
  days: number;
  generatedAt: string;
  links: { page: string; json: string; atom: string; badge: string };
  versionCheckUnavailable: boolean;
  summary: Record<Result['tier'], number>;
  priorities: Record<Priority, number>;
  /** Matched stack items in the order to fix them. */
  fixFirst: FixItem[];
  /** Out of support, losing it soon, or on paid extended support; absent from feeds cached before it existed. */
  support?: SupportNotice[];
  changes: Change[];
  results: Result[];
  watching: string[];
}

export interface Health {
  sources: Record<string, { health: 'ok' | 'stale' | 'error' | 'never'; lastSuccessAt: string | null }>;
}

/** This browser's allowance of different stacks an hour (src/lib/pass.ts). */
export interface PassStatus {
  active: boolean;
  used: number;
  limit: number;
  resetsAt: string | null;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly fallback?: string,
    readonly reason?: string,
  ) {
    super(message);
  }
}

async function json<T>(res: Response): Promise<T> {
  const body = (await res.json().catch(() => ({}))) as { error?: string; fallback?: string; reason?: string };
  if (!res.ok) throw new ApiError(body.error ?? `request failed (${res.status})`, res.status, body.fallback, body.reason);
  return body as T;
}

/**
 * How long the browser waits before saying a request is stuck, rather than
 * loading forever: about twice a slow normal answer. Reading a description
 * (4-9 s uncached) waits longest, and the server gives up on its own model
 * calls within it (3 + 12 + 3 s), so its fallbacks answer first. A feed is
 * cached or takes a few seconds; OSV gives up after 5.
 */
export const RESOLVE_TIMEOUT_MS = 20_000;
export const FEED_TIMEOUT_MS = 15_000;
export const SMALL_TIMEOUT_MS = 10_000;

/** fetch with a deadline. A timeout or a dropped connection becomes an ApiError that says which. */
export async function request(url: string, init: RequestInit, timeoutMs: number, fetchImpl: typeof fetch = (...a) => fetch(...a)): Promise<Response> {
  try {
    return await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
  } catch (err) {
    if ((err as { name?: unknown } | null)?.name === 'TimeoutError') {
      throw new ApiError('Vulnder took too long to answer. Try again in a moment.', 0, undefined, 'timeout');
    }
    throw new ApiError("Couldn't reach Vulnder. Check your connection and try again.", 0, undefined, 'network');
  }
}

export const getPass = () => request('/api/pass', {}, SMALL_TIMEOUT_MS).then((r) => json<PassStatus>(r));

export const getConfig = () => request('/api/config', {}, SMALL_TIMEOUT_MS).then((r) => json<AppConfig>(r));
export const getHealth = () => request('/api/health', {}, SMALL_TIMEOUT_MS).then((r) => json<Health>(r));
export const getFeed = (s: string, days: number) =>
  request(`/api/feed?s=${encodeURIComponent(s)}${days === 30 ? '' : `&days=${days}`}`, {}, FEED_TIMEOUT_MS).then((r) => json<Feed>(r));

export function resolve(body: { text: string } | { candidates: Candidate[] }, turnstileToken: string): Promise<ResolveResponse> {
  return request(
    '/api/resolve',
    { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...body, turnstileToken }) },
    RESOLVE_TIMEOUT_MS,
  ).then((r) => json<ResolveResponse>(r));
}
