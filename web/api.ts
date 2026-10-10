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

export const getPass = () => fetch('/api/pass').then((r) => json<PassStatus>(r));

export const getConfig = () => fetch('/api/config').then((r) => json<AppConfig>(r));
export const getHealth = () => fetch('/api/health').then((r) => json<Health>(r));
export const getFeed = (s: string, days: number) =>
  fetch(`/api/feed?s=${encodeURIComponent(s)}${days === 30 ? '' : `&days=${days}`}`).then((r) => json<Feed>(r));

export function resolve(body: { text: string } | { candidates: Candidate[] }, turnstileToken: string): Promise<ResolveResponse> {
  return fetch('/api/resolve', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ...body, turnstileToken }),
  }).then((r) => json<ResolveResponse>(r));
}
