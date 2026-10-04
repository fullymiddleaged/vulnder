import { CVE_ID, ecosystemFromGithub, normalizePackageName } from '../../lib/normalize';
import { addDays, toIso } from '../../lib/time';
import type { AffectedInput, FetchResult, Ref, Source, SourceContext, VulnPatch } from '../types';
import { githubGet, nextLink } from './github';

/**
 * GitHub Advisory Database, reviewed advisories, via the global advisories
 * REST API (https://docs.github.com/en/rest/security-advisories/global-advisories).
 *
 * Pages through `modified>=since` sorted by `updated` ascending. The cursor
 * keeps the Link-header `after` token while paging, and `since` moves to the
 * latest `updated_at` seen once a pass completes. If an `after` token is
 * rejected, the next page restarts from `since` (re-reading is harmless).
 */

export interface GhsaCursor {
  since: string;
  /** The full next-page URL from the Link header, while a pass is in progress. */
  next: string | null;
  /** Latest updated_at seen in the current pass. */
  maxSeen: string | null;
}

export const ADVISORIES_URL = 'https://api.github.com/advisories';
const MAX_SUMMARY = 2000;

export function advisoriesUrl(since: string): string {
  // The API rejects timestamps with fractional seconds (HTTP 422).
  const seconds = new Date(since).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const q = new URLSearchParams({
    type: 'reviewed',
    sort: 'updated',
    direction: 'asc',
    per_page: '100',
    modified: `>=${seconds}`,
  });
  return `${ADVISORIES_URL}?${q}`;
}

export const ghsaSource: Source<GhsaCursor> = {
  name: 'ghsa',

  initialCursor(now: Date): GhsaCursor {
    // Without a backfill, start a couple of days back.
    return { since: addDays(now, -2).toISOString(), next: null, maxSeen: null };
  },

  async fetchChanges(cursor: GhsaCursor, ctx: SourceContext): Promise<FetchResult<GhsaCursor>> {
    const url = cursor.next ?? advisoriesUrl(cursor.since);
    const res = await githubGet(ctx, url, 'ghsa');
    if (!res.ok) {
      if (cursor.next && res.status >= 400 && res.status < 500) {
        // Stale pagination token: restart the pass from `since`.
        return { records: [], nextCursor: { ...cursor, next: null }, done: false };
      }
      throw new Error(`GitHub advisories: HTTP ${res.status}`);
    }
    const body = (await res.json()) as unknown;
    if (!Array.isArray(body)) throw new Error('GitHub advisories: expected an array');

    const records: VulnPatch[] = [];
    let maxSeen = cursor.maxSeen;
    for (const adv of body) {
      const patch = parseAdvisory(adv);
      if (patch) records.push(patch);
      const updated = toIso((adv as { updated_at?: unknown }).updated_at);
      if (updated && (!maxSeen || updated > maxSeen)) maxSeen = updated;
    }

    const next = nextLink(res.headers.get('link'));
    if (next) return { records, nextCursor: { since: cursor.since, next, maxSeen }, done: false };
    return { records, nextCursor: { since: maxSeen ?? cursor.since, next: null, maxSeen: null }, done: true };
  },
};

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() !== '' ? v.trim() : null);

export function parseAdvisory(adv: unknown): VulnPatch | null {
  if (!isObj(adv)) return null;
  const ghsaId = str(adv.ghsa_id);
  if (!ghsaId) return null;
  const cveId = str(adv.cve_id);
  const id = cveId && CVE_ID.test(cveId) ? cveId : ghsaId;

  const aliases = new Set<string>([ghsaId]);
  if (Array.isArray(adv.identifiers)) {
    for (const i of adv.identifiers) if (isObj(i) && typeof i.value === 'string') aliases.add(i.value);
  }
  aliases.delete(id);

  if (adv.withdrawn_at) return { source: 'ghsa', id, aliases: [...aliases], fields: {}, withdrawn: true };

  const cvss = pickCvss(adv);
  const refs: Ref[] = [];
  const html = str(adv.html_url);
  if (html) refs.push({ url: html, tags: ['advisory'] });
  if (Array.isArray(adv.references)) {
    for (const r of adv.references) if (typeof r === 'string' && /^https?:\/\//i.test(r)) refs.push({ url: r });
  }

  const affected: AffectedInput[] = [];
  if (Array.isArray(adv.vulnerabilities)) {
    for (const v of adv.vulnerabilities) {
      if (!isObj(v) || !isObj(v.package)) continue;
      const ecosystem = typeof v.package.ecosystem === 'string' ? ecosystemFromGithub(v.package.ecosystem) : null;
      const name = str(v.package.name);
      if (!ecosystem || !name) continue;
      const range = str(v.vulnerable_version_range);
      affected.push({
        kind: 'package',
        ecosystem,
        packageName: normalizePackageName(ecosystem, name),
        label: name,
        ranges: range ? [{ range }] : [],
        fixedVersion: firstPatched(v.first_patched_version),
      });
    }
  }

  const description = str(adv.description);
  return {
    source: 'ghsa',
    id,
    aliases: [...aliases],
    fields: {
      title: str(adv.summary),
      summary: description ? description.slice(0, MAX_SUMMARY) : null,
      publishedAt: toIso(adv.published_at),
      modifiedAt: toIso(adv.updated_at),
      cvssScore: cvss?.score ?? null,
      cvssVector: cvss?.vector ?? null,
      cwe: Array.isArray(adv.cwes)
        ? adv.cwes.map((c) => (isObj(c) ? str(c.cwe_id) : null)).filter((c): c is string => c !== null)
        : [],
      refs,
    },
    affected,
  };
}

function pickCvss(adv: Json): { score: number; vector: string | null } | null {
  const sev = isObj(adv.cvss_severities) ? adv.cvss_severities : {};
  for (const c of [sev.cvss_v4, sev.cvss_v3, adv.cvss]) {
    if (isObj(c) && typeof c.score === 'number' && c.score > 0) return { score: c.score, vector: str(c.vector_string) };
  }
  return null;
}

/** first_patched_version is a string in current responses, an {identifier} object in older ones. */
function firstPatched(v: unknown): string | null {
  if (typeof v === 'string') return str(v);
  if (isObj(v)) return str(v.identifier);
  return null;
}
