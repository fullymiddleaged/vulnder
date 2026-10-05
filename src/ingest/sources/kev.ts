import { z } from 'zod';
import { USER_AGENT } from '../../config';
import { CVE_ID, normalizeKey } from '../../lib/normalize';
import { toIso } from '../../lib/time';
import type { FetchResult, Source, SourceContext, VulnPatch } from '../types';
import { productLabel } from './cve-record';

/**
 * CISA Known Exploited Vulnerabilities, fetched whole with a conditional GET
 * (ETag / Last-Modified) so unchanged files cost one request and no writes.
 */

export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export interface KevCursor {
  etag: string | null;
  lastModified: string | null;
}

const KevEntry = z.object({
  cveID: z.string(),
  vendorProject: z.string().optional(),
  product: z.string().optional(),
  vulnerabilityName: z.string().optional(),
  dateAdded: z.string(),
  shortDescription: z.string().optional(),
  requiredAction: z.string().optional(),
  dueDate: z.string().optional(),
  knownRansomwareCampaignUse: z.string().optional(),
  cwes: z.array(z.string()).optional(),
});

const KevFeed = z.object({
  catalogVersion: z.string().optional(),
  dateReleased: z.string().optional(),
  vulnerabilities: z.array(z.unknown()),
});

export const kevSource: Source<KevCursor> = {
  name: 'kev',

  initialCursor(): KevCursor {
    return { etag: null, lastModified: null };
  },

  async fetchChanges(cursor: KevCursor, ctx: SourceContext): Promise<FetchResult<KevCursor>> {
    const headers: Record<string, string> = { 'User-Agent': USER_AGENT };
    if (cursor.etag) headers['If-None-Match'] = cursor.etag;
    if (cursor.lastModified) headers['If-Modified-Since'] = cursor.lastModified;
    const res = await ctx.fetch(KEV_URL, { headers });
    if (res.status === 304) return { records: [], nextCursor: cursor, done: true };
    if (!res.ok) throw new Error(`KEV: HTTP ${res.status}`);

    const feed = KevFeed.parse(await res.json());
    const records: VulnPatch[] = [];
    for (const raw of feed.vulnerabilities) {
      const patch = parseKevEntry(raw);
      if (patch) records.push(patch);
    }
    return {
      records,
      nextCursor: { etag: res.headers.get('etag'), lastModified: res.headers.get('last-modified') },
      done: true,
    };
  },
};

export function parseKevEntry(raw: unknown): VulnPatch | null {
  const parsed = KevEntry.safeParse(raw);
  if (!parsed.success) return null;
  const e = parsed.data;
  if (!CVE_ID.test(e.cveID)) return null;
  const addedAt = toIso(e.dateAdded);
  if (!addedAt) return null;

  const vendor = normalizeKey(e.vendorProject);
  const product = normalizeKey(e.product);
  // "Multiple Products" names no product a stack could match.
  const usable = vendor && product && !/^multiple/.test(product);

  return {
    source: 'kev',
    id: e.cveID,
    aliases: [],
    fields: {
      title: e.vulnerabilityName?.trim() || null,
      summary: e.shortDescription?.trim() || null,
      cwe: (e.cwes ?? []).filter((c) => /^CWE-\d+$/.test(c)),
      kevAddedAt: addedAt,
      kevRansomware: e.knownRansomwareCampaignUse === 'Known',
      kevDueDate: e.dueDate ? toIso(e.dueDate) : null,
      kevRequiredAction: e.requiredAction?.trim() || null,
    },
    affected: usable
      ? [
          {
            kind: 'product',
            vendor,
            product,
            label: productLabel(e.vendorProject, e.product),
            ranges: [],
            fixedVersion: null,
          },
        ]
      : [],
  };
}
