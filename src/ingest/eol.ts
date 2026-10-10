import { z } from 'zod';
import { USER_AGENT } from '../config';
import { normalizeKey } from '../lib/normalize';
import { EOL_SLUGS } from '../stack/eol';
import type { EolRelease } from '../match/support';
import { chunkByJsonSize, stmt, type Statement } from './store';
import type { SourceContext } from './types';

/**
 * Vendor support dates from endoflife.date (MIT-licensed data), fetched once a
 * UTC day with a conditional GET: about 480 products in one ~3 MB response, so
 * one subrequest. Only the products src/stack/eol.ts maps are kept, and only
 * rows that changed are written. Parsing it costs tens of milliseconds of CPU:
 * fine for the Paid cron and for Node (GitHub Actions on Free), not for a Free
 * plan cron, which ingest doesn't use.
 */

export const EOL_URL = 'https://endoflife.date/api/v1/products/full';
export const EOL_CURSOR_KEY = 'cursor:eol';
export const EOL_STATUS_KEY = 'status:eol';
/** The UTC day of the last attempt, so a failing upstream is tried once a day, not every run. */
export const EOL_LAST_KEY = 'eol:last';

export interface EolCursor {
  etag: string | null;
}

const date = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);

const Release = z.object({
  name: z.string().min(1).max(64),
  label: z.string().max(200).nullish(),
  isEol: z.boolean().nullish(),
  eolFrom: date.nullish(),
  eoesFrom: date.nullish(),
});

const Product = z.object({
  name: z.string(),
  releases: z.array(z.unknown()),
});

const Full = z.object({ result: z.array(z.unknown()) });

/** One release line as written to eol_releases. */
export type EolRow = EolRelease;

export interface EolFetch {
  status: 'unchanged' | 'fetched';
  rows: EolRow[];
  nextCursor: EolCursor;
  /** Mapped products endoflife.date no longer lists: a lead for src/stack/eol.ts. */
  missing: string[];
}

export async function fetchEol(cursor: EolCursor, ctx: Pick<SourceContext, 'fetch'>): Promise<EolFetch> {
  const headers: Record<string, string> = { 'User-Agent': USER_AGENT };
  if (cursor.etag) headers['If-None-Match'] = cursor.etag;
  const res = await ctx.fetch(EOL_URL, { headers });
  if (res.status === 304) return { status: 'unchanged', rows: [], nextCursor: cursor, missing: [] };
  if (!res.ok) throw new Error(`endoflife.date: HTTP ${res.status}`);
  const { rows, missing } = parseEol(await res.json());
  return { status: 'fetched', rows, nextCursor: { etag: res.headers.get('etag') }, missing };
}

/** The mapped products' releases from a /products/full response; entries that don't parse are skipped. */
export function parseEol(json: unknown): { rows: EolRow[]; missing: string[] } {
  const wanted = new Set(EOL_SLUGS);
  const seen = new Set<string>();
  const rows = new Map<string, EolRow>();
  for (const raw of Full.parse(json).result) {
    const p = Product.safeParse(raw);
    if (!p.success || !wanted.has(p.data.name)) continue;
    seen.add(p.data.name);
    for (const r of p.data.releases) {
      const parsed = Release.safeParse(r);
      const release = parsed.success ? normalizeKey(parsed.data.name) : null;
      if (!parsed.success || !release) continue;
      const e = parsed.data;
      rows.set(`${p.data.name}|${release}`, {
        slug: p.data.name,
        release,
        label: e.label?.trim() || null,
        eol_from: e.eolFrom ?? null,
        is_eol: e.isEol ? 1 : 0,
        eoes_from: e.eoesFrom ?? null,
      });
    }
  }
  return { rows: [...rows.values()], missing: EOL_SLUGS.filter((s) => !seen.has(s)) };
}

export const EOL_STORED_SQL = 'SELECT slug, release, label, eol_from, is_eol, eoes_from FROM eol_releases';

const UPSERT_EOL = `INSERT INTO eol_releases (slug, release, label, eol_from, is_eol, eoes_from, updated_at)
SELECT json_extract(value, '$.slug'), json_extract(value, '$.release'), json_extract(value, '$.label'),
  json_extract(value, '$.eol_from'), json_extract(value, '$.is_eol'), json_extract(value, '$.eoes_from'), ?
FROM json_each(?) WHERE true
ON CONFLICT (slug, release) DO UPDATE SET label = excluded.label, eol_from = excluded.eol_from, is_eol = excluded.is_eol,
  eoes_from = excluded.eoes_from, updated_at = excluded.updated_at`;

const DELETE_EOL = `DELETE FROM eol_releases
WHERE (slug, release) IN (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?))`;

/**
 * The writes that bring the stored releases to `fresh`: changed and new rows
 * upserted, and rows gone upstream deleted. Products missing from `fresh`
 * keep their rows, so a product endoflife.date drops keeps its last dates.
 */
export function eolStatements(stored: EolRow[], fresh: EolRow[], now: Date): { statements: Statement[]; rows: number } {
  const key = (r: EolRow) => `${r.slug}|${r.release}`;
  const same = (a: EolRow, b: EolRow) => a.label === b.label && a.eol_from === b.eol_from && a.is_eol === b.is_eol && a.eoes_from === b.eoes_from;
  const before = new Map(stored.map((r) => [key(r), r]));
  const after = new Map(fresh.map((r) => [key(r), r]));
  const freshSlugs = new Set(fresh.map((r) => r.slug));
  const changed = fresh.filter((r) => {
    const b = before.get(key(r));
    return !b || !same(b, r);
  });
  const gone = stored.filter((r) => freshSlugs.has(r.slug) && !after.has(key(r))).map((r) => [r.slug, r.release]);
  const out: Statement[] = [];
  for (const chunk of chunkByJsonSize(changed)) out.push(stmt(UPSERT_EOL, now.toISOString(), JSON.stringify(chunk)));
  for (const chunk of chunkByJsonSize(gone)) out.push(stmt(DELETE_EOL, JSON.stringify(chunk)));
  return { statements: out, rows: changed.length + gone.length };
}
