import { strToU8, zipSync } from 'fflate';
import cve2022_48816 from '../fixtures/cve/records/CVE-2022-48816.json';
import cve2024_34393 from '../fixtures/cve/records/CVE-2024-34393.json';
import cve2025_12828 from '../fixtures/cve/records/CVE-2025-12828.json';
import cve2026_100107 from '../fixtures/cve/records/CVE-2026-100107.json';
import cve2026_100148 from '../fixtures/cve/records/CVE-2026-100148.json';
import cve2026_104886 from '../fixtures/cve/records/CVE-2026-104886.json';
import cve2026_104910 from '../fixtures/cve/records/CVE-2026-104910.json';
import releases from '../fixtures/cve/releases.json';
import epssLatest from '../fixtures/epss/latest.json';
import epssScores from '../fixtures/epss/scores.json';
import ghsaPage from '../fixtures/ghsa/page.json';
import kevFeed from '../fixtures/kev/feed.json';
// endoflife.date's /api/v1/products/full, cut down to the products src/stack/eol.ts maps and one it doesn't (nginx).
import eolFull from '../fixtures/eol/full.json';

export type CveRecordJson = { cveMetadata: { cveId: string; dateUpdated: string; datePublished?: string; state: string } };

export const cveRecords: Record<string, CveRecordJson> = {
  'CVE-2022-48816': cve2022_48816 as CveRecordJson,
  'CVE-2024-34393': cve2024_34393 as CveRecordJson,
  'CVE-2025-12828': cve2025_12828 as CveRecordJson,
  'CVE-2026-100107': cve2026_100107 as CveRecordJson,
  'CVE-2026-100148': cve2026_100148 as CveRecordJson,
  'CVE-2026-104886': cve2026_104886 as CveRecordJson,
  'CVE-2026-104910': cve2026_104910 as CveRecordJson,
};

export { eolFull, epssLatest, epssScores, ghsaPage, kevFeed, releases };

/** A delta zip laid out like cvelistV5's (deltaCves/CVE-*.json), built from recorded records. */
export function deltaZip(records: CveRecordJson[]): Uint8Array {
  const files: Record<string, Uint8Array> = {};
  for (const r of records) files[`deltaCves/${r.cveMetadata.cveId}.json`] = strToU8(JSON.stringify(r));
  return zipSync(files);
}

/** A deep copy with cveMetadata overrides, for shaping test scenarios. */
export function withMeta(record: CveRecordJson, meta: Partial<CveRecordJson['cveMetadata']>): CveRecordJson {
  const copy = structuredClone(record);
  Object.assign(copy.cveMetadata, meta);
  return copy;
}
