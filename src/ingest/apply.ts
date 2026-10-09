import { CVE_ID } from '../lib/normalize';
import {
  detectFixReleased,
  mergePatch,
  type AffectedKeyed,
  type EventInput,
  type MergeOptions,
  type VulnRecord,
} from './merge';
import { allForKeys, chunkByJsonSize, stmt, type Statement, type Store } from './store';
import { parseSeverityLabel, type AffectedInput, type AffectedSource, type Ref, type SourceName, type Ssvc, type VulnPatch } from './types';

export interface ApplyOptions extends MergeOptions {
  now: Date;
  /** Appended to the same batch as the data writes, e.g. the source's new cursor. */
  extraStatements?: Statement[];
}

export interface ApplyStats {
  received: number;
  written: number;
  skipped: number;
  deleted: number;
  events: number;
  /** IDs created by this batch. */
  inserted: string[];
}

interface VulnRow {
  id: string;
  aliases: string;
  title: string | null;
  summary: string | null;
  published_at: string | null;
  modified_at: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  severity_label: string | null;
  cwe: string;
  epss: number | null;
  epss_percentile: number | null;
  epss_date: string | null;
  epss_baseline: number | null;
  lev_log: number;
  kev_added_at: string | null;
  kev_ransomware: number;
  kev_due_date: string | null;
  kev_required_action: string | null;
  ssvc: string | null;
  refs: string;
  source_flags: number;
  provenance: string;
  last_event_at: string | null;
}

interface AffectedRow {
  vuln_id: string;
  source: AffectedSource;
  kind: 'package' | 'product';
  ecosystem: string | null;
  package_name: string | null;
  vendor: string | null;
  product: string | null;
  label: string | null;
  ranges: string;
  fixed_version: string | null;
}

const VULN_COLUMNS = [
  'id',
  'aliases',
  'title',
  'summary',
  'published_at',
  'modified_at',
  'cvss_score',
  'cvss_vector',
  'severity_label',
  'cwe',
  'epss',
  'epss_percentile',
  'epss_date',
  'epss_baseline',
  'lev_log',
  'kev_added_at',
  'kev_ransomware',
  'kev_due_date',
  'kev_required_action',
  'ssvc',
  'refs',
  'source_flags',
  'provenance',
  'last_event_at',
  'updated_at',
] as const;

const UPSERT_VULNS = `INSERT INTO vulns (${VULN_COLUMNS.join(', ')})
SELECT ${VULN_COLUMNS.map((c) => `json_extract(value, '$.${c}')`).join(', ')}
FROM json_each(?) WHERE true
ON CONFLICT (id) DO UPDATE SET ${VULN_COLUMNS.filter((c) => c !== 'id')
  .map((c) => `${c} = excluded.${c}`)
  .join(', ')}`;

/**
 * What a daily EPSS pass changes. D1 bills a written row for every index whose
 * column a statement sets, changed or not, so the full upsert costs about six
 * rows a vuln and this narrow update two.
 */
const EPSS_COLUMNS = ['epss', 'epss_percentile', 'epss_date', 'epss_baseline', 'lev_log'] as const;

export const UPDATE_EPSS = `UPDATE vulns SET ${[...EPSS_COLUMNS, 'updated_at']
  .map((c) => `${c} = json_extract(j.value, '$.${c}')`)
  .join(', ')}
FROM json_each(?) j WHERE vulns.id = json_extract(j.value, '$.id')`;

const AFFECTED_COLUMNS = [
  'vuln_id',
  'source',
  'kind',
  'ecosystem',
  'package_name',
  'vendor',
  'product',
  'label',
  'ranges',
  'fixed_version',
] as const;

const INSERT_AFFECTED = `INSERT INTO affected (${AFFECTED_COLUMNS.join(', ')})
SELECT ${AFFECTED_COLUMNS.map((c) => `json_extract(value, '$.${c}')`).join(', ')}
FROM json_each(?)`;

const DELETE_AFFECTED_FOR_SOURCE = `DELETE FROM affected
WHERE vuln_id IN (SELECT value FROM json_each(?)) AND source = ?`;

const UPSERT_ALIASES = `INSERT INTO aliases (alias, vuln_id)
SELECT json_extract(value, '$.alias'), json_extract(value, '$.vuln_id')
FROM json_each(?) WHERE true
ON CONFLICT (alias) DO UPDATE SET vuln_id = excluded.vuln_id`;

const INSERT_EVENTS = `INSERT OR IGNORE INTO events (vuln_id, type, occurred_at, dedupe_key, detail)
SELECT json_extract(value, '$.vuln_id'), json_extract(value, '$.type'), json_extract(value, '$.occurred_at'),
  json_extract(value, '$.dedupe_key'), json_extract(value, '$.detail')
FROM json_each(?)`;

const INSERT_CATALOG = `INSERT OR IGNORE INTO catalog (kind, key, ecosystem, name, vendor, product, normalized, label)
SELECT json_extract(value, '$.kind'), json_extract(value, '$.key'), json_extract(value, '$.ecosystem'),
  json_extract(value, '$.name'), json_extract(value, '$.vendor'), json_extract(value, '$.product'),
  json_extract(value, '$.normalized'), json_extract(value, '$.label')
FROM json_each(?)`;

/** Statements that remove vulns (and everything hanging off them) by ID. */
export function deleteVulnsStatements(ids: string[]): Statement[] {
  if (ids.length === 0) return [];
  const p = JSON.stringify(ids);
  return [
    stmt('DELETE FROM affected WHERE vuln_id IN (SELECT value FROM json_each(?))', p),
    stmt('DELETE FROM events WHERE vuln_id IN (SELECT value FROM json_each(?))', p),
    stmt('DELETE FROM aliases WHERE vuln_id IN (SELECT value FROM json_each(?))', p),
    stmt('DELETE FROM vulns WHERE id IN (SELECT value FROM json_each(?))', p),
  ];
}

/**
 * Merges a page of patches into D1: resolves aliases to canonical IDs, merges
 * each patch into the stored record, detects events, and writes only what
 * changed, in one batch together with `extraStatements`.
 */
export async function applyPatches(store: Store, patches: VulnPatch[], opts: ApplyOptions): Promise<ApplyStats> {
  const stats: ApplyStats = { received: patches.length, written: 0, skipped: 0, deleted: 0, events: 0, inserted: [] };
  const nowIso = opts.now.toISOString();

  // 1. Resolve every ID and alias to the vuln that already holds it, either as
  //    its primary ID (e.g. a GHSA-only record) or as an alias.
  const aliasMap = new Map<string, string>();
  if (patches.length > 0) {
    const rows = await allForKeys<{ alias: string; vuln_id: string }>(
      store,
      `SELECT id AS alias, id AS vuln_id FROM vulns WHERE id IN (SELECT value FROM json_each(?1))
       UNION ALL
       SELECT alias, vuln_id FROM aliases WHERE alias IN (SELECT value FROM json_each(?1))`,
      patches.flatMap((p) => [p.id, ...p.aliases]),
    );
    for (const r of rows) aliasMap.set(r.alias, r.vuln_id);
  }

  // A GHSA-keyed record gets re-keyed to its CVE once a CVE ID shows up.
  const rekeys = new Map<string, string>();
  const canonical = patches.map((p) => {
    if (CVE_ID.test(p.id)) {
      for (const a of p.aliases) {
        const holder = aliasMap.get(a);
        if (holder && holder !== p.id && !CVE_ID.test(holder)) rekeys.set(holder, p.id);
      }
      return p.id;
    }
    return aliasMap.get(p.id) ?? p.id;
  });

  // 2. Load the stored records and affected rows involved.
  const ids = [...new Set([...canonical, ...rekeys.keys()])];
  const records = new Map<string, VulnRecord>();
  // Rows as stored, untouched by the merge, to tell what a write must cover.
  const loaded = new Map<string, VulnRow>();
  const affected = new Map<string, AffectedRow[]>();
  if (ids.length > 0) {
    for (const row of await allForKeys<VulnRow>(store, 'SELECT * FROM vulns WHERE id IN (SELECT value FROM json_each(?))', ids)) {
      records.set(row.id, rowToRecord(row));
      loaded.set(row.id, row);
    }
    // Affected rows are only compared when a patch replaces them (or a re-key moves them).
    const needAffected = new Set(rekeys.keys());
    patches.forEach((p, i) => {
      if (p.affected !== undefined || p.withdrawn) needAffected.add(canonical[i]!);
    });
    for (const row of await allForKeys<AffectedRow>(
      store,
      `SELECT ${AFFECTED_COLUMNS.join(', ')} FROM affected WHERE vuln_id IN (SELECT value FROM json_each(?))`,
      [...needAffected].filter((id) => records.has(id)),
    )) {
      const k = `${row.vuln_id}|${row.source}`;
      if (!affected.has(k)) affected.set(k, []);
      affected.get(k)!.push(row);
    }
  }

  const statements: Statement[] = [];
  for (const [from, to] of rekeys) {
    const old = records.get(from);
    if (!old) continue;
    const target = records.get(to);
    if (target) {
      target.aliases = [...new Set([...target.aliases, from, ...old.aliases])].filter((a) => a !== to);
    } else {
      records.set(to, { ...old, id: to, aliases: [...new Set([...old.aliases, from])].filter((a) => a !== to) });
    }
    records.delete(from);
    for (const src of ['cve', 'ghsa', 'kev'] as const) {
      const rows = affected.get(`${from}|${src}`);
      if (rows) {
        affected.set(`${to}|${src}`, [...(affected.get(`${to}|${src}`) ?? []), ...rows.map((r) => ({ ...r, vuln_id: to }))]);
        affected.delete(`${from}|${src}`);
      }
    }
    statements.push(
      stmt('UPDATE affected SET vuln_id = ? WHERE vuln_id = ?', to, from),
      stmt('UPDATE OR IGNORE events SET vuln_id = ? WHERE vuln_id = ?', to, from),
      stmt('DELETE FROM events WHERE vuln_id = ?', from),
      stmt('UPDATE aliases SET vuln_id = ? WHERE vuln_id = ?', to, from),
      stmt('DELETE FROM vulns WHERE id = ?', from),
    );
  }

  // 3. Merge.
  const existedBefore = new Set(records.keys());
  const dirty = new Set<string>(rekeys.size > 0 ? [...rekeys.values()].filter((id) => records.has(id)) : []);
  const deletions: string[] = [];
  const replaceAffected = new Map<string, { id: string; source: AffectedSource; rows: AffectedRow[] }>();
  const events: EventInput[] = [];
  const aliasRows: { alias: string; vuln_id: string }[] = [];
  const catalogRows = new Map<string, Record<string, string | null>>();

  patches.forEach((original, i) => {
    const id = canonical[i]!;
    let patch: VulnPatch = { ...original, id };

    if (patch.withdrawn) {
      if (patch.source === 'cve' || !CVE_ID.test(id)) {
        if (records.has(id)) {
          records.delete(id);
          dirty.delete(id);
          deletions.push(id);
        } else {
          stats.skipped++;
        }
        return;
      }
      // A withdrawn GHSA on a CVE-keyed record only drops the GHSA's package rows.
      patch = { source: 'ghsa', id, aliases: [], fields: {}, affected: [] };
    }

    const existing = records.get(id) ?? null;
    const res = mergePatch(existing, patch, opts);
    if (!res.record) {
      stats.skipped++;
      return;
    }
    const rec = res.record;
    records.set(id, rec);
    if (res.changed) dirty.add(id);
    if (!existing) stats.inserted.push(id);
    events.push(...res.events);

    if (patch.affected !== undefined && patch.source !== 'epss') {
      const source = patch.source;
      const key = `${id}|${source}`;
      const before = affected.get(key) ?? [];
      const after = dedupeAffected(patch.affected.map((a) => toAffectedRow(id, source, a)));
      if (!sameAffected(before, after)) {
        replaceAffected.set(key, { id, source, rows: after });
        affected.set(key, after);
        if (existedBefore.has(id) && before.length > 0) {
          const fixes = detectFixReleased(id, before.map(keyed), after.map(keyed), patch.fields.modifiedAt ?? nowIso);
          if (fixes.length > 0) {
            events.push(...fixes);
            for (const e of fixes) if (!rec.lastEventAt || e.occurredAt > rec.lastEventAt) rec.lastEventAt = e.occurredAt;
            dirty.add(id);
          }
        }
        for (const row of after) {
          const c = catalogEntry(row);
          if (c) catalogRows.set(`${c.kind}|${c.key}`, c);
        }
      }
    }

    // Aliases the stored record already had are in the aliases table; only
    // ones looked up above can point elsewhere.
    const stored = new Set(parseJson<string[]>(loaded.get(id)?.aliases ?? null, []));
    for (const alias of rec.aliases) {
      const holder = aliasMap.get(alias);
      if (holder === undefined && stored.has(alias)) continue;
      if (holder !== id) {
        aliasRows.push({ alias, vuln_id: id });
        aliasMap.set(alias, id);
      }
    }
  });

  // 4. Write.
  statements.push(...deleteVulnsStatements(deletions));
  stats.deleted = deletions.length;

  const vulnRows: ReturnType<typeof recordToRow>[] = [];
  const epssRows: Record<string, unknown>[] = [];
  for (const id of dirty) {
    if (!records.has(id)) continue;
    const row = recordToRow(records.get(id)!, nowIso);
    const was = loaded.get(id);
    if (was && onlyEpssChanged(recordToRow(rowToRecord(was), nowIso), row)) {
      epssRows.push(Object.fromEntries(['id', ...EPSS_COLUMNS, 'updated_at'].map((c) => [c, row[c as keyof typeof row]])));
    } else {
      vulnRows.push(row);
    }
  }
  stats.written = vulnRows.length + epssRows.length;
  for (const chunk of chunkByJsonSize(vulnRows)) statements.push(stmt(UPSERT_VULNS, JSON.stringify(chunk)));
  for (const chunk of chunkByJsonSize(epssRows)) statements.push(stmt(UPDATE_EPSS, JSON.stringify(chunk)));

  const bySource = new Map<AffectedSource, string[]>();
  const newAffected: AffectedRow[] = [];
  for (const { id, source, rows } of replaceAffected.values()) {
    if (!records.has(id)) continue;
    if (!bySource.has(source)) bySource.set(source, []);
    bySource.get(source)!.push(id);
    newAffected.push(...rows);
  }
  for (const [source, sourceIds] of bySource) {
    for (let i = 0; i < sourceIds.length; i += 400) {
      statements.push(stmt(DELETE_AFFECTED_FOR_SOURCE, JSON.stringify(sourceIds.slice(i, i + 400)), source));
    }
  }
  for (const chunk of chunkByJsonSize(newAffected)) statements.push(stmt(INSERT_AFFECTED, JSON.stringify(chunk)));

  for (const chunk of chunkByJsonSize(aliasRows)) statements.push(stmt(UPSERT_ALIASES, JSON.stringify(chunk)));

  const eventRows = events
    .filter((e) => records.has(e.vulnId))
    .map((e) => ({
      vuln_id: e.vulnId,
      type: e.type,
      occurred_at: e.occurredAt,
      dedupe_key: e.dedupeKey,
      detail: JSON.stringify(e.detail),
    }));
  stats.events = eventRows.length;
  for (const chunk of chunkByJsonSize(eventRows)) statements.push(stmt(INSERT_EVENTS, JSON.stringify(chunk)));

  for (const chunk of chunkByJsonSize([...catalogRows.values()])) statements.push(stmt(INSERT_CATALOG, JSON.stringify(chunk)));

  statements.push(...(opts.extraStatements ?? []));
  if (statements.length > 0) await store.batch(statements);
  return stats;
}

function rowToRecord(r: VulnRow): VulnRecord {
  return {
    id: r.id,
    aliases: parseJson<string[]>(r.aliases, []),
    title: r.title,
    summary: r.summary,
    publishedAt: r.published_at,
    modifiedAt: r.modified_at,
    cvssScore: r.cvss_score,
    cvssVector: r.cvss_vector,
    severityLabel: parseSeverityLabel(r.severity_label),
    cwe: parseJson<string[]>(r.cwe, []),
    refs: parseJson<Ref[]>(r.refs, []),
    ssvc: r.ssvc ? parseJson<Ssvc | null>(r.ssvc, null) : null,
    epss: r.epss,
    epssPercentile: r.epss_percentile,
    epssDate: r.epss_date,
    epssBaseline: r.epss_baseline,
    levLog: r.lev_log ?? 0,
    kevAddedAt: r.kev_added_at,
    kevRansomware: r.kev_ransomware === 1,
    kevDueDate: r.kev_due_date,
    kevRequiredAction: r.kev_required_action,
    sourceFlags: r.source_flags,
    provenance: parseJson<Record<string, SourceName>>(r.provenance, {}),
    lastEventAt: r.last_event_at,
  };
}

function recordToRow(rec: VulnRecord, nowIso: string): Record<(typeof VULN_COLUMNS)[number], unknown> {
  return {
    id: rec.id,
    aliases: JSON.stringify(rec.aliases),
    title: rec.title,
    summary: rec.summary,
    published_at: rec.publishedAt,
    modified_at: rec.modifiedAt,
    cvss_score: rec.cvssScore,
    cvss_vector: rec.cvssVector,
    severity_label: rec.severityLabel,
    cwe: JSON.stringify(rec.cwe),
    epss: rec.epss,
    epss_percentile: rec.epssPercentile,
    epss_date: rec.epssDate,
    epss_baseline: rec.epssBaseline,
    lev_log: rec.levLog,
    kev_added_at: rec.kevAddedAt,
    kev_ransomware: rec.kevRansomware ? 1 : 0,
    kev_due_date: rec.kevDueDate,
    kev_required_action: rec.kevRequiredAction,
    ssvc: rec.ssvc ? JSON.stringify(rec.ssvc) : null,
    refs: JSON.stringify(rec.refs),
    source_flags: rec.sourceFlags,
    provenance: JSON.stringify(rec.provenance),
    last_event_at: rec.lastEventAt,
    updated_at: nowIso,
  };
}

/** True when two rows differ only in EPSS columns (and updated_at). */
function onlyEpssChanged(before: ReturnType<typeof recordToRow>, after: ReturnType<typeof recordToRow>): boolean {
  const epss = new Set<string>([...EPSS_COLUMNS, 'updated_at']);
  return VULN_COLUMNS.every((c) => epss.has(c) || before[c] === after[c]);
}

function toAffectedRow(vulnId: string, source: AffectedSource, a: AffectedInput): AffectedRow {
  return {
    vuln_id: vulnId,
    source,
    kind: a.kind,
    ecosystem: a.ecosystem ?? null,
    package_name: a.packageName ?? null,
    vendor: a.vendor ?? null,
    product: a.product ?? null,
    label: a.label ?? null,
    ranges: JSON.stringify(a.ranges),
    fixed_version: a.fixedVersion ?? null,
  };
}

function affectedKey(r: AffectedRow): string {
  return JSON.stringify([r.kind, r.ecosystem, r.package_name, r.vendor, r.product, r.label, r.ranges, r.fixed_version]);
}

function dedupeAffected(rows: AffectedRow[]): AffectedRow[] {
  const seen = new Map<string, AffectedRow>();
  for (const r of rows) seen.set(affectedKey(r), r);
  return [...seen.values()];
}

function sameAffected(a: AffectedRow[], b: AffectedRow[]): boolean {
  if (a.length !== b.length) return false;
  const ka = a.map(affectedKey).sort();
  const kb = b.map(affectedKey).sort();
  return ka.every((k, i) => k === kb[i]);
}

function keyed(r: AffectedRow): AffectedKeyed {
  return {
    kind: r.kind,
    ecosystem: r.ecosystem,
    packageName: r.package_name,
    vendor: r.vendor,
    product: r.product,
    fixedVersion: r.fixed_version,
  };
}

function catalogEntry(r: AffectedRow): Record<string, string | null> | null {
  if (r.kind === 'package' && r.ecosystem && r.package_name) {
    return {
      kind: 'package',
      key: `${r.ecosystem}:${r.package_name}`,
      ecosystem: r.ecosystem,
      name: r.package_name,
      vendor: null,
      product: null,
      normalized: r.package_name.toLowerCase(),
      label: r.label ?? r.package_name,
    };
  }
  if (r.kind === 'product' && r.vendor && r.product) {
    return {
      kind: 'product',
      key: `${r.vendor}/${r.product}`,
      ecosystem: null,
      name: null,
      vendor: r.vendor,
      product: r.product,
      normalized: r.product,
      label: r.label,
    };
  }
  return null;
}

function parseJson<T>(text: string | null, fallback: T): T {
  if (!text) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}
