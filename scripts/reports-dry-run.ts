/**
 * Reads the trusted sources' feeds as ingest would (src/ingest/reports.ts),
 * writes nothing, and shows what their write-ups would change in local D1:
 * which CVEs they name, and which would move to Act now. Dev machine only.
 *
 *   npm run reports:dry-run
 *
 * Feeds hold their newest posts only (watchTowr's 4 cover about three weeks),
 * so this checks today's volume and the rule's threshold, not history.
 */
import { Budget } from '../src/ingest/budget';
import { refreshReports } from '../src/ingest/reports';
import { REPORT_SOURCES } from '../src/ingest/reporters';
import type { Statement, Store } from '../src/ingest/store';
import { parseSeverityLabel, type Ssvc } from '../src/ingest/types';
import { daysBetween } from '../src/lib/lev';
import type { ExploitRef } from '../src/match/components';
import { reportedSignal, reportsOf } from '../src/match/match';
import { assess, type Signals } from '../src/match/priority';
import { WranglerStore } from './lib/wrangler-store';

const now = new Date();

/** Keeps meta in memory and captures report rows; nothing reaches D1. */
class DryStore implements Store {
  readonly meta = new Map<string, string>();
  readonly rows: { source: string; cve_id: string; url: string; published_at: string; kind: string }[] = [];
  async all<T>(sql: string, params: unknown[] = []): Promise<T[]> {
    if (!sql.includes('FROM meta')) return [];
    const keys = JSON.parse(String(params[0])) as string[];
    return keys.filter((k) => this.meta.has(k)).map((k) => ({ key: k, value: this.meta.get(k)! })) as T[];
  }
  async batch(statements: Statement[]): Promise<void> {
    for (const s of statements) {
      if (s.sql.startsWith('INSERT INTO meta')) this.meta.set(String(s.params[0]), String(s.params[1]));
      else if (s.sql.startsWith('INSERT INTO exploits')) {
        for (const r of JSON.parse(String(s.params[2])) as { cve_id: string; url: string; published_at: string; kind: string }[]) this.rows.push({ source: String(s.params[0]), ...r });
      }
    }
  }
}

const dry = new DryStore();
const budget = new Budget({ maxSubrequests: 1000, deadline: Number.MAX_SAFE_INTEGER });
const ctx = { fetch: budget.wrapFetch(fetch), store: dry, budget, now: () => now, log: console.log, runtime: 'node' as const };
// Pages are capped per run, so read until none are left.
for (let run = 0; run < 10; run++) {
  const r = await refreshReports(ctx);
  if (r.errors.length > 0) console.warn(`errors: ${r.errors.join('; ')}`);
  if (r.pages === 0) break;
  dry.meta.delete('reports:last');
}

const bySource = new Map<string, number>();
for (const r of dry.rows) bySource.set(r.source, (bySource.get(r.source) ?? 0) + 1);
console.log(`\nCVEs named, by source: ${REPORT_SOURCES.map((s) => `${s.name} ${bySource.get(s.id) ?? 0}`).join(', ')}`);

// The same reading of the rows as the feed's (src/match/match.ts): one per source, earliest post, urgent if any was.
const byCve = new Map<string, ExploitRef[]>();
for (const r of dry.rows) byCve.set(r.cve_id, [...(byCve.get(r.cve_id) ?? []), r]);
const reports = new Map([...byCve].map(([id, rows]) => [id, reportsOf(rows)] as const));

type Row = { id: string; published_at: string | null; cvss_score: number | null; cvss_vector: string | null; severity_label: string | null; ssvc: string | null; epss: number | null; kev_added_at: string | null };
const ids = [...reports.keys()];
const db = new WranglerStore({ target: 'local' });
const cols = 'id, published_at, cvss_score, cvss_vector, severity_label, ssvc, epss, kev_added_at';
const found = new Map<string, Row>();
for (const table of ['vulns', 'cve_index']) {
  const missing = ids.filter((id) => !found.has(id));
  if (missing.length === 0) break;
  for (const r of await db.all<Row>(`SELECT ${cols} FROM ${table} WHERE id IN (SELECT value FROM json_each(?))`, [JSON.stringify(missing)])) found.set(r.id, r);
}

const lines: string[] = [];
let lifted = 0;
for (const id of ids.sort()) {
  const v = found.get(id);
  const list = reports.get(id)!;
  if (!v) {
    lines.push(`${id}  not in local D1  ${list.map((r) => `${r.name}${r.urgent ? '!' : ''}`).join(', ')}`);
    continue;
  }
  let ssvc: Ssvc | null;
  try {
    ssvc = v.ssvc ? (JSON.parse(v.ssvc) as Ssvc) : null;
  } catch {
    ssvc = null;
  }
  const signals: Signals = {
    kevAddedAt: v.kev_added_at,
    knownRansomware: false,
    epss: v.epss,
    lev: null,
    exploitedSibling: null,
    cvss: v.cvss_score,
    cvssVector: v.cvss_vector,
    severityLabel: parseSeverityLabel(v.severity_label),
    ssvc,
    ageDays: v.published_at ? daysBetween(v.published_at, now.toISOString()) : null,
  };
  const before = assess(signals);
  const after = assess({ ...signals, reported: reportedSignal(list, now) });
  if (before.priority !== after.priority) lifted++;
  lines.push(
    `${id}  CVSS ${v.cvss_score ?? '–'}  EPSS ${v.epss ?? '–'}${v.kev_added_at ? '  KEV' : ''}  ${before.priority} → ${after.priority}  ${list.map((r) => `${r.name}${r.urgent ? '!' : ''}`).join(', ')}`,
  );
}
console.log(`\n${ids.length} CVEs named; ${found.size} in local D1; ${lifted} would change priority (! = called critical or urgent)\n`);
console.log(lines.join('\n'));
