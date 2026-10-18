/**
 * Backtests the ranking against CISA KEV (docs/plans/chain-risk-and-cve-roles.md,
 * phase 0): how CVEs would have ranked before they were added, from what was
 * known then. Reads local D1 only (cve_index, and exploits when asked) and
 * changes nothing. Downloads one EPSS file a week into .cache/epss/ the first
 * time (about 2.7 MB each).
 *
 *   npm run backtest                            # CVSS-only, EPSS-only and today's ranking
 *   npm run backtest -- --chain                 # plus chain rule 1 (CWEs from the cvelistV5 clone)
 *   npm run backtest -- --trend                 # plus the product-pressure test
 *   npm run backtest -- --product-kev           # plus lifts for products with a KEV add in the last 90 days
 *   npm run backtest -- --with-current-exploits # today's Metasploit/Nuclei/exploit refs: an upper bound
 *   npm run backtest -- --json out.json         # also write the numbers
 */
import { existsSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parseCveRecord } from '../src/ingest/sources/cve-record';
import { roleOf } from '../src/match/roles';
import type { Signals } from '../src/match/priority';
import { parseArgs } from './lib/args';
import {
  addDays,
  formatReport,
  loadEpss,
  runBacktest,
  runTrend,
  toCve,
  TREND_PRIOR_DAYS,
  TREND_RECENT_DAYS,
  type IndexRow,
  type TrendRow,
  type Variant,
} from './lib/backtest';
import { WranglerStore } from './lib/wrangler-store';

const { values } = parseArgs({
  options: {
    'kev-from': { type: 'string', default: '2025-01-01' },
    'epss-from': { type: 'string', default: '2024-11-04' },
    to: { type: 'string' },
    chain: { type: 'boolean' },
    trend: { type: 'boolean' },
    'product-kev': { type: 'boolean' },
    'with-current-exploits': { type: 'boolean' },
    cvelist: { type: 'string', default: path.join('.cache', 'cvelistV5') },
    'epss-cache': { type: 'string', default: path.join('.cache', 'epss') },
    json: { type: 'string' },
  },
});

const log = (m: string) => console.error(m);
const day = (s: string, name: string) => {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) throw new Error(`--${name} takes a date, YYYY-MM-DD`);
  return s;
};
const store = new WranglerStore({ target: 'local' });
const kevFrom = day(values['kev-from']!, 'kev-from');
const epssFrom = day(values['epss-from']!, 'epss-from');
const to = day(values.to ?? new Date().toISOString().slice(0, 10), 'to');
// Old enough for the trend's 455-day lookback and the chain rule's enablers.
const historyFrom = addDays(kevFrom, -(TREND_RECENT_DAYS + TREND_PRIOR_DAYS));
const exploitsWanted = values['with-current-exploits'] === true;

const COLUMNS = `id, published_at, title, product, cvss_score, cvss_vector, severity_label, ssvc, kev_added_at, kev_ransomware${exploitsWanted ? ', exploit_ref' : ''}`;
type Row = IndexRow & { exploit_ref?: string | null };

// One month a query keeps each Wrangler call's output small.
const rows = new Map<string, Row>();
for (let m = `${historyFrom.slice(0, 7)}-01`; m <= to; ) {
  const next = new Date(`${m}T00:00:00Z`);
  next.setUTCMonth(next.getUTCMonth() + 1);
  const end = next.toISOString().slice(0, 10);
  log(`reading cve_index ${m.slice(0, 7)}`);
  for (const r of await store.all<Row>(`SELECT ${COLUMNS} FROM cve_index WHERE state = 'published' AND published_at >= ? AND published_at < ?`, [m, end])) {
    rows.set(r.id, r);
  }
  m = end;
}
// KEV adds of older CVEs: cases for recall, and outcomes for the trend test.
for (const r of await store.all<Row>(`SELECT ${COLUMNS} FROM cve_index WHERE state = 'published' AND kev_added_at IS NOT NULL`)) rows.set(r.id, r);
log(`${rows.size} CVEs`);

// CWEs (and a summary when there's no title) for the role labels, only the chain rule reads them.
const cweOf = new Map<string, { cwe: string[]; text: string | null }>();
if (values.chain) {
  const dir = values.cvelist!;
  if (!existsSync(path.join(dir, 'cves'))) log(`no cvelistV5 clone at ${dir}: roles come from titles only`);
  else {
    log('reading CWEs from the cvelistV5 clone');
    for (const id of rows.keys()) {
      const m = /^CVE-(\d{4})-(\d+)$/.exec(id);
      if (!m) continue;
      const file = path.join(dir, 'cves', m[1]!, `${Math.floor(Number(m[2]) / 1000)}xxx`, `${id}.json`);
      try {
        const rec = parseCveRecord(JSON.parse(await readFile(file, 'utf8')));
        if (rec && !rec.withdrawn) cweOf.set(id, { cwe: rec.fields.cwe ?? [], text: rec.fields.title ?? rec.fields.summary ?? null });
      } catch {
        // A missing or unreadable record falls back to the title.
      }
    }
  }
}

const exploitsOf = new Map<string, Signals['exploit']>();
if (exploitsWanted) {
  log('reading exploits (today’s, so the run is an upper bound)');
  const ex = await store.all<{ cve_id: string; source: string; kind: string }>('SELECT cve_id, source, kind FROM exploits');
  for (const e of ex) {
    const x = exploitsOf.get(e.cve_id) ?? { ref: false, metasploit: null, nuclei: false };
    if (e.source === 'metasploit') x.metasploit = e.kind === 'exploit' || x.metasploit === 'exploit' ? 'exploit' : 'auxiliary';
    if (e.source === 'nuclei') x.nuclei = true;
    exploitsOf.set(e.cve_id, x);
  }
  for (const r of rows.values()) {
    if (!r.exploit_ref) continue;
    exploitsOf.set(r.id, { ...(exploitsOf.get(r.id) ?? { metasploit: null, nuclei: false }), ref: true });
  }
}

const cves = [...rows.values()].map((r) => {
  const rec = cweOf.get(r.id);
  return toCve(r, roleOf(rec?.cwe ?? [], r.title ?? rec?.text ?? null, r.cvss_vector), exploitsWanted ? (exploitsOf.get(r.id) ?? { ref: false, metasploit: null, nuclei: false }) : undefined);
});

const variants: Variant[] = [
  { name: 'CVSS only', ranker: 'cvss' },
  { name: 'EPSS only', ranker: 'epss' },
  { name: 'Today', ranker: 'assess' },
  ...(values.chain ? [{ name: 'Today + chain rule 1', ranker: 'assess' as const, chain: true }] : []),
  ...(values['product-kev']
    ? [
        { name: 'Today + product KEV (Attend)', ranker: 'assess' as const, productKev: 'attend' as const },
        { name: 'Today + product KEV (score)', ranker: 'assess' as const, productKev: 'score' as const },
      ]
    : []),
];

const report = await runBacktest({
  cves,
  variants,
  kevFrom,
  to,
  epssFrom,
  loadEpss: (d, wanted) => loadEpss(d, wanted, { fetchFn: fetch, cacheDir: values['epss-cache']!, log }),
  log,
});

const trend = values.trend
  ? runTrend(
      [...rows.values()].flatMap((r): TrendRow[] =>
        r.product
          ? [{ product: r.product, published: r.published_at?.slice(0, 10) ?? null, high: (r.cvss_score ?? 0) >= 7 || (r.cvss_score === null && (r.severity_label === 'high' || r.severity_label === 'critical')), kevAdded: r.kev_added_at?.slice(0, 10) ?? null }]
          : [],
      ),
      kevFrom,
      to,
    )
  : null;

const notes = [
  `# Ranking backtest, ${kevFrom} to ${to}`,
  '',
  'Point in time: EPSS from the weekly file on or before each date; KEV only once added; age from the date.',
  'Left out: SSVC "exploitation" (leaks KEV), LEV, families' + (exploitsWanted ? '. Exploit signals are TODAY’S: an upper bound.' : ', exploit signals.'),
  'CVSS, vector, SSVC automatable and technical impact are as held today (rarely changed after the first weeks).',
  '',
];
console.log(notes.join('\n') + formatReport(report, trend));
if (values.json) await writeFile(values.json, JSON.stringify({ kevFrom, to, epssFrom, exploits: exploitsWanted, report, trend }, null, 2));
