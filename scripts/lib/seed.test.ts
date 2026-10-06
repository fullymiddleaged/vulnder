import { describe, expect, it } from 'vitest';
import { nextChunk, planSeed, reportedRowsWritten, splitTransactionText } from './seed';

/** The shape of `wrangler d1 export --no-schema` output: one statement per line. */
const EXPORT = [
  'PRAGMA defer_foreign_keys=TRUE;',
  `INSERT INTO "d1_migrations" ("id","name","applied_at") VALUES(1,'0001_init.sql','2026-10-05 04:04:42');`,
  `INSERT INTO "meta" ("key","value","updated_at") VALUES('cursor:cve','{"day":"2026-10-04"}','2026-10-05');`,
  `INSERT INTO "meta" ("key","value","updated_at") VALUES('usage_salt:2026-10-06','"abc"','2026-10-06');`,
  `INSERT INTO "meta" ("key","value","updated_at") VALUES('seeding','{}','2026-10-06');`,
  `INSERT INTO "events" ("id","vuln_id") VALUES(1,'CVE-2026-1');`,
  `INSERT INTO "vulns" ("id","summary") VALUES('CVE-2026-1',replace('Run BEGIN TRANSACTION; then\\nbegin  transaction','\\n',char(10)));`,
  `INSERT INTO "usage_counters" ("day","bucket","subject","count") VALUES('2026-10-06','parse','*',3);`,
  `INSERT INTO "sqlite_sequence" VALUES('d1_migrations',2);`,
  `INSERT INTO "affected" ("id","vuln_id") VALUES(7,'CVE-2026-1');`,
  '',
].join('\n');

describe('planSeed', () => {
  const plan = planSeed(EXPORT);

  it('copies only data tables, parents first and cursors last', () => {
    expect(plan.map((s) => s.table)).toEqual(['vulns', 'affected', 'events', 'meta']);
  });

  it('leaves out per-database meta: the IP-hash salt and the seed marker', () => {
    const meta = plan.filter((s) => s.table === 'meta').map((s) => s.sql);
    expect(meta).toHaveLength(1);
    expect(meta[0]).toContain("'cursor:cve'");
  });

  it('makes every statement an idempotent upsert, without a trailing semicolon', () => {
    for (const s of plan) {
      expect(s.sql).toMatch(/^INSERT OR REPLACE INTO "/);
      expect(s.sql).not.toMatch(/;$/);
    }
  });

  it('never emits "BEGIN TRANSACTION", which Wrangler refuses even inside strings', () => {
    const vuln = plan.find((s) => s.table === 'vulns')!.sql;
    expect(vuln).not.toMatch(/begin\s+transaction/i);
    expect(vuln).toContain("'Run BEGIN'||' TRANSACTION; then\\nbegin'||'  transaction'");
  });

  it('estimates billed rows per table, counting indexes', () => {
    expect(plan.map((s) => s.rows)).toEqual([6, 4, 3, 2]);
  });
});

describe('splitTransactionText', () => {
  it('leaves other text alone', () => {
    expect(splitTransactionText("VALUES('beginning a transaction')")).toBe("VALUES('beginning a transaction')");
  });
});

describe('nextChunk', () => {
  const statements = Array.from({ length: 5 }, (_, i) => ({ table: 'vulns', sql: `S${i}`, rows: 10 }));

  it('fills a chunk up to the byte limit', () => {
    expect(nextChunk(statements, 0, 8, Infinity)).toEqual({ start: 0, end: 2, rows: 20, sql: 'S0;\nS1;\n' });
    expect(nextChunk(statements, 4, 8, Infinity)).toEqual({ start: 4, end: 5, rows: 10, sql: 'S4;\n' });
  });

  it('stops before the row budget, and returns null when nothing fits or nothing is left', () => {
    expect(nextChunk(statements, 0, 1000, 35)).toMatchObject({ end: 3, rows: 30 });
    expect(nextChunk(statements, 0, 1000, 9)).toBeNull();
    expect(nextChunk(statements, 5, 1000, Infinity)).toBeNull();
  });

  it('sends a statement bigger than the byte limit on its own', () => {
    expect(nextChunk([{ table: 'vulns', sql: 'x'.repeat(50), rows: 1 }], 0, 8, Infinity)).toMatchObject({ start: 0, end: 1 });
  });
});

describe('reportedRowsWritten', () => {
  it('reads the count from text or JSON output', () => {
    expect(reportedRowsWritten('🚣 Executed 1,204 queries in 2.1 seconds (0 rows read, 6,020 rows written)')).toBe(6020);
    expect(reportedRowsWritten('[{"meta":{"rows_written":5}},{"meta":{"rows_written":7}}]')).toBe(12);
    expect(reportedRowsWritten('🚣 2 commands executed successfully.')).toBeNull();
  });
});
