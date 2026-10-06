/**
 * Turns a `wrangler d1 export --no-schema` dump of the local database into the
 * statements that seed a fresh remote one: data tables only, parents before
 * children, meta (the ingest cursors) last, every statement idempotent so an
 * interrupted seed can resume.
 */

/**
 * Tables to copy, in order, with the rows D1 bills for each insert: the row
 * plus one per index, counting the automatic indexes behind TEXT and composite
 * primary keys and UNIQUE constraints (see migrations/0001_init.sql).
 */
export const SEED_TABLES = [
  { table: 'vulns', rowsPerInsert: 6 },
  { table: 'aliases', rowsPerInsert: 3 },
  { table: 'affected', rowsPerInsert: 4 },
  { table: 'events', rowsPerInsert: 3 },
  { table: 'catalog', rowsPerInsert: 3 },
  { table: 'meta', rowsPerInsert: 2 },
] as const;

/** Meta rows that belong to one database: the daily IP-hash salt, and a seed marker. */
const LOCAL_ONLY_META = /^INSERT INTO "meta" \([^)]*\) VALUES\('(usage_salt:|seeding')/;

export interface SeedStatement {
  table: string;
  sql: string;
  /** Rows D1 will bill for this statement (an estimate). */
  rows: number;
}

/**
 * Wrangler refuses any SQL file containing "BEGIN TRANSACTION", even inside a
 * string, and a few CVE descriptions contain it. Outside strings an export
 * never does, so every match is inside a literal, where splitting it into a
 * concatenation stores the same text.
 */
export function splitTransactionText(sql: string): string {
  // No leading word boundary: exports write newlines as a literal \n, so "begin" can follow an "n".
  return sql.replace(/(BEGIN)(\s+TRANSACTION)/gi, "$1'||'$2");
}

export function planSeed(exportSql: string): SeedStatement[] {
  const byTable = new Map<string, SeedStatement[]>(SEED_TABLES.map((t) => [t.table, []]));
  const weight = new Map<string, number>(SEED_TABLES.map((t) => [t.table, t.rowsPerInsert]));
  for (const line of exportSql.split('\n')) {
    const m = /^INSERT INTO "([A-Za-z_0-9]+)" /.exec(line);
    if (!m) continue;
    const table = m[1]!;
    const list = byTable.get(table);
    if (!list || LOCAL_ONLY_META.test(line)) continue;
    const sql = splitTransactionText(line.replace(/^INSERT INTO /, 'INSERT OR REPLACE INTO ').replace(/;\s*$/, ''));
    list.push({ table, sql, rows: weight.get(table)! });
  }
  return [...byTable.values()].flat();
}

export interface SeedChunk {
  /** Index of the first statement, and one past the last. */
  start: number;
  end: number;
  rows: number;
  sql: string;
}

/**
 * The next chunk from `start`: as many statements as fit in `maxBytes` and in
 * `rowBudget` estimated rows. Null when nothing fits the row budget (or
 * nothing is left); a single statement larger than `maxBytes` goes alone.
 */
export function nextChunk(statements: SeedStatement[], start: number, maxBytes: number, rowBudget: number): SeedChunk | null {
  let end = start;
  let bytes = 0;
  let rows = 0;
  const parts: string[] = [];
  while (end < statements.length) {
    const s = statements[end]!;
    const size = s.sql.length + 2;
    if (rows + s.rows > rowBudget) break;
    if (parts.length > 0 && bytes + size > maxBytes) break;
    parts.push(`${s.sql};\n`);
    bytes += size;
    rows += s.rows;
    end++;
  }
  return parts.length === 0 ? null : { start, end, rows, sql: parts.join('') };
}

/** Rows written as Wrangler reports them for a remote import, or null when it doesn't say. */
export function reportedRowsWritten(output: string): number | null {
  const text = /([\d,]+) rows? written/i.exec(output);
  if (text) return Number(text[1]!.replace(/,/g, ''));
  const json = [...output.matchAll(/"rows_written"\s*:\s*(\d+)/g)];
  return json.length > 0 ? json.reduce((sum, m) => sum + Number(m[1]), 0) : null;
}
