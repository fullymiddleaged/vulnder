/**
 * The storage seam between ingest logic and D1. Two implementations:
 * D1BindingStore (inside the Worker) and WranglerStore (Node, via the
 * Wrangler CLI). Ingest code only ever talks to this interface.
 */
export interface Statement {
  sql: string;
  params: unknown[];
}

export interface Store {
  /** Runs one read query. Implementations flush pending writes first. */
  all<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<T[]>;
  /** Runs write statements in order, atomically where the backend allows. */
  batch(statements: Statement[]): Promise<void>;
  /** Writes anything buffered. Stores that write immediately leave it out. */
  flush?(): Promise<void>;
}

export function stmt(sql: string, ...params: unknown[]): Statement {
  return { sql, params };
}

/**
 * Keeps each JSON parameter well under D1's 100 KB statement limit, which also
 * applies when WranglerStore inlines the parameter into the SQL text.
 */
export const MAX_JSON_PARAM_BYTES = 80_000;

/**
 * Splits rows into chunks whose JSON encoding stays under maxBytes. A single
 * row larger than the limit gets a chunk of its own.
 */
export function chunkByJsonSize<T>(rows: T[], maxBytes = MAX_JSON_PARAM_BYTES): T[][] {
  const chunks: T[][] = [];
  let current: T[] = [];
  let size = 2;
  for (const row of rows) {
    const rowSize = utf8Length(JSON.stringify(row)) + 1;
    if (current.length > 0 && size + rowSize > maxBytes) {
      chunks.push(current);
      current = [];
      size = 2;
    }
    current.push(row);
    size += rowSize;
  }
  if (current.length > 0) chunks.push(current);
  return chunks;
}

function utf8Length(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff) {
      n += 4;
      i++;
    } else n += 3;
  }
  return n;
}

/**
 * Reads rows for a list of keys with one JSON parameter per query, chunked to
 * stay inside statement limits. `sql` must contain one `?` bound to the JSON
 * array, used as `IN (SELECT value FROM json_each(?))`.
 */
export async function allForKeys<T>(store: Store, sql: string, keys: string[], chunkSize = 400): Promise<T[]> {
  const out: T[] = [];
  const unique = [...new Set(keys)];
  for (let i = 0; i < unique.length; i += chunkSize) {
    const rows = await store.all<T>(sql, [JSON.stringify(unique.slice(i, i + chunkSize))]);
    out.push(...rows);
  }
  return out;
}
