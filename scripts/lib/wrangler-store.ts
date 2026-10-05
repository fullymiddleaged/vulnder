import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { Statement, Store } from '../../src/ingest/store';

/**
 * Store that talks to D1 through the Wrangler CLI, for Node: the backfill and
 * the GitHub Actions ingest job. Writes are inlined into SQL and buffered into
 * a file run with `wrangler d1 execute --file`; reads use `--command --json`
 * and flush pending writes first, so reads always see earlier writes.
 */

export interface WranglerStoreOptions {
  target: 'local' | 'remote';
  /** Database name or binding. */
  database?: string;
  cwd?: string;
  /** Flush the write buffer once it reaches this many bytes. */
  flushBytes?: number;
  /** Runs wrangler with the given arguments and returns stdout. Replaceable in tests. */
  runner?: (args: string[]) => Promise<string>;
}

/** Windows limits a whole command line to 32,767 characters. */
const MAX_COMMAND_CHARS = 30_000;

export class WranglerStore implements Store {
  private pending: string[] = [];
  private pendingBytes = 0;
  private readonly database: string;
  private readonly flushBytes: number;
  private readonly run: (args: string[]) => Promise<string>;

  constructor(private readonly opts: WranglerStoreOptions) {
    this.database = opts.database ?? 'DB';
    this.flushBytes = opts.flushBytes ?? 4_000_000;
    this.run = opts.runner ?? defaultRunner(opts.cwd ?? process.cwd());
  }

  async all<T = Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<T[]> {
    await this.flush();
    const command = inlineParams(sql, params);
    if (command.length > MAX_COMMAND_CHARS) {
      throw new Error(`query too long for the command line (${command.length} chars); read in smaller chunks`);
    }
    const out = await this.run(['d1', 'execute', this.database, `--${this.opts.target}`, '--json', '--command', command]);
    return parseResults<T>(out);
  }

  async batch(statements: Statement[]): Promise<void> {
    for (const s of statements) {
      const line = `${inlineParams(s.sql, s.params).trim().replace(/;$/, '')};\n`;
      this.pending.push(line);
      this.pendingBytes += line.length;
    }
    if (this.pendingBytes >= this.flushBytes) await this.flush();
  }

  async flush(): Promise<void> {
    if (this.pending.length === 0) return;
    const sql = this.pending.join('');
    this.pending = [];
    this.pendingBytes = 0;
    const dir = await mkdtemp(path.join(tmpdir(), 'vulnture-'));
    const file = path.join(dir, 'batch.sql');
    try {
      await writeFile(file, sql, 'utf8');
      await this.run(['d1', 'execute', this.database, `--${this.opts.target}`, '--file', file, '--yes']);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
}

function defaultRunner(cwd: string): (args: string[]) => Promise<string> {
  const require = createRequire(import.meta.url);
  // bin/ is not in wrangler's package exports, so locate it from package.json.
  const pkgPath = require.resolve('wrangler/package.json');
  const pkg = require(pkgPath) as { bin: Record<string, string> };
  const wrangler = path.join(path.dirname(pkgPath), pkg.bin.wrangler!);
  return (args) =>
    new Promise((resolve, reject) => {
      // Run wrangler's JS entry with this Node binary: no shell, so SQL in
      // arguments needs no shell quoting on any platform.
      execFile(
        process.execPath,
        [wrangler, ...args],
        { cwd, maxBuffer: 1 << 30, env: { ...process.env, WRANGLER_SEND_METRICS: 'false', CI: 'true' } },
        (err, stdout, stderr) => {
          if (err) {
            const detail = extractError(stdout) ?? stderr.trim().split('\n').slice(-5).join('\n');
            reject(new Error(`wrangler ${args.slice(0, 4).join(' ')} failed: ${detail || err.message}`));
          } else {
            resolve(stdout);
          }
        },
      );
    });
}

function extractError(stdout: string): string | null {
  try {
    const parsed = JSON.parse(stdout) as { error?: { text?: string } };
    return parsed.error?.text ?? null;
  } catch {
    return null;
  }
}

/** Parses `wrangler d1 execute --json` output: an array with one entry per statement. */
export function parseResults<T>(stdout: string): T[] {
  const start = stdout.indexOf('[');
  if (start < 0) throw new Error(`unexpected wrangler output: ${stdout.slice(0, 200)}`);
  const parsed = JSON.parse(stdout.slice(start)) as { results?: T[]; success?: boolean }[];
  const first = parsed[0];
  if (!first || first.success === false) throw new Error('wrangler query failed');
  return first.results ?? [];
}

/**
 * Replaces SQLite parameters (`?` and `?NNN`) with literals, skipping quoted
 * strings and identifiers. A bare `?` takes the number after the largest one
 * used so far, as in SQLite.
 */
export function inlineParams(sql: string, params: unknown[]): string {
  let out = '';
  let maxIndex = 0;
  let i = 0;
  while (i < sql.length) {
    const ch = sql[i]!;
    if (ch === "'" || ch === '"' || ch === '`') {
      const end = closingQuote(sql, i, ch);
      out += sql.slice(i, end + 1);
      i = end + 1;
      continue;
    }
    if (ch === '-' && sql[i + 1] === '-') {
      const end = sql.indexOf('\n', i);
      const stop = end < 0 ? sql.length : end;
      out += sql.slice(i, stop);
      i = stop;
      continue;
    }
    if (ch === '?') {
      let j = i + 1;
      while (j < sql.length && /\d/.test(sql[j]!)) j++;
      const index = j > i + 1 ? Number(sql.slice(i + 1, j)) : maxIndex + 1;
      if (index < 1 || index > params.length) throw new Error(`parameter ?${index} has no value`);
      maxIndex = Math.max(maxIndex, index);
      out += sqlLiteral(params[index - 1]);
      i = j;
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

function closingQuote(sql: string, start: number, quote: string): number {
  let i = start + 1;
  while (i < sql.length) {
    if (sql[i] === quote) {
      if (sql[i + 1] === quote) {
        i += 2;
        continue;
      }
      return i;
    }
    i++;
  }
  throw new Error('unterminated quote in SQL');
}

export function sqlLiteral(v: unknown): string {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'boolean') return v ? '1' : '0';
  if (typeof v === 'bigint') return v.toString();
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error(`cannot store non-finite number ${v}`);
    return String(v);
  }
  if (typeof v === 'string') {
    const quoted = `'${v.replace(/\0/g, '').replace(/'/g, "''")}'`;
    // Wrangler refuses any SQL whose text contains "BEGIN TRANSACTION", even
    // inside a string literal, and some CVE descriptions do. Splitting the
    // literal into a concatenation stores the same value.
    return quoted.includes('BEGIN TRANSACTION') ? `(${quoted.replace(/BEGIN TRANSACTION/g, "BEGIN '||'TRANSACTION")})` : quoted;
  }
  throw new Error(`unsupported parameter type ${typeof v}`);
}
