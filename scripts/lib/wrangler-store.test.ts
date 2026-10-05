import { describe, expect, it } from 'vitest';
import { inlineParams, parseResults, sqlLiteral, WranglerStore } from './wrangler-store';

describe('sqlLiteral', () => {
  it('quotes and escapes', () => {
    expect(sqlLiteral(null)).toBe('NULL');
    expect(sqlLiteral(undefined)).toBe('NULL');
    expect(sqlLiteral(true)).toBe('1');
    expect(sqlLiteral(0.1)).toBe('0.1');
    expect(sqlLiteral(-3)).toBe('-3');
    expect(sqlLiteral("O'Brien")).toBe("'O''Brien'");
    expect(sqlLiteral('a\0b')).toBe("'ab'");
    expect(sqlLiteral('{"k":"it\'s; DROP TABLE vulns; --"}')).toBe(`'{"k":"it''s; DROP TABLE vulns; --"}'`);
  });

  it('never emits the text "BEGIN TRANSACTION", which wrangler rejects', () => {
    const lit = sqlLiteral("SQL injection via 'BEGIN TRANSACTION; DROP' and BEGIN TRANSACTION again");
    expect(lit).not.toContain('BEGIN TRANSACTION');
    expect(lit).toBe("('SQL injection via ''BEGIN '||'TRANSACTION; DROP'' and BEGIN '||'TRANSACTION again')");
  });

  it('refuses values it cannot represent', () => {
    expect(() => sqlLiteral(Number.NaN)).toThrow();
    expect(() => sqlLiteral(Infinity)).toThrow();
    expect(() => sqlLiteral({})).toThrow();
  });
});

describe('inlineParams', () => {
  it('replaces positional parameters in order', () => {
    expect(inlineParams('SELECT * FROM t WHERE a = ? AND b = ?', [1, 'x'])).toBe("SELECT * FROM t WHERE a = 1 AND b = 'x'");
  });

  it('supports numbered parameters used more than once', () => {
    expect(inlineParams('SELECT ?1 UNION SELECT ?1', ['k'])).toBe("SELECT 'k' UNION SELECT 'k'");
  });

  it('continues numbering after the largest numbered parameter, as SQLite does', () => {
    expect(inlineParams('SELECT ?2, ?, ?1', ['a', 'b', 'c'])).toBe("SELECT 'b', 'c', 'a'");
  });

  it('leaves question marks in strings, identifiers and comments alone', () => {
    expect(inlineParams(`SELECT '?', "a?b", ? -- what?\n`, [5])).toBe(`SELECT '?', "a?b", 5 -- what?\n`);
    expect(inlineParams("SELECT 'it''s ?', ?", [1])).toBe("SELECT 'it''s ?', 1");
  });

  it('fails on a missing parameter', () => {
    expect(() => inlineParams('SELECT ?, ?', [1])).toThrow(/\?2/);
  });
});

describe('parseResults', () => {
  it('reads the first statement’s rows', () => {
    expect(parseResults('[{"results":[{"n":1}],"success":true,"meta":{}}]')).toEqual([{ n: 1 }]);
  });

  it('tolerates a banner before the JSON', () => {
    expect(parseResults('Using local database\n[{"results":[],"success":true}]')).toEqual([]);
  });

  it('throws on failure', () => {
    expect(() => parseResults('[{"success":false}]')).toThrow();
    expect(() => parseResults('nothing here')).toThrow();
  });
});

describe('WranglerStore', () => {
  function fake() {
    const calls: string[][] = [];
    const store = new WranglerStore({
      target: 'local',
      runner: async (args) => {
        calls.push(args);
        return args.includes('--command') ? '[{"results":[{"ok":1}],"success":true}]' : '';
      },
    });
    return { store, calls };
  }

  it('buffers writes and flushes them before a read', async () => {
    const { store, calls } = fake();
    await store.batch([{ sql: 'INSERT INTO meta (key) VALUES (?)', params: ['a'] }]);
    expect(calls).toEqual([]);
    expect(await store.all('SELECT ? AS ok', [1])).toEqual([{ ok: 1 }]);
    expect(calls).toHaveLength(2);
    expect(calls[0]).toEqual(expect.arrayContaining(['d1', 'execute', 'DB', '--local', '--file', '--yes']));
    expect(calls[1]).toEqual(['d1', 'execute', 'DB', '--local', '--json', '--command', 'SELECT 1 AS ok']);
  });

  it('flushes on its own once the buffer is large', async () => {
    const calls: string[][] = [];
    const store = new WranglerStore({ target: 'remote', flushBytes: 100, runner: async (a) => (calls.push(a), '') });
    await store.batch([{ sql: 'SELECT ?', params: ['x'.repeat(200)] }]);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toContain('--remote');
    await store.flush();
    expect(calls).toHaveLength(1);
  });

  it('refuses reads too long for the Windows command line', async () => {
    const { store } = fake();
    await expect(store.all('SELECT ?', ['x'.repeat(40_000)])).rejects.toThrow(/too long/);
  });
});
