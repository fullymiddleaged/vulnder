import { describe, expect, it } from 'vitest';
import { Budget, BudgetExhausted } from '../src/ingest/budget';
import { chunkByJsonSize } from '../src/ingest/store';

describe('Budget', () => {
  it('allows exactly maxSubrequests', () => {
    const b = new Budget({ maxSubrequests: 3, deadline: Number.MAX_SAFE_INTEGER });
    expect(b.has(3)).toBe(true);
    expect(b.has(4)).toBe(false);
    b.take(2);
    expect(b.has(1)).toBe(true);
    b.take(1);
    expect(b.spent).toBe(3);
    expect(b.has(1)).toBe(false);
    expect(() => b.take(1)).toThrow(BudgetExhausted);
  });

  it('stops at the deadline', () => {
    let t = 1000;
    const b = new Budget({ maxSubrequests: 100, deadline: 2000, now: () => t });
    expect(b.has()).toBe(true);
    t = 2000;
    expect(b.has()).toBe(false);
    expect(() => b.take()).toThrow(/deadline/);
  });

  it('charges wrapped fetches', async () => {
    const b = new Budget({ maxSubrequests: 1, deadline: Number.MAX_SAFE_INTEGER });
    const f = b.wrapFetch((async () => new Response('ok')) as unknown as typeof fetch);
    await f('https://example.com');
    await expect(async () => f('https://example.com')).rejects.toThrow(BudgetExhausted);
  });
});

describe('chunkByJsonSize', () => {
  it('returns nothing for no rows', () => {
    expect(chunkByJsonSize([])).toEqual([]);
  });

  it('keeps each chunk under the limit', () => {
    const rows = Array.from({ length: 50 }, (_, i) => ({ i, pad: 'x'.repeat(100) }));
    const chunks = chunkByJsonSize(rows, 1000);
    expect(chunks.flat()).toEqual(rows);
    for (const c of chunks) expect(JSON.stringify(c).length).toBeLessThanOrEqual(1000);
  });

  it('puts an oversized row in a chunk of its own', () => {
    const big = { pad: 'x'.repeat(2000) };
    expect(chunkByJsonSize([{ a: 1 }, big, { b: 2 }], 1000)).toEqual([[{ a: 1 }], [big], [{ b: 2 }]]);
  });

  it('counts multi-byte characters as UTF-8', () => {
    const rows = [{ s: 'é'.repeat(300) }, { s: 'é'.repeat(300) }];
    // Each row is ~600 bytes in UTF-8 but only ~300 UTF-16 units.
    expect(chunkByJsonSize(rows, 1000)).toHaveLength(2);
  });
});
