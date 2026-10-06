import { beforeEach, describe, expect, it } from 'vitest';
import { limitFromVar, takeDailyQuota } from '../src/lib/quota';
import { resetDb, rows, store } from './helpers/db';

const DAY1 = new Date('2026-10-06T10:00:00Z');
const DAY2 = new Date('2026-10-07T00:00:01Z');
const limits = { perClient: 2, total: 3 };

beforeEach(resetDb);

describe('takeDailyQuota', () => {
  it('caps each client, then the total, without letting a capped client use up the total', async () => {
    const take = (ip: string | null) => takeDailyQuota(store(), 'parse', ip, limits, DAY1);
    expect(await take('198.51.100.1')).toBe('ok');
    expect(await take('198.51.100.1')).toBe('ok');
    expect(await take('198.51.100.1')).toBe('client-limit');
    expect(await take('198.51.100.1')).toBe('client-limit');
    expect(await take('198.51.100.2')).toBe('ok');
    expect(await take(null)).toBe('total-limit');
    expect(await rows("SELECT count FROM usage_counters WHERE subject = '*'")).toEqual([{ count: 4 }]);
  });

  it('stores only salted hashes, and starts a new day with a new salt and clean counters', async () => {
    await takeDailyQuota(store(), 'parse', '198.51.100.1', limits, DAY1);
    const [day1] = await rows<{ subject: string }>("SELECT subject FROM usage_counters WHERE subject != '*'");
    expect(day1!.subject).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(await rows('SELECT * FROM usage_counters'))).not.toContain('198.51.100.1');

    await takeDailyQuota(store(), 'parse', '198.51.100.1', limits, DAY2);
    const left = await rows<{ day: string; subject: string }>("SELECT day, subject FROM usage_counters WHERE subject != '*'");
    expect(left).toHaveLength(1);
    expect(left[0]!.day).toBe('2026-10-07');
    expect(left[0]!.subject).not.toBe(day1!.subject);
    expect(await rows("SELECT key FROM meta WHERE key LIKE 'usage_salt:%'")).toEqual([{ key: 'usage_salt:2026-10-07' }]);
  });

  it('keeps buckets apart', async () => {
    const one = { perClient: 1, total: 10 };
    expect(await takeDailyQuota(store(), 'parse', 'x', one, DAY1)).toBe('ok');
    expect(await takeDailyQuota(store(), 'other', 'x', one, DAY1)).toBe('ok');
  });
});

describe('limitFromVar', () => {
  it('accepts positive whole numbers only', () => {
    expect(limitFromVar('45', 30)).toBe(45);
    for (const bad of [undefined, '', '0', '-3', '2.5', 'lots']) expect(limitFromVar(bad, 30)).toBe(30);
  });
});
