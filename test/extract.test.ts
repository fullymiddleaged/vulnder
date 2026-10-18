import { afterEach, describe, expect, it, vi } from 'vitest';
import { ExtractionUnavailable, extractWithFallback, type ExtractTiming } from '../src/resolve/extract';

const TEXT = 'Redis 7 and nginx';
const PRIMARY = '@cf/test/primary';
const FALLBACK = '@cf/test/fallback';
/** Short enough to keep the tests quick, far enough apart to order reliably. */
const TIMING: ExtractTiming = { hedgeMs: 40, deadlineMs: 400 };

const reply = (name: string) => ({ choices: [{ message: { content: JSON.stringify({ items: [{ name, version: null, type: 'product', ecosystem: null, vendor: null }] }) } }] });

/** A model call that answers (or throws) after `ms`, or when its signal aborts, whichever comes first. */
function after(ms: number, answer: () => unknown) {
  return (signal: AbortSignal) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        try {
          resolve(answer());
        } catch (err) {
          reject(err);
        }
      }, ms);
      signal.addEventListener('abort', () => {
        clearTimeout(timer);
        reject(signal.reason);
      });
    });
}

type Behaviour = (signal: AbortSignal) => Promise<unknown>;

function fakeAi(models: Record<string, Behaviour>) {
  const signals: Record<string, AbortSignal> = {};
  const run = vi.fn((model: string, _input: unknown, options: { signal: AbortSignal }) => {
    signals[model] = options.signal;
    return models[model]!(options.signal);
  });
  return { ai: { run } as unknown as Ai, run, signals };
}

const names = (e: { candidates: { name: string }[] }) => e.candidates.map((c) => c.name);

describe('extractWithFallback', () => {
  afterEach(() => vi.restoreAllMocks());

  it('uses the primary alone when it answers before the hedge', async () => {
    const { ai, run } = fakeAi({ [PRIMARY]: after(5, () => reply('Redis')), [FALLBACK]: after(5, () => reply('nginx')) });
    expect(names(await extractWithFallback(ai, PRIMARY, FALLBACK, TEXT, TIMING))).toEqual(['Redis']);
    await new Promise((r) => setTimeout(r, TIMING.hedgeMs + 20));
    expect(run.mock.calls.map(([m]) => m)).toEqual([PRIMARY]);
  });

  it('starts the fallback at the hedge and takes its answer when the primary is slow', async () => {
    const logged = vi.spyOn(console, 'log').mockImplementation(() => {});
    const { ai, run, signals } = fakeAi({ [PRIMARY]: after(300, () => reply('Redis')), [FALLBACK]: after(5, () => reply('nginx')) });
    const started = Date.now();
    expect(names(await extractWithFallback(ai, PRIMARY, FALLBACK, TEXT, TIMING))).toEqual(['nginx']);
    expect(Date.now() - started).toBeGreaterThanOrEqual(TIMING.hedgeMs - 5);
    expect(run.mock.calls.map(([m]) => m)).toEqual([PRIMARY, FALLBACK]);
    // The slow primary is abandoned, not left running.
    expect(signals[PRIMARY]!.aborted).toBe(true);
    expect(logged).toHaveBeenCalledWith('extract fallback started: slow');
  });

  it('keeps the primary answer when it beats the fallback after the hedge', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const { ai, signals } = fakeAi({ [PRIMARY]: after(60, () => reply('Redis')), [FALLBACK]: after(200, () => reply('nginx')) });
    expect(names(await extractWithFallback(ai, PRIMARY, FALLBACK, TEXT, TIMING))).toEqual(['Redis']);
    expect(signals[FALLBACK]!.aborted).toBe(true);
  });

  it('starts the fallback at once when the primary fails', async () => {
    const logged = vi.spyOn(console, 'log').mockImplementation(() => {});
    const { ai, run } = fakeAi({
      [PRIMARY]: after(1, () => {
        throw new Error('5007: no such model');
      }),
      [FALLBACK]: after(1, () => reply('nginx')),
    });
    const started = Date.now();
    expect(names(await extractWithFallback(ai, PRIMARY, FALLBACK, TEXT, TIMING))).toEqual(['nginx']);
    expect(Date.now() - started).toBeLessThan(TIMING.hedgeMs);
    expect(run).toHaveBeenCalledTimes(2);
    // The error's name says why, never its message, which could echo the input.
    expect(logged).toHaveBeenCalledWith('extract fallback started: Error');
  });

  it('is unavailable when both models fail', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const fail = after(1, () => {
      throw new Error('4006: daily allocation used');
    });
    const { ai } = fakeAi({ [PRIMARY]: fail, [FALLBACK]: fail });
    await expect(extractWithFallback(ai, PRIMARY, FALLBACK, TEXT, TIMING)).rejects.toBeInstanceOf(ExtractionUnavailable);
  });

  it('gives up on both at the deadline', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const never = after(10_000, () => reply('Redis'));
    const { ai, signals } = fakeAi({ [PRIMARY]: never, [FALLBACK]: never });
    const started = Date.now();
    await expect(extractWithFallback(ai, PRIMARY, FALLBACK, TEXT, TIMING)).rejects.toBeInstanceOf(ExtractionUnavailable);
    expect(Date.now() - started).toBeLessThan(TIMING.deadlineMs + 200);
    expect(signals[PRIMARY]!.aborted && signals[FALLBACK]!.aborted).toBe(true);
  });

  it('never hedges without a fallback model', async () => {
    const { ai, run } = fakeAi({ [PRIMARY]: after(100, () => reply('Redis')) });
    expect(names(await extractWithFallback(ai, PRIMARY, null, TEXT, TIMING))).toEqual(['Redis']);
    expect(run).toHaveBeenCalledTimes(1);
  });
});
