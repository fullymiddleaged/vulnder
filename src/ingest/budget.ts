/** Thrown when a run has used its subrequest or time allowance. */
export class BudgetExhausted extends Error {
  constructor(reason: string) {
    super(`budget exhausted: ${reason}`);
    this.name = 'BudgetExhausted';
  }
}

/** Thrown when an upstream API says to back off. Handled like an exhausted budget. */
export class RateLimited extends Error {
  constructor(source: string, detail: string) {
    super(`${source} rate limited: ${detail}`);
    this.name = 'RateLimited';
  }
}

export interface BudgetOptions {
  /** Outbound fetches plus D1 queries allowed in this run. */
  maxSubrequests: number;
  /**
   * D1 statements allowed in this run (each statement in a batch counts), when
   * D1 has a tighter per-invocation limit than subrequests overall. Defaults
   * to no separate limit.
   */
  maxD1Queries?: number;
  /** Wall-clock deadline, in ms since the epoch. */
  deadline: number;
  now?: () => number;
}

/**
 * Tracks what a run has spent, so each source can stop cleanly and save its
 * cursor before the platform cuts it off. The Worker cron and the Node runner
 * use the same budget logic with different limits.
 */
export class Budget {
  private used = 0;
  private d1Used = 0;
  private readonly now: () => number;
  private readonly maxD1: number;

  constructor(private readonly opts: BudgetOptions) {
    this.now = opts.now ?? Date.now;
    this.maxD1 = opts.maxD1Queries ?? Infinity;
  }

  /** Subrequests spent, D1 queries included. */
  get spent(): number {
    return this.used;
  }

  get d1Spent(): number {
    return this.d1Used;
  }

  /**
   * Subrequests left under whichever limit is closer. Every D1 query is also a
   * subrequest, so spending this many can't break either limit.
   */
  get remaining(): number {
    return Math.max(0, Math.min(this.opts.maxSubrequests - this.used, this.maxD1 - this.d1Used));
  }

  /** True when n more subrequests (fetches or D1 queries) fit and the deadline has not passed. */
  has(n = 1): boolean {
    return this.used + n <= this.opts.maxSubrequests && this.d1Used + n <= this.maxD1 && this.now() < this.opts.deadline;
  }

  /** Records n subrequests, or throws BudgetExhausted if they don't fit. */
  take(n = 1): void {
    if (this.now() >= this.opts.deadline) throw new BudgetExhausted('deadline reached');
    if (this.used + n > this.opts.maxSubrequests) {
      throw new BudgetExhausted(`subrequest limit ${this.opts.maxSubrequests} reached`);
    }
    this.used += n;
  }

  /**
   * Records n D1 queries without refusing them, so the run's own bookkeeping
   * (cursors, status) still lands after a source has spent the budget.
   * Sources check has() before each page, and the Worker's limits are set
   * below the platform's, which leaves room for this.
   */
  charge(n = 1): void {
    this.used += n;
    this.d1Used += n;
  }

  /**
   * A fetch that charges this budget before each request and gives up on a
   * request after timeoutMs, so one hung upstream cannot stall the whole run.
   */
  wrapFetch(inner: typeof fetch, timeoutMs = 60_000): typeof fetch {
    return ((input: RequestInfo | URL, init?: RequestInit) => {
      this.take(1);
      return inner(input, { ...init, signal: init?.signal ?? AbortSignal.timeout(timeoutMs) });
    }) as typeof fetch;
  }
}
