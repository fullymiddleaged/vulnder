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
  private readonly now: () => number;

  constructor(private readonly opts: BudgetOptions) {
    this.now = opts.now ?? Date.now;
  }

  get spent(): number {
    return this.used;
  }

  get remaining(): number {
    return Math.max(0, this.opts.maxSubrequests - this.used);
  }

  /** True when n more subrequests fit and the deadline has not passed. */
  has(n = 1): boolean {
    return this.used + n <= this.opts.maxSubrequests && this.now() < this.opts.deadline;
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
   * Records n subrequests without refusing them. Used for D1 queries, so the
   * run's own bookkeeping (cursors, status) still lands after a source has
   * spent the budget. Sources check has() before each page, and the Worker's
   * limit is set below the platform's, which leaves room for this.
   */
  charge(n = 1): void {
    this.used += n;
  }

  /** A fetch that charges this budget before each request. */
  wrapFetch(inner: typeof fetch): typeof fetch {
    return ((input: RequestInfo | URL, init?: RequestInit) => {
      this.take(1);
      return inner(input, init);
    }) as typeof fetch;
  }
}
