import type { Budget } from './budget';
import type { Statement, Store } from './store';

/** Store backed by the Worker's D1 binding. Each query is charged to the budget, if given. */
export class D1BindingStore implements Store {
  constructor(
    private readonly db: D1Database,
    private readonly budget?: Budget,
  ) {}

  async all<T = Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<T[]> {
    this.budget?.take(1);
    const res = await this.db
      .prepare(sql)
      .bind(...params)
      .all<T>();
    return res.results;
  }

  async batch(statements: Statement[]): Promise<void> {
    if (statements.length === 0) return;
    this.budget?.take(statements.length);
    await this.db.batch(statements.map((s) => this.db.prepare(s.sql).bind(...s.params)));
  }
}
