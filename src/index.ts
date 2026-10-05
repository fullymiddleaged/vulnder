import { Hono } from 'hono';
import { Budget } from './ingest/budget';
import { D1BindingStore } from './ingest/d1-store';
import { runIngest } from './ingest/run';
import { feeds } from './routes/feeds';
import { health } from './routes/health';
import { resolve } from './routes/resolve';
import type { AppEnv } from './types';

/** Worker cron budget: under the Paid plan's 1,000 D1 queries per invocation, and well inside 15 minutes. */
const CRON_MAX_SUBREQUESTS = 900;
const CRON_DEADLINE_MS = 10 * 60_000;

const app = new Hono<AppEnv>();

app.route('/api/health', health);
app.route('/api/resolve', resolve);
app.route('/', feeds);

app.notFound((c) => {
  if (c.req.path.startsWith('/api/')) return c.json({ error: 'not found' }, 404);
  return c.text('Not found', 404);
});

app.onError((err, c) => {
  // Never log request URLs or bodies: stack URLs describe someone's infrastructure.
  console.error(`unhandled error on ${c.req.method} ${c.req.routePath}: ${err.message}`);
  return c.json({ error: 'internal error' }, 500);
});

export default {
  fetch: app.fetch,

  async scheduled(_controller, env, ctx) {
    if (env.INGEST_RUNTIME !== 'worker') {
      console.log('ingest skipped: INGEST_RUNTIME is not "worker" (ingest runs from GitHub Actions)');
      return;
    }
    const budget = new Budget({ maxSubrequests: CRON_MAX_SUBREQUESTS, deadline: Date.now() + CRON_DEADLINE_MS });
    ctx.waitUntil(
      runIngest({
        store: new D1BindingStore(env.DB, budget),
        fetch: (input, init) => fetch(input, init),
        budget,
        runtime: 'worker',
        githubToken: env.GITHUB_TOKEN || undefined,
        log: (m) => console.log(m),
      }).then((report) => console.log(JSON.stringify(report))),
    );
  },
} satisfies ExportedHandler<Env>;

export { app };
