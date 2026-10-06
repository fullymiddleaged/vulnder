/**
 * Runs one ingest pass from Node, writing to D1 through Wrangler. This is how
 * ingest runs on the free plan (scheduled from GitHub Actions), and it works
 * locally too.
 *
 *   npm run ingest                    # local D1
 *   npm run ingest -- --remote        # remote D1 (needs CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID)
 *   npm run ingest -- --sources kev,epss --minutes 10
 *
 * GITHUB_TOKEN, if set, raises the GitHub API limit.
 */
import { Budget } from '../src/ingest/budget';
import { runIngest } from '../src/ingest/run';
import { parseArgs, parseSources, parseTarget } from './lib/args';
import { productionConfig } from './lib/production-config';
import { WranglerStore } from './lib/wrangler-store';

const { values } = parseArgs({
  options: {
    local: { type: 'boolean' },
    remote: { type: 'boolean' },
    sources: { type: 'string' },
    minutes: { type: 'string', default: '40' },
    'max-subrequests': { type: 'string', default: '20000' },
    'no-maintenance': { type: 'boolean' },
  },
});

const target = parseTarget(values);
const store = new WranglerStore({ target, config: target === 'remote' ? productionConfig() : undefined });
const budget = new Budget({
  maxSubrequests: Number(values['max-subrequests']),
  deadline: Date.now() + Number(values.minutes) * 60_000,
});

const report = await runIngest({
  store,
  fetch: globalThis.fetch,
  budget,
  runtime: 'node',
  githubToken: process.env.GITHUB_TOKEN || undefined,
  sources: parseSources(values.sources),
  maintenance: !values['no-maintenance'],
  log: (m) => console.log(m),
});

console.log(JSON.stringify(report, null, 2));
if (report.sources.some((s) => s.status === 'error')) process.exitCode = 1;
