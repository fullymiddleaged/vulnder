/**
 * Runs one ingest pass from Node, writing to D1 through Wrangler. This is how
 * ingest runs on the free plan (scheduled from GitHub Actions), and it works
 * locally too.
 *
 *   npm run ingest                    # local D1
 *   npm run ingest -- --remote        # remote D1 (needs CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID)
 *   npm run ingest -- --sources kev,epss --minutes 10
 *
 * GITHUB_TOKEN, if set, raises the GitHub API limit. CLOUDFLARE_ACCOUNT_ID and
 * CLOUDFLARE_API_TOKEN (with Workers AI read and edit) let it group similar
 * CVEs into families; --no-families skips that. Families are assigned to at
 * most --family-daily vulns a UTC day (default 8,000), which keeps the first
 * pass over a fresh database inside Workers Free's 100,000 rows written a day;
 * on Paid, raise it or pass 0 for no cap.
 */
import { Budget } from '../src/ingest/budget';
import { FREE_PLAN_FAMILY_DAILY, restEmbedder } from '../src/ingest/families';
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
    'no-families': { type: 'boolean' },
    'family-daily': { type: 'string', default: String(FREE_PLAN_FAMILY_DAILY) },
  },
});

const familyDaily = Number(values['family-daily']);
if (!Number.isInteger(familyDaily) || familyDaily < 0) throw new Error('--family-daily must be a whole number (0 for no cap)');

const target = parseTarget(values);
const store = new WranglerStore({ target, config: target === 'remote' ? productionConfig() : undefined });
const budget = new Budget({
  maxSubrequests: Number(values['max-subrequests']),
  deadline: Date.now() + Number(values.minutes) * 60_000,
});

// Families of similar CVEs need Workers AI: the token must also have Workers AI read and edit.
const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
const apiToken = process.env.CLOUDFLARE_API_TOKEN;
const embed = !values['no-families'] && accountId && apiToken ? restEmbedder(globalThis.fetch, accountId, apiToken) : undefined;
if (!embed && !values['no-families']) console.log('families: skipped (set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN to assign them)');

const report = await runIngest({
  store,
  fetch: globalThis.fetch,
  budget,
  runtime: 'node',
  githubToken: process.env.GITHUB_TOKEN || undefined,
  sources: parseSources(values.sources),
  maintenance: !values['no-maintenance'],
  embed,
  familyDailyVulns: familyDaily === 0 ? undefined : familyDaily,
  log: (m) => console.log(m),
});

console.log(JSON.stringify(report, null, 2));
if (report.sources.some((s) => s.status === 'error')) process.exitCode = 1;
