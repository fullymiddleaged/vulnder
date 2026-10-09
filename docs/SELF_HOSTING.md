# Running and self-hosting Vulnder

## Running locally

Needs Node.js 22 or newer.

```sh
npm ci
cp .dev.vars.example .dev.vars        # Turnstile test secret; optional GITHUB_TOKEN
npm run db:migrate:local
npm run backfill                      # last 90 days into local D1 (clones cvelistV5 into .cache/, ~2 GB)
npm run dev                           # http://localhost:8787
```

- `npm run ingest` runs one incremental pass against local D1, the same pass production runs every hour.
- Free-text parsing calls Workers AI, which needs a Cloudflare login even during `wrangler dev`. Without one, manifests and manually added items still work.
- Jev is billed in [AI Gateway credits](https://developers.cloudflare.com/ai-gateway/), not neurons. Without credits its calls fail with "Insufficient AI Gateway credits" and parsing carries on without it.
- `npm run update-injection-corpus` refreshes the prompt-injection test corpus (`test/fixtures/injection/corpus.json`) from [garak](https://github.com/NVIDIA/garak) (Apache-2.0) and [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) (MIT), at the commits pinned in the script.
- Checks: `npm test`, `npm run typecheck`, `npm run lint`. `npm run record-fixtures` refreshes the recorded upstream samples the tests use. Tests never touch the network.

## Deploying

1. **Database.** `npx wrangler d1 create vulnder`. Keep the ID out of git: put `D1_DATABASE_ID=<database_id>` in `.env` (git-ignored), and the same `D1_DATABASE_ID` as a build variable wherever you deploy from. Commands that reach Cloudflare (`npm run db:migrate:remote`, `seed:remote`, `deploy:paid`, `ingest -- --remote`) write `wrangler.production.jsonc`, also git-ignored, with the real ID. `wrangler.jsonc` keeps a placeholder for local development. (The ID grants no access without your Cloudflare credentials, so putting it in `wrangler.jsonc` is fine too.)
2. **Name and URL.** Set `BASE_URL` (and `DISPLAY_NAME` if you like) in `wrangler.jsonc`; feed links, badge links and Atom IDs are built from it. On your own domain, also replace `vulnder.com` in `public/index.html`, `public/robots.txt`, `public/sitemap.xml` and `public/llms.txt`.
3. **Turnstile.** Create a [Turnstile widget](https://developers.cloudflare.com/turnstile/) (Managed mode) for your hostname and put its site key in both `TURNSTILE_SITE_KEY` entries in `wrangler.jsonc`. After the first deploy, add the secret key as a Worker secret named `TURNSTILE_SECRET_KEY`. Locally, `.dev.vars` uses Cloudflare's always-pass test keys.
4. **Seed.** `npm run db:migrate:remote`, then `npm run backfill` (if you haven't), `npm run seed:remote` to see the plan, and `npm run seed:remote -- --yes` to copy it up. That's about 700,000 rows written: roughly 1% of Workers Paid's monthly D1 allowance, but more than Free's 100,000 a day, so on Free add `--max-rows 90000` and repeat daily until it reports done. Ingest waits for the seed, then carries on from the snapshot. Optionally buy AI Gateway credits for Jev (about $0.0001 a parse).
5. **Deploy**, choosing how ingest runs:
   - **Free plan:** `npm run deploy:free`. The Worker can't run ingest itself (50 subrequests, 10 ms CPU), so `.github/workflows/ingest.yml` runs it hourly from GitHub Actions. Set repository variables `INGEST_FROM_ACTIONS=true` and `D1_DATABASE_ID`, and secrets `CLOUDFLARE_API_TOKEN` (D1 edit, plus Workers AI read and edit for similar-CVE families) and `CLOUDFLARE_ACCOUNT_ID`. Without the Workers AI permission, ingest skips families. With it, families are assigned to at most 8,000 CVEs a day (`--family-daily`), so the first pass over a seeded database takes about five days. Apply migration 0004 on a day the seed isn't using the allowance. GitHub turns off scheduled workflows after 60 days without repository activity; `/api/health` shows stale sources when that happens.
   - **Workers Paid:** `npm run deploy:paid`, which adds an hourly cron trigger. Set `GITHUB_TOKEN` as a Worker secret (Workers egress IPs are shared, and GitHub's unauthenticated limit is 60 requests an hour). Leave `INGEST_FROM_ACTIONS` unset. With Workers Builds, set the deploy command to `npm run deploy:paid` and add the `D1_DATABASE_ID` build variable.

## Bindings and secrets

| Name | Kind | Purpose |
|---|---|---|
| `DB` | D1 | All data |
| `AI` | Workers AI | Free-text extraction and Jev (AI Gateway credits); on the Paid cron, also similar-CVE embeddings (capped at a million tokens a day) |
| `RESOLVE_LIMITER` | Rate limiting | Per-IP limit on `POST /api/resolve` (20 a minute); IPv6 by /64 |
| `FEED_LIMITER` | Rate limiting | Per-IP limit on feed, Atom and badge cache misses (60 a minute); a browser with a feed pass gets its own |
| `FEED_HEAVY_LIMITER` | Rate limiting | Tighter limit on misses for stacks touching 1,000+ vulns (6 a minute), per IP or per pass |
| `ASSETS` | Static assets | The front end in `public/` |
| `BASE_URL`, `DISPLAY_NAME` | Vars | Public URL and name |
| `INGEST_RUNTIME` | Var | `actions` (free plan) or `worker` (Paid cron) |
| `AI_MODEL` | Var | Workers AI model ID (default `@cf/google/gemma-4-26b-a4b-it`) |
| `PARSE_DAILY_PER_CLIENT`, `PARSE_DAILY_TOTAL` | Vars | Daily caps on free-text parses that reach the model (defaults 30 and 600; cached parses are free) |
| `TURNSTILE_SITE_KEY` | Var | Public Turnstile key; tokens must come from `BASE_URL`'s hostname |
| `TURNSTILE_SECRET_KEY` | Secret | Required; `/api/resolve` refuses requests without it |
| `GITHUB_TOKEN` | Secret | Optional; raises the GitHub API limit |

## Architecture

[ENGINEERING.md](ENGINEERING.md) records the limits that were checked, the design decisions, and what the build turned up. In short: ingest is one set of source modules (`src/ingest/sources/`) behind a `Store` interface. It runs in the Worker's cron (D1 binding) or in Node (Wrangler CLI), works to a budget, and saves its cursor, so it can stop at any point and resume.
