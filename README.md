# Vulnder

**Something is circling your stack.** Describe what you run, or drop in a manifest, and see the vulnerabilities from the last 30 days that apply to you. They're ranked by real-world exploitation signals, not CVSS labels. You don't need an account: your stack lives in the URL, and the same URL gives you a JSON feed, an Atom feed and a README badge.

<!-- Screenshot: add docs/screenshot.png once the app is deployed. -->

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/OWNER/vulnder)

<sub>Before using the button, replace `OWNER` with the GitHub account that hosts this repository.</sub>

## How it ranks things

Each result goes in one of three tiers:

| Tier | Meaning |
|---|---|
| **Exploited** | On CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog. Always listed first. |
| **Likely** | [EPSS](https://www.first.org/epss) score of 0.10 or more. EPSS is a *predicted* probability of exploitation in the next 30 days, not evidence that exploitation has happened. |
| **Backlog** | Matches your stack, with neither signal. |

CVSS is shown, but it's never used to sort.

Each result also has a confidence label:

- **Version confirmed**: you gave a version, and [OSV](https://osv.dev) says that exact version is affected.
- **Product match**: the product is named as affected, but the version is unknown or couldn't be checked.

The page opens with **What changed this week**: newly published issues, KEV additions, EPSS jumps and fix releases for your stack.

## Feeds and badge

```
https://vulnder.dev/?s=npm:next@14.2.3,pypi:fastapi,p:postgresql/postgresql@16
https://vulnder.dev/api/feed?s=…      JSON: changes and the tiered list
https://vulnder.dev/feed.xml?s=…      Atom: one entry per change
https://vulnder.dev/badge.svg?s=…     "N known-exploited CVEs", green at zero
```

`days` (1–90, default 30) widens or narrows the window. The `s` format is a versioned public contract, documented in [docs/STACK_FORMAT.md](docs/STACK_FORMAT.md). A stack can hold up to 200 items; self-host for anything larger.

`GET /api/health` reports when each source last updated, plus record counts.

## Privacy

A list of what you run is useful to an attacker, so Vulnder keeps as little as it can:

- **Your stack and your text are not stored.** Free text goes to Workers AI only to pick out component names. The parsed result is cached under a SHA-256 hash of the normalised text; the text itself is never cached.
- **Manifests stay on your machine.** Files are parsed in your browser, and only package names and versions are sent.
- **Stack URLs are not logged.** Workers Logs redact query strings (`observability.redact_query_string`), and the code never logs request bodies or `s`.
- **No tracking.** There are no analytics or third-party scripts, apart from Cloudflare Turnstile on the submit form.
- **No referrer leaks.** Pages and links send no `Referer`, so clicking an advisory doesn't hand your stack URL to another site.
- **What Cloudflare can see.** Vulnder runs on Cloudflare, which processes every request, including the stack in the URL. Feed responses are cached in Cloudflare's cache under the canonical stack. If that is too much exposure, self-host.

## Data sources

| Source | Used for |
|---|---|
| [MITRE cvelistV5](https://github.com/CVEProject/cvelistV5) | Every new or changed CVE record, including CISA's ADP enrichment (SSVC, CVSS, CPEs) |
| [GitHub Advisory Database](https://github.com/advisories) | Package names, vulnerable ranges and first patched versions (CC BY 4.0) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed exploitation, date added, ransomware use |
| [FIRST EPSS](https://www.first.org/epss) | Exploitation probability and percentile. *EPSS scores courtesy of FIRST.* |
| [OSV](https://osv.dev) | Exact-version checks at request time |

Vulnder keeps 90 days of data. A vulnerability stays while it was published, or had an event, in the last 90 days, so an old CVE that lands on KEV today still shows up.

## Running locally

Requirements: Node.js 22 or newer.

```sh
npm ci
cp .dev.vars.example .dev.vars        # Turnstile test secret; optional GITHUB_TOKEN
npm run db:migrate:local
npm run backfill                      # last 90 days into local D1 (clones cvelistV5 into .cache/, ~2 GB)
npm run dev                           # http://localhost:8787
```

`npm run ingest` runs one incremental pass against local D1, the same pass production runs every hour.

Free-text parsing calls Workers AI, which needs a Cloudflare login even during `wrangler dev`. Without one, manifests and manually added items still work.

Other commands: `npm test`, `npm run typecheck`, `npm run lint`, and `npm run record-fixtures` to refresh the recorded upstream samples that tests use. Tests never touch the network.

## Deploying

1. `npx wrangler d1 create vulnder`, then put the returned `database_id` in both D1 entries in `wrangler.jsonc`.
2. Set `BASE_URL` (and `DISPLAY_NAME` if you like) in `wrangler.jsonc`. Feed links, badge links and Atom IDs are built from it.
3. Create a [Turnstile widget](https://developers.cloudflare.com/turnstile/), put its site key in `TURNSTILE_SITE_KEY`, and run `npx wrangler secret put TURNSTILE_SECRET_KEY`.
4. `npm run db:migrate:remote`, then `npm run backfill -- --remote`.
5. Deploy, choosing how ingest runs:
   - **Free plan:** `npx wrangler deploy`. The Worker can't run ingest itself (50 subrequests, 10 ms CPU), so `.github/workflows/ingest.yml` runs it hourly from GitHub Actions. Add the `CLOUDFLARE_API_TOKEN` (with D1 edit permission) and `CLOUDFLARE_ACCOUNT_ID` repository secrets. GitHub turns off scheduled workflows after 60 days without repository activity; `/api/health` shows sources as stale when that happens.
   - **Workers Paid:** `npx wrangler deploy --env paid`, which adds an hourly cron trigger. Set `GITHUB_TOKEN` as a Worker secret (Workers egress IPs are shared, and the unauthenticated GitHub limit is 60 requests an hour), then disable the Actions workflow.

### Bindings and secrets

| Name | Kind | Purpose |
|---|---|---|
| `DB` | D1 | All data |
| `AI` | Workers AI | Free-text extraction only (10,000 free neurons a day) |
| `RESOLVE_LIMITER` | Rate limiting | Per-IP limit on `POST /api/resolve` (20 a minute) |
| `ASSETS` | Static assets | The front end in `public/` |
| `BASE_URL`, `DISPLAY_NAME` | Vars | Public URL and name |
| `INGEST_RUNTIME` | Var | `actions` (free plan) or `worker` (Paid cron) |
| `AI_MODEL` | Var | Workers AI model ID (default `@cf/google/gemma-4-26b-a4b-it`) |
| `TURNSTILE_SITE_KEY` | Var | Public Turnstile key |
| `TURNSTILE_SECRET_KEY` | Secret | Required; `/api/resolve` refuses requests without it |
| `GITHUB_TOKEN` | Secret | Optional; raises the GitHub API limit |

## How it works

[docs/DESIGN.md](docs/DESIGN.md) records the limits that were checked, the design decisions, and what the build turned up. Briefly: ingest is one set of source modules (`src/ingest/sources/`) behind a `Store` interface. It runs either in the Worker's cron (D1 binding) or in Node (Wrangler CLI). Every run works to a budget and saves its cursor, so it can stop at any point and resume.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most useful contributions are new data sources and new manifest parsers.

## Licence

[MIT](LICENSE)
