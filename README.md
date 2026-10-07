# Vulnder

**Someone's into your stack. See who, ranked by real-world exploitation.** Describe what you run, or drop in a manifest, and see the vulnerabilities from the last 30 days that apply to you. They're ranked by real-world exploitation signals, not CVSS labels. You don't need an account: your stack lives in the URL, and the same URL gives you a JSON feed, an Atom feed and a README badge.

<!-- Screenshot: add docs/screenshot.png once the app is deployed. -->

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/fullymiddleaged/vulnder)

## How it ranks things

Each result gets a priority, named after CISA's [SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc) decisions (Act, Attend, Track), with Watch added between Attend and Track. Evidence of exploitation always outranks prediction and severity:

| Priority | When |
|---|---|
| **Act now** (red) | On CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog, or CISA reports active exploitation. |
| **Attend** (amber) | [EPSS](https://www.first.org/epss) of 0.10 or more, CVSS 9.0 or more that an attacker can reach (below), or a proof-of-concept exploit that is automatable or gives total control. EPSS is a *predicted* probability of exploitation in the next 30 days, not evidence that it has happened. |
| **Watch** (yellow) | CVSS 8.0 or more, CVSS 7.0 or more within reach on an internet-facing item (below), a proof-of-concept exploit, or automatable with total technical impact. |
| **Track** (grey) | Everything else: it affects your stack, but nothing above applies. |

A CVSS score says how bad a bug is, not whether anyone can get at it. So a critical goes to Attend only when its CVSS vector says it's reachable over the network with no login and no user action, or CISA judges it automatable. Criticals that need local access, a login or someone's help go to Watch instead. A critical with no CVSS 3 or 4 vector stays in Attend. From CVSS 7.0 up, each result says which of these applies ("Reachable over the network without a login", "Needs a login and user action").

You can mark items in your stack as internet-facing, on the Edit page or with `!` in the link (see [STACK_FORMAT.md](docs/STACK_FORMAT.md)). On those items, a bug that is reachable with no login and no user action, or that CISA judges automatable, counts for more: CVSS 7.0 or more goes to Watch, its score gets × 1.25, and its reasons say "Internet-facing". A missing vector gets no benefit of the doubt here. The mark only reorders results; it never hides one. When you describe your stack in words, two things mark components for you: products that face the internet by what they are (VPN and remote-access gateways, edge firewalls, ADCs and mail gateways such as FortiGate, Cisco ASA, Palo Alto PAN-OS or Citrix NetScaler) are always marked, and Jev (below) marks what your description says or clearly implies faces the internet, such as "nginx in front" or "our public API". The results page lists what was marked, and you can untick any of them under Edit stack. Manifests are never marked automatically. The mark goes into the link, so a shared link says which of your systems face the internet.

Within a priority, results are ordered by a 0–100 risk score: threat (1 for KEV, otherwise EPSS, at least 0.2 with a proof-of-concept exploit, 0.01 before EPSS has scored it) × impact (CVSS ÷ 10, at least 0.9 for total technical impact, 0.5 without CVSS), × 1.25 if automatable, × 1.25 if internet-facing and within reach, and × 1.2 if used in ransomware, capped at 100. It's a heuristic for ordering, not a probability. Exploitation status, automatability and technical impact come from CISA's [Vulnrichment](https://github.com/cisagov/vulnrichment) data in CVE records. Every result lists why it got its priority.

**Fix first** ranks the items in your stack: the one with the most urgent priority first, then by the total risk score of its CVEs, since one upgrade usually closes several.

The JSON feed carries `priority`, `score` and `reasons` on each result and a `fixFirst` list. The older `tier` field (exploited, likely or backlog, from KEV and EPSS only) is unchanged, and the badge still counts exploited CVEs.

Each result also has a confidence label:

- **Version confirmed**: you gave a version, and [OSV](https://osv.dev) says that exact version is affected.
- **Product match**: the product is named as affected, but the version is unknown or couldn't be checked.

A vague name like "Cisco switches" becomes several close matches, in catalog order (most-affected first). When your description makes the stack's scale (enterprise, small business or home) or hosting (cloud or on-premises) clear, [Jev](https://developers.cloudflare.com/ai/models/typesafe/jev/) on Workers AI judges how well each close match fits it, and they're sorted by that, so a home lab sees small-business gear before data-centre switches. That only changes the order; it never hides a match. The same call asks, for each component you named that isn't already marked as an edge product, whether your description says it faces the internet, and marks it when Jev is fairly sure (0.7 or more). Manifests aren't sent to Jev: they keep catalog order and get no marks.

Free text that reads like instructions for an AI rather than a list of what you run is refused: first by a phrase check, then by Jev. Text that gets past both still can't add anything: the extraction model's answer is checked against your words, and components you didn't name are dropped. If Jev is unavailable, parsing carries on without the second check and close matches keep catalog order.

The page opens with **What changed this week**: newly published issues, KEV additions, EPSS jumps and fix releases for your stack.

## Feeds and badge

```
https://vulnder.com/?s=npm:next@14.2.3,pypi:fastapi,p:postgresql/postgresql@16
https://vulnder.com/api/feed?s=…      JSON: changes and the tiered list
https://vulnder.com/feed.xml?s=…      Atom: one entry per change
https://vulnder.com/badge.svg?s=…     "N known-exploited CVEs", green at zero
```

`days` (1–90, default 30) widens or narrows the window. The `s` format is a versioned public contract, documented in [docs/STACK_FORMAT.md](docs/STACK_FORMAT.md). A stack can hold up to 200 items; self-host for anything larger.

`GET /api/health` reports when each source last updated. It's cached for 15 minutes.

## Privacy

A list of what you run is useful to an attacker, so Vulnder keeps as little as it can:

- **Your stack and your text are not stored.** Free text goes to Workers AI only to pick out component names and, through Jev (zero data retention), to screen it and judge which close matches fit. The parsed result is cached under a SHA-256 hash of the normalised text; the text itself is never cached.
- **Manifests stay on your machine.** Files are parsed in your browser, and only package names and versions are sent.
- **Stack URLs are not logged.** Workers Logs redact query strings (`observability.redact_query_string`), and the code never logs request bodies or `s`.
- **IP addresses are not stored.** Rate limits use the IP only as a key. The daily cap on free-text parsing counts a SHA-256 hash of the IP with a random salt that's deleted at the end of each UTC day, along with that day's counts.
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

Jev is billed in [AI Gateway credits](https://developers.cloudflare.com/ai-gateway/), not neurons. Without credits its calls fail with "Insufficient AI Gateway credits", and parsing carries on without it (see above).

`npm run update-injection-corpus` refreshes the prompt-injection test corpus (`test/fixtures/injection/corpus.json`) from [garak](https://github.com/NVIDIA/garak) (Apache-2.0) and [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) (MIT), at the commits pinned in the script.

Other commands: `npm test`, `npm run typecheck`, `npm run lint`, and `npm run record-fixtures` to refresh the recorded upstream samples that tests use. Tests never touch the network.

## Deploying

1. `npx wrangler d1 create vulnder`. Keep the ID out of git: put `D1_DATABASE_ID=<the returned database_id>` in a `.env` file (git-ignored), and the same `D1_DATABASE_ID` as a build variable wherever you deploy from. Commands that reach Cloudflare (`npm run db:migrate:remote`, `seed:remote`, `deploy:paid`, `ingest -- --remote`) write `wrangler.production.jsonc`, also git-ignored, with the real ID; `wrangler.jsonc` keeps a placeholder, which local development uses. (Or simply put the ID in `wrangler.jsonc`: it identifies the database but grants no access without your Cloudflare credentials.)
2. Set `BASE_URL` (and `DISPLAY_NAME` if you like) in `wrangler.jsonc`. Feed links, badge links and Atom IDs are built from it.
3. Create a [Turnstile widget](https://developers.cloudflare.com/turnstile/) (Managed mode) for your hostname, and put its site key in both `TURNSTILE_SITE_KEY` entries in `wrangler.jsonc`; the site key is public. After the first deploy, add the secret key as a Worker secret named `TURNSTILE_SECRET_KEY` (dashboard: Workers & Pages → your Worker → Settings → Variables and Secrets). Locally, `.dev.vars` uses Cloudflare's always-pass test keys (see `.dev.vars.example`).
4. `npm run db:migrate:remote`, then seed it from your local database: `npm run backfill` (if you haven't), then `npm run seed:remote` to see the plan, and `npm run seed:remote -- --yes` to copy it up. The seed writes each row once, about 700,000 rows written with indexes: roughly 1% of Workers Paid's monthly D1 allowance, but more than the Free plan's 100,000 a day, so on Free add `--max-rows 90000` and repeat it daily until it reports done. Ingest waits until the seed has finished, then carries on from the snapshot. (`npm run backfill -- --remote` still works, but it writes rows several times over.) Optionally, buy AI Gateway credits so Jev can screen free text and order close matches (about $0.0001 a parse, at $0.042 per million input tokens).
5. Deploy, choosing how ingest runs:
   - **Free plan:** `npm run deploy:free`. The Worker can't run ingest itself (50 subrequests, 10 ms CPU), so `.github/workflows/ingest.yml` runs it hourly from GitHub Actions. Set the repository variables `INGEST_FROM_ACTIONS` (to `true`) and `D1_DATABASE_ID`, and add the `CLOUDFLARE_API_TOKEN` (with D1 edit permission) and `CLOUDFLARE_ACCOUNT_ID` repository secrets. GitHub turns off scheduled workflows after 60 days without repository activity; `/api/health` shows sources as stale when that happens.
   - **Workers Paid:** `npm run deploy:paid`, which adds an hourly cron trigger. Set `GITHUB_TOKEN` as a Worker secret (Workers egress IPs are shared, and the unauthenticated GitHub limit is 60 requests an hour). Leave `INGEST_FROM_ACTIONS` unset so the Actions workflow stays off. Deploying from GitHub with Workers Builds? Set its deploy command to `npm run deploy:paid` and add the `D1_DATABASE_ID` build variable.

### Bindings and secrets

| Name | Kind | Purpose |
|---|---|---|
| `DB` | D1 | All data |
| `AI` | Workers AI | Free text only: extraction (10,000 free neurons a day) and Jev (AI Gateway credits) |
| `RESOLVE_LIMITER` | Rate limiting | Per-IP limit on `POST /api/resolve` (20 a minute) |
| `FEED_LIMITER` | Rate limiting | Per-IP limit on feed, Atom and badge requests that miss the cache (60 a minute) |
| `ASSETS` | Static assets | The front end in `public/` |
| `BASE_URL`, `DISPLAY_NAME` | Vars | Public URL and name |
| `INGEST_RUNTIME` | Var | `actions` (free plan) or `worker` (Paid cron) |
| `AI_MODEL` | Var | Workers AI model ID (default `@cf/google/gemma-4-26b-a4b-it`) |
| `PARSE_DAILY_PER_CLIENT`, `PARSE_DAILY_TOTAL` | Vars | Daily caps on free-text parses that reach the model (defaults 30 and 600; cached parses are free) |
| `TURNSTILE_SITE_KEY` | Var | Public Turnstile key. Tokens must come from `BASE_URL`'s hostname |
| `TURNSTILE_SECRET_KEY` | Secret | Required; `/api/resolve` refuses requests without it |
| `GITHUB_TOKEN` | Secret | Optional; raises the GitHub API limit |

## How it works

[docs/DESIGN.md](docs/DESIGN.md) records the limits that were checked, the design decisions, and what the build turned up. Briefly: ingest is one set of source modules (`src/ingest/sources/`) behind a `Store` interface. It runs either in the Worker's cron (D1 binding) or in Node (Wrangler CLI). Every run works to a budget and saves its cursor, so it can stop at any point and resume.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most useful contributions are new data sources and new manifest parsers.

## Licence

[Apache License 2.0](LICENSE). Copyright 2026 Pete Salmond ([@fullymiddleaged](https://github.com/fullymiddleaged)). If you redistribute Vulnder or a derivative, keep the [NOTICE](NOTICE) file with it.

The licence covers the code, not the name: "Vulnder" and its logo identify this project, so please give a fork or public deployment its own name.
