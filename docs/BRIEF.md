# Build brief: Vulnture, a stack-aware CVE feed on Cloudflare

Name: **Vulnture** (vulnerability + vulture). Repo and Worker name `vulnture`; the hosted instance will live at `vulnture.dev`.

Keep the display name and the public base URL in config, not hard-coded, because self-hosters will run it on their own domain. Feed links, badge links, and Atom IDs must all be built from the configured base URL.

Branding: a light touch on the vulture theme (something is circling your stack) is welcome in the logo, empty states, and tagline. Keep the results themselves plain and factual; no jokes in severity or tier wording.

## What we are building

An open-source web app, hosted on Cloudflare, where someone describes their tech stack in a free-text box (or pastes a manifest file) and immediately sees the vulnerabilities from the last 30 days that are relevant to them, ranked by real-world exploitation signals rather than CVSS labels. No accounts. The confirmed stack is encoded in the URL, and the same URL serves a JSON feed, an Atom feed, and a README badge.

The point of the product is signal over noise. Existing tools require sign-up and configuration, then show everything. This one should give a useful, trustworthy answer in about ten seconds and be honest about how confident each match is.

## Before writing code

Several details below come from memory and may be out of date. Verify these against current official docs first, and tell me about anything that differs before you design around it:

1. Cloudflare Workers limits on the free and paid plans: subrequests per invocation, CPU time, number of cron triggers, D1 size and row limits, Workers AI free allowance.
2. The current recommended Workers AI model for structured JSON extraction, and whether it supports JSON mode / schema-constrained output.
3. The cvelistV5 repo layout: `cves/delta.json`, `cves/deltaLog.json`, how far back `deltaLog.json` reaches, and the release zip naming.
4. The EPSS API (`api.first.org/data/v1/epss`): batch size limit per request, and the fields returned.
5. The CISA KEV JSON feed URL and schema.
6. The GitHub global advisories REST endpoint (`GET /advisories`): filter parameters, pagination, and unauthenticated vs token rate limits.
7. OSV API `POST /v1/querybatch`: batch limits and the response shape.

Then write a short `docs/DESIGN.md` recording what you confirmed and any changes to this brief, and show it to me before starting phase 1.

## Stack

- TypeScript on Cloudflare Workers, deployed with Wrangler. One Worker serves the API, the feeds, and the static front end (Workers static assets).
- Hono for routing.
- D1 for storage, with SQL migrations checked in.
- Cron Triggers for ingest.
- Workers AI for free-text parsing only.
- Turnstile and the Workers rate-limiting binding on the parse endpoint.
- Vitest with the Cloudflare Workers test pool. Recorded fixtures for every external source; tests never hit the network.
- Front end: keep it light. Plain TypeScript with a small bundler step, or Preact if it earns its place. No heavy framework.

## Data sources and what each is for

| Source | Used for | When |
|---|---|---|
| MITRE cvelistV5 (deltas) | Every new or changed CVE record, including the CISA ADP container (vendor/product, SSVC, CVSS where present) | Cron, incremental |
| GitHub Advisory Database (REST) | Package-level data: ecosystem, package name, vulnerable ranges, first patched version | Cron, incremental by modified date |
| CISA KEV | Confirmed exploitation, date added, ransomware flag, due date | Cron, fetch whole file |
| FIRST EPSS | Exploitation probability and percentile | Cron, for CVEs in the retention window |
| OSV `querybatch` | Exact version checks when the user supplied versions | Request time, cached |

Retain 90 days of data in D1; the UI defaults to 30 days.

## Ingest

- A scheduled handler runs hourly. Each source is its own module with a common interface (`fetchChanges(cursor) -> { records, nextCursor }`), so sources can be added or fixed independently.
- Every source keeps a cursor in a `meta` table. A run must be resumable: if it hits the subrequest or CPU budget it saves the cursor and stops cleanly, and the next run continues. Design this for the free-plan limits you confirmed, so the project is deployable at zero cost.
- Normalise everything to one record per vulnerability, keyed by CVE ID where one exists, with GHSA IDs and other identifiers stored as aliases. Merge, do not duplicate, when a GHSA and a CVE describe the same issue.
- Prune records older than 90 days on a daily run.
- Backfill is a separate local script (`npm run backfill`), not a Worker. It should populate the last 90 days from a shallow clone of cvelistV5 plus the advisory API, and load D1 through Wrangler. It must work against both local and remote D1.

### Change events

The most valuable output is what changed, so record events as ingest detects them:

- `published`: new vulnerability in the window.
- `kev_added`: appeared on KEV.
- `epss_crossed`: EPSS crossed the high threshold (0.10) upward, or rose by 0.10 or more since last recorded.
- `fix_released`: a patched version appeared where there was none.

## Schema (starting point, refine as needed)

- `vulns`: id, aliases (JSON), title, summary, published_at, modified_at, cvss_score, cvss_vector, cwe, epss, epss_percentile, kev_added_at, kev_ransomware, references (JSON), source_flags.
- `affected`: vuln_id, kind (`package` or `product`), ecosystem, package_name, vendor, product, ranges (JSON), fixed_version. Indexed for lookup by (ecosystem, package_name) and (vendor, product).
- `events`: vuln_id, type, occurred_at, detail (JSON).
- `catalog`: every distinct package and vendor/product seen, with a normalised name, known aliases, and a count. Used to resolve free text.
- `meta`: cursors, last successful run per source, data version counter.

## Stack resolution (the core feature)

Free text must resolve to real identifiers. Never match free text against CVE descriptions.

Flow:

1. User submits text such as "Next.js on Vercel, Postgres 16, Redis, nginx, a couple of Cisco switches", or pastes a file.
2. If the input parses as a known manifest, handle it deterministically with no model call. Support `package.json`, `package-lock.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `pom.xml`, `Gemfile.lock`, `composer.json`, Dockerfile `FROM` lines, and CycloneDX / SPDX JSON.
3. Otherwise call Workers AI with a strict JSON schema. The model's only job is to extract candidate items: a name, an optional version, and a guess at type (package with ecosystem, or vendor/product). It must not judge relevance or severity.
4. Match candidates against `catalog` using normalisation, aliases, and fuzzy matching. Return each as a chip with a status: resolved, ambiguous (offer the alternatives), or unrecognised.
5. The UI shows the chips. The user can remove, correct, or add items. Only the confirmed set is used for matching.
6. An item with no vulnerabilities in the window is still kept and shown as "watching, nothing in the last 30 days", so the feed picks up future issues.

Treat the pasted text as untrusted input to the model: fixed system prompt, schema-validated output, discard anything that does not validate, cap input length.

Cache parse results by a hash of the normalised input so repeat submissions cost nothing.

## The stack URL

- The confirmed stack is serialised into a compact, human-readable query parameter, for example `?s=npm:next@14.2.3,pypi:fastapi,p:postgresql/postgresql@16,p:cisco/ios_xe`. Fall back to a compressed base64url form when it gets long. Cap at 200 items and tell the user to self-host beyond that.
- The format is versioned and documented in `docs/STACK_FORMAT.md`, since it is a public contract once people bookmark feeds.

## Matching and confidence

Every result carries one of two confidence labels, and the UI must show it plainly:

- **Version confirmed**: the user supplied a version and it falls inside an affected range. For packages, use OSV `querybatch` rather than implementing range logic per ecosystem.
- **Product match**: the product is named as affected but the version is unknown or could not be checked.

## Tiers

- **Exploited**: on CISA KEV. Always shown first.
- **Likely**: EPSS at or above 0.10.
- **Backlog**: matched, with neither signal.

Wording rule: EPSS is a predicted probability of exploitation in the next 30 days. Never describe an EPSS score as "weaponised" or "exploited". Only KEV earns that language. Show CVSS as secondary information, not as the sort key.

## Routes

- `GET /`: the app.
- `POST /api/resolve`: text or file in, chips out. Turnstile and rate limiting apply here.
- `GET /api/feed?s=...&days=30`: JSON. Contains a `changes` section (events in the last 7 days for this stack) and the full tiered list.
- `GET /feed.xml?s=...`: Atom. One entry per event, so feed readers surface tier changes, not just new CVEs.
- `GET /badge.svg?s=...`: "N known-exploited CVEs" badge, green at zero.
- `GET /api/health`: last successful ingest per source.

Cache feed responses with the Cache API, keyed on the canonicalised stack plus the data version counter, so they invalidate when ingest writes.

## Front end

- First screen is the text box, a drop zone for files, and two or three example stacks to click. Nothing else.
- After confirm: "What changed this week" at the top, then the tiered list. Each item shows the ID, the matched component, the tier with its evidence (KEV date or EPSS percentage), the confidence label, the fixed version if there is one, and links to the advisory and patch, not to a bare NVD page.
- Buttons to copy the page link, the Atom link, the JSON link, and the badge markdown.
- A footer showing data freshness per source, taken from the health endpoint.
- Accessible, works on mobile, light and dark themes, no tracking scripts.

## Privacy

A stack list is useful to an attacker, so:

- Do not store submitted stacks or free text. The parse cache is keyed by hash and stores only the parsed output.
- Do not log the `s` parameter or request bodies in Worker logs.
- State this on the page and in the README, and be accurate about what Cloudflare itself can see as the host. Do not overclaim.

## Open-source packaging

- MIT licence.
- README: what it is, a screenshot, a "Deploy to Cloudflare" button, local development steps, the stack URL format, data source attribution (EPSS requires it), and the privacy statement.
- `CONTRIBUTING.md` explaining how to add a data source and how to add a manifest parser, since those are the likely contributions.
- GitHub Actions: lint, typecheck, and tests on every pull request.
- No secrets in the repo. Document every binding and secret in `wrangler` config comments and the README.

## Not in version 1

- Accounts, saved stacks, or email.
- Push webhooks to Slack, Teams, or Jira. People can point an RSS integration at the Atom feed. Leave a clear seam for adding this later.
- Reachability analysis.
- Container image or OS package scanning beyond naming the base image.

## Phases

Stop at the end of each phase, show me what works, and wait for a go-ahead.

1. **Skeleton and ingest.** Repo, Wrangler config, D1 migrations, the four cron sources with fixtures and tests, the backfill script, `/api/health`. Done when a local run populates D1 and the tests pass.
2. **Matching and feeds.** Stack URL format, matching, tiers, events, `/api/feed`, `/feed.xml`, `/badge.svg`, caching. Done when a hand-written stack URL returns correct tiered results against fixture data.
3. **Resolution.** Manifest parsers, Workers AI extraction, catalog matching, `/api/resolve`, Turnstile and rate limiting. Done when the example inputs resolve to the expected chips in tests, with the model call mocked.
4. **Front end.** The full flow from text box to results.
5. **Packaging.** README, deploy button, CI, licence, contribution guide.

## Working rules

- Do not deploy to Cloudflare or create remote resources without asking me first. Everything should run locally with `wrangler dev` and local D1 until then.
- Ask me when you need an account ID, API token, or Turnstile keys.
- Attaching the `vulnture.dev` custom domain is a deploy step for me to approve; do not assume the domain is already set up in the Cloudflare account.
- Prefer small, reviewable commits with clear messages.
- When something external does not behave as this brief assumes, stop and tell me rather than working around it silently.
