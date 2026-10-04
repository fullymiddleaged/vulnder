# Vulnture — pre-phase-1: verify brief, write docs/DESIGN.md

## Context
Greenfield repo (`C:\vscode\vulnture` is empty, not yet a git repo). The brief requires verifying seven external assumptions, recording the results and any brief changes in `docs/DESIGN.md`, and showing that doc before phase 1 starts. Verification is done (below). User decisions so far: **hybrid ingest** (same source code runs in the Worker cron on Workers Paid, or in a scheduled GitHub Actions job on the free plan) and **git init**.

## Steps on approval
1. `git init`, add `.gitignore` (node_modules, .wrangler, dist, .dev.vars, *.local).
2. Write `docs/DESIGN.md` with the content outlined below.
3. Commit `docs/` (BRIEF.md, plans/, DESIGN.md) and `.gitignore`: "Add brief and design notes from pre-build verification". Leave `.clawness/` out of the commit; add it to `.gitignore` unless the user wants it tracked.
4. Stop. Show DESIGN.md and wait for the phase 1 go-ahead. No other code.

## DESIGN.md content

### A. Confirmed facts (as of 2026-10-04, with source URLs)
| Item | Confirmed |
|---|---|
| Workers subrequests | Free 50/req; Paid 10,000 default (configurable up to 10M) |
| Workers CPU | Free 10 ms (HTTP and cron). Paid: HTTP 30 s default (up to 5 min); cron 30 s if interval <1 h, 15 min if ≥1 h |
| Cron triggers | Free 5/account; Paid 250. Cron wall clock 15 min. Memory 128 MB |
| D1 | DB size 500 MB free / 10 GB paid; 50 queries per invocation free / 1000 paid; 100 bound params per query; 100 KB statement; 2 MB row. Free 5M rows read and 100k rows written per day (hard stop when exceeded). FTS5 and JSON extensions available |
| Workers AI | 10,000 neurons/day free on both plans; Paid only beyond that ($0.011/1k neurons) |
| JSON mode | `response_format: {type:"json_schema", json_schema}`, not guaranteed, no streaming. The docs' supported-model list is stale: Llama 3/3.1 8B were deprecated on 30 May 2026 |
| cvelistV5 | `delta.json` = last commit only (~7 min). `deltaLog.json` = 30 days, 24 MB (measured). Releases: `YYYY-MM-DD_delta_CVEs_at_HHMMZ.zip` (cumulative since midnight UTC, 1–4 MB on weekdays) and `YYYY-MM-DD_all_CVEs_at_midnight.zip.zip` (~620 MB, zip in a zip). Tag hour and asset hour can differ. Measured volume: ~500 new and up to ~4,000 updated CVEs/day; 19k distinct changed CVEs in 30 days; CVE IDs now reach 6 digits |
| EPSS | `api.first.org/data/v1/epss`, BETA. `cve=` max 2000 chars (~110 IDs); `limit` 0–10,000, default 100. Envelope `status, status-code, version, access, total, offset, limit, data[]`; items `cve, epss, percentile, date`, **values are strings** |
| KEV | JSON `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, schema `…_schema.json`. 1,733 entries, 1.77 MB. Item fields: cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes, cwes, plus a new `forensicTriage` field |
| GitHub `/advisories` | Filters: ghsa_id, type (reviewed default / malware / unreviewed), cve_id, ecosystem, severity, cwes, is_withdrawn, affects, published, updated, modified, epss_*. sort: updated / published / epss_*. Cursor pagination (`after`/`before` via Link header), per_page ≤100. Ecosystems: rubygems, npm, pip, maven, nuget, composer, go, rust, erlang, actions, pub, swift, other. Rate limit 60/h unauthenticated, 5,000/h with a token. Responses carry an `epss` object |
| OSV querybatch | ≤1000 queries per batch; results have only `id` + `modified`; paginates per query past 1,000 per query or 3,000 total; no documented rate limit; 32 MiB response cap on HTTP/1.1 |
| GitHub Actions | Free for public repos on standard runners; schedule ≥5 min, often delayed at the top of the hour; disabled after 60 days without repo activity |

### B. Changes to the brief
1. **Hybrid ingest.** `src/ingest/sources/*` implement `fetchChanges(cursor)` against an injected `fetch`, using only Web APIs. A `Store` interface has two implementations: `D1BindingStore` (Worker cron, Paid) and `WranglerStore` (Node: generates SQL and runs `wrangler d1 execute --file`, `--local` or `--remote`). Backfill and the Actions job (`.github/workflows/ingest.yml`, hourly at :17) use `WranglerStore`. The `INGEST_RUNTIME` var picks the mode, and the free-plan wrangler config has no cron trigger. A budget object (subrequests, elapsed time) makes each run stop cleanly and save its cursor, so both runtimes resume the same way. `/api/health` reports staleness, which covers the 60-day Actions disable.
2. **CVE source uses the hourly release delta zip, not `delta.json`.** Polling `delta.json` hourly would miss most changes. Find the zips through the releases API, never by building the name. Process the previous day's final zip at day rollover. Skip records whose `dateUpdated` ≤ cursor. If ingest falls behind past release retention, the Node path falls back to `deltaLog.json` (30 days), or past that to a re-backfill. The CVE ID regex allows 4+ digits.
3. **Retention defined by activity.** Keep a vuln if it was published in the last 90 days or has any event in the last 90 days. An old CVE that lands on KEV this week still appears. Prune whatever falls outside.
4. **Manifest parsing runs in the browser.** The shared TS parsers run client-side, and only the extracted `{ecosystem,name,version}` candidates go to the server. A lockfile never leaves the user's machine, and it avoids the 10 ms free-plan request CPU limit. `/api/resolve` accepts `{text}` (model path) or `{candidates}` (manifest path). Server-side tests still cover every parser.
5. **Model.** Default `@cf/google/gemma-4-26b-a4b-it` (a deprecation-notice replacement, with `json_schema` + strict in its input schema, $0.10/$0.30 per M tokens). Estimate ~17 neurons per parse, or ~500 parses/day free. Fallback `@cf/meta/llama-3.3-70b-instruct-fp8-fast` (on the JSON-mode list, ~5× the cost, 24k context). Model ID lives in config. Output is validated with zod and discarded if invalid. When the quota runs out, the UI falls back to "add items manually or paste a manifest". Neuron estimates get re-measured from a recorded response in phase 3.
6. **EPSS refresh.** Once per day, after the score `date` advances, batch the in-window CVE IDs (~110 per call, `limit=1000`, ~400 calls/day spread across runs). Write only on crossing or meaningful change, to stay under 100k rows written/day. EPSS can't run at all within the free 50-subrequest Worker budget, which also points to the hybrid design.
7. **KEV** uses a conditional GET (ETag/Last-Modified) and skips unchanged files.
8. **GitHub advisories**: `type=reviewed`, `sort=updated`, `modified>=cursor`, Link-header cursor. Optional `GITHUB_TOKEN` secret, recommended because Workers egress IPs are shared. An ecosystem map converts GitHub names to OSV names (pip→PyPI, rust→crates.io, composer→Packagist, erlang→Hex, …).
9. **OSV** returns all-time IDs, which may be PYSEC-/GO-/RUSTSEC- IDs. Intersect them with D1 ids and aliases. For an unknown ID, call `GET /v1/vulns/{id}` for its aliases, bounded by the budget and cached. Cache results by (ecosystem, name, version) in the Cache API.
10. **D1 query shape.** Pass lists as one JSON param through `json_each()` (100-param cap). Batch statements, because the free plan allows 50 queries per invocation. Index everything filtered on, because rows read count scanned rows.
11. **Rate limiting.** The binding only allows periods of 10 or 60 s and is eventually consistent. The docs advise against IP keys, but an anonymous endpoint has nothing else, so use a generous IP-keyed limit (never logged) with Turnstile as the primary gate.

### C. Open items to verify in later phases
- D1 FTS5 trigram tokenizer support, and whether `wrangler d1 export` handles virtual tables (phase 3, catalog fuzzy matching).
- Whether Gemma 4's reasoning output can be disabled or capped, and the real token use per parse (phase 3).
- EPSS attribution wording (phase 5). GitHub API version header: 2022-11-28 vs 2026-03-10 (phase 1).
- Current versions of hono, wrangler, vitest, @cloudflare/vitest-pool-workers, zod and fflate, checked before installing (phase 1).

## Verification
- DESIGN.md renders and every confirmed row cites its source URL.
- `git log` shows one commit, containing only `docs/` and `.gitignore`.
