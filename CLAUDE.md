# Vulnder

A stack-aware CVE feed on Cloudflare Workers. Someone describes what they run (free text, a pasted manifest, or items added by hand); Vulnder resolves that to stack items and shows which recent CVEs affect them, ranked by what to fix first. The stack lives in the URL (`?s=`, see docs/STACK_FORMAT.md), so results, the JSON feed, the Atom feed and the badge are all shareable links. Design history: docs/BRIEF.md, docs/ENGINEERING.md. Visual design: PRODUCT.md and DESIGN.md at the root (Impeccable skill).

## Principles (don't undo these)

- **Privacy:** user text and stacks are never stored or logged. Parses are cached under a hash of the normalised text; IPs are only rate-limit keys or a daily-salted hash. Feed passes (`src/lib/pass.ts`) hold a random id and keyed hashes of stacks, never stacks, and are deleted after a day. Manifests are parsed in the browser.
- **Evidence beats severity:** exploitation evidence (CISA KEV, SSVC "active") always outranks prediction (EPSS) and severity (CVSS). Every priority shows its reasons; scores are heuristics for ordering, not probabilities.
- **AI only extracts and judges; code decides.** Models never rank CVEs or hide matches. Their output is schema-validated, grounded against the user's text, and treated as untrusted.
- **Never hide a match.** Vague names expand to close matches (marked `?` in the stack); ranking only reorders them.
- **Free-plan first:** it must run on Workers Free (10 ms CPU, 50 subrequests, 10,000 neurons a day). Ingest runs from GitHub Actions there, or from the cron on Paid.

## How it works

- `src/ingest/`: pulls CVE records (with CISA Vulnrichment SSVC), GitHub advisories, KEV and EPSS into D1. `scripts/` runs it from Node via Wrangler. New deployments are seeded from a local backfill with `scripts/seed-remote.ts` (dev machine only; resumable under a daily row budget); a `seeding` meta row pauses ingest until it finishes. `families.ts` then embeds each new CVE's title once (Workers AI, `EMBED_MODEL`, CVE text only, daily token cap) and groups similar CVEs per product against family leaders; code decides at the calibrated `FAMILY_SIM`.
- `src/resolve/`: turns input into stack items. `extract.ts` asks Workers AI (`AI_MODEL`) to list named components; `catalog.ts` resolves names against the catalog (aliases, categories, fuzzy match); `injection.ts` is a free phrase screen; `jev.ts` and `profile.ts` screen the text and order close matches by fit (below).
- `src/match/`: `match.ts` matches a stack to CVEs (OSV confirms package versions) from per-component data that `components.ts` loads and the feed routes cache by data version; `priority.ts` assigns Act/Attend/Watch/Track, a 0–100 score and reasons, plus the per-component "Fix first" list.
- `src/routes/`: `POST /api/resolve` (Turnstile, per-IP limit, daily model caps in `src/lib/quota.ts`); `GET /api/feed`, `/feed.xml`, `/badge.svg` (cached by data version; cache misses rate-limited).
- `web/`: the front end, bundled to `public/app.js` by `npm run build:web`.

## Jev (TypeSafe's decision model on Workers AI, `typesafe/jev`)

Runs **at request time, on the user's own text only**, never as a batch job over the catalog. Two calls per uncached parse: a screen before extraction (injection noul, blocked at `INJECTION_BLOCK`; scale and hosting choices), then one judge call after resolving, with a fit noul per close match (only when the profile is clear) and an exposure noul per named component. Fixed logic acts on the answers: fit reorders close matches, and exposure at `EXPOSED_AT` or above adds the `!` internet-facing mark. Edge products by role (`EDGE_PRODUCTS` in aliases.ts) get the mark without Jev and are left out of its questions; with nothing left to ask, the judge call is skipped. Both calls fail open. Jev is billed in AI Gateway credits, not neurons: without credits every call fails with "2021: Insufficient AI Gateway credits", and parsing carries on without it.

## Working here

- `npm test` (vitest in workerd), `npm run typecheck`, `npm run lint`, `npm run dev` (port 8787). Run all three checks before calling work done.
- The user deploys through GitHub; never deploy. Commit only when asked, one commit per feature.
- `wrangler.jsonc` keeps the placeholder `database_id`; never commit the real one. Local D1 is keyed by the placeholder. Commands that reach Cloudflare use the git-ignored `wrangler.production.jsonc`, stamped from `D1_DATABASE_ID` (in `.env` locally) by `scripts/lib/production-config.ts`.
- Edit files with the editor tools, not Python/Node scripts that write files: on Windows those can turn LF into CRLF or mangle escapes.
- Licence, NOTICE and the name in forks: AGENTS.md. Never remove LICENSE, NOTICE or copyright lines.
- Hostile input is a given: anything reaching `parseStack`, the alias tables or the model must be fuzz-safe (`test/resolve-fuzz.test.ts`). Look up input-keyed tables with `ownValue()`.
