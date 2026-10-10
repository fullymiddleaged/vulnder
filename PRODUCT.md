# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- **Small-team ops and security owners:** the person who owns patching at a company with no security team or paid scanner. They need to know what to fix first this week and whether anything in their stack is being actively exploited.
- **Security professionals:** analysts who want a fast triage view and will check the reasons, data sources and confidence behind every ranking.
- **Solo developers and maintainers:** someone checking their own projects or an open-source repo, often by dropping in a lockfile or adding a README badge.

All three arrive with a stack in mind and want an answer in seconds, not a dashboard to configure.

## Product Purpose

Vulnder answers two questions about a stack: which new CVEs affect it, and which of those anyone is exploiting. The user describes what they run (a sentence, a pasted manifest, a lockfile or SBOM, or items added by hand), confirms the resolved stack, and gets recent CVEs ranked by what to fix first, with the reasons shown. Success is a trustworthy, ordered answer in about ten seconds, with no account.

## Positioning

Ranks by evidence of exploitation (CISA KEV, SSVC "active") ahead of prediction (EPSS, LEV) ahead of severity (CVSS), and shows which signal decided each place. No account, nothing stored: the stack lives in the URL, and the same link is the results page, a JSON feed, an Atom feed and a README badge. AI only reads the user's description; code does the ranking and every rule can be read.

## Operating Context

- Entry points: the home page stack builder, a shared stack link, a README badge click, or a feed reader following the Atom feed.
- Inputs: free text (parsed by Workers AI behind Turnstile), manifests and lockfiles/SBOMs read in the browser, and manual items.
- Output: priority tiers Act / Attend / Watch / Track, a 0–100 ordering score, reasons, a per-component "Fix first" list, close-match (`?`) marks in the stack, and a `;team` per item for enterprise stacks.
- Secondary pages: About, How it works (including use with AI agents).
- The same stack URL is consumed by coding agents through the JSON feed and llms.txt, so the visible results and the feed must say the same thing.

## Capabilities and Constraints

- Plain TypeScript front end (`web/`) bundled to `public/app.js`, one stylesheet `public/styles.css`, static HTML pages in `public/`. No framework; keep it light.
- Served from a Cloudflare Worker; must still work on Workers Free limits.
- Never hide a match: vague names expand to close matches and ranking only reorders them.
- Scores are heuristics for ordering, not probabilities, and must not be presented as such.
- Privacy: Vulnder never stores or logs user text or stacks (Cloudflare AI Gateway can log the model requests, and the privacy copy says so); manifests never leave the browser. No analytics or tracking scripts.
- The feeds, badge and stack format (docs/STACK_FORMAT.md) are public contracts; UI changes must not change what they encode.
- Display name and base URL are configurable for self-hosters.

## Brand Commitments

- Name: Vulnder. The brand is about vulnerabilities (bugs, CVEs, scanning), never vultures.
- Logo: a playful Tinder nod (heart, match) combined with a bug or scanner image.
- Type: Atkinson Next and Atkinson Mono.
- Playfulness lives in the logo, tagline and empty states only. Tiers, scores, reasons and anything describing a vulnerability stay plain and factual.
- British spelling in copy.

## Evidence on Hand

- Data sources credited in the footer: CVE records (MITRE cvelistV5), GitHub Advisory Database, CISA KEV, EPSS (FIRST), OSV.
- About page cites published sources for CVE volume and exploitation trends.
- Open source under Apache 2.0; author Pete Salmond (@fullymiddleaged).
- No testimonials, user counts, customer logos or benchmarks exist. Do not invent them.

## Product Principles

1. Evidence beats severity: exploitation evidence always outranks prediction, which outranks severity.
2. Show the reasons: every priority says which signal decided it, what else counted and what data was missing.
3. Never hide a match: be honest about confidence instead of filtering.
4. Keep nothing: privacy is a feature, stated plainly.
5. Fast and free: an answer in seconds, no account, nothing to install.
6. Easy for every level: a solo dev and a seasoned analyst get the same answer, and neither needs security jargon or special tooling to use it. As a new tool, Vulnder should look distinct, not like the rest of the category.

## Accessibility & Inclusion

WCAG 2.2 AA across all pages, including the results view, stack builder and dialogs.
