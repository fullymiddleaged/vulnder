# Vulnder

**CVE alerts for your stack, ranked by real-world exploitation.**

Describe what you run, or drop in a lockfile or SBOM. Vulnder shows the recent CVEs that affect it, in the order to fix them. No account: your stack lives in the URL, and the same link is a JSON feed, an Atom feed and a README badge.

<!-- Screenshot: add docs/screenshot.png once the app is deployed. -->

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/fullymiddleaged/vulnder)

## Ranking

Evidence of exploitation beats prediction, and prediction beats severity.

| Priority | Means | Respond |
|---|---|---|
| **Act now** | On CISA KEV, or CISA reports active exploitation | 24–48 hours |
| **Attend** | Likely to be exploited: high EPSS or LEV, a similar CVE exploited, or a critical bug reachable without a login | 7 days |
| **Watch** | Serious but less pressing: CVSS 8+, or a public proof of concept | 30 days |
| **Track** | Affects you, nothing urgent | Next routine update |

Every result says which signal decided it, what data was missing, and what to do. Scores only order results; they aren't probabilities. Vague names expand to close matches, which are labelled and never hidden. Full detail: [docs/RANKING.md](docs/RANKING.md).

## Feeds and badge

```
https://vulnder.com/?s=npm:next@14.2.3,pypi:fastapi,p:postgresql/postgresql@16
https://vulnder.com/api/feed?s=…      JSON
https://vulnder.com/feed.xml?s=…      Atom, one entry per change
https://vulnder.com/badge.svg?s=…     "N known-exploited CVEs", green at zero
```

`days` sets the window (1–90, default 30). Up to 200 items per stack. The `s` format is a versioned public contract: [docs/STACK_FORMAT.md](docs/STACK_FORMAT.md).

## Privacy

A list of what you run is useful to an attacker, so Vulnder keeps as little as it can.

- **Nothing you enter is stored.** Free text goes to Workers AI only to pick out names; parses are cached under a hash of the text, never the text.
- **Lockfiles stay in your browser.** Only package names and versions are sent.
- **Stack URLs aren't logged.** IPs are used only as rate-limit keys or a daily-salted hash, and there's no analytics.
- **Feed passes hold no stacks**, only keyed hashes, and are deleted after a day.
- **Not indexed.** Stack pages and feeds are `noindex`, and no `Referer` is sent.

Vulnder runs on Cloudflare, which sees every request, including the stack in the URL. If that's too much, self-host.

## Data

[CVE records](https://github.com/CVEProject/cvelistV5) with CISA's enrichment, the [GitHub Advisory Database](https://github.com/advisories) (CC BY 4.0), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [EPSS](https://www.first.org/epss) (*scores courtesy of FIRST*) and [OSV](https://osv.dev) for version checks. 90 days are kept; an old CVE that lands on KEV today still shows up.

## Self-hosting

Runs on Cloudflare Workers, D1 and Workers AI, including the free plan.

```sh
npm ci
cp .dev.vars.example .dev.vars
npm run db:migrate:local
npm run backfill      # last 90 days into local D1 (~2 GB clone)
npm run dev           # http://localhost:8787
```

Deploying, bindings and secrets: [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md). Design decisions: [docs/ENGINEERING.md](docs/ENGINEERING.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New data sources and manifest parsers help most. A star helps other people find it.

## Licence

[Apache 2.0](LICENSE). Copyright 2026 Pete Salmond ([@fullymiddleaged](https://github.com/fullymiddleaged)). Keep the [NOTICE](NOTICE) file with any redistribution.

The licence covers the code, not the name. Please give a fork or public deployment its own name; [AGENTS.md](AGENTS.md) explains what a fork needs.
