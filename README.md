# Vulnder

[![CI](https://github.com/fullymiddleaged/vulnder/actions/workflows/ci.yml/badge.svg)](https://github.com/fullymiddleaged/vulnder/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/fullymiddleaged/vulnder/badge)](https://scorecard.dev/viewer/?uri=github.com/fullymiddleaged/vulnder)

**CVE alerts for your stack, ranked by what to fix first.**

Describe what you run, drop in a lockfile or SBOM, or paste the CVE IDs from a scanner report. Vulnder shows the CVEs that affect it, in the order to fix them, with the reason for each. No account: your stack lives in the URL, and the same link gives an Atom feed and a README badge.

<!-- Screenshot: add docs/screenshot.png once the app is deployed. -->

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/fullymiddleaged/vulnder)

## What it does

- Takes your stack three ways: a description in your own words, a lockfile or SBOM, or a list of CVE IDs (pasted, or from a Nessus, Qualys, Tenable, Trivy or Grype report). Files are read in your browser. A CVE list is ranked whatever its age.
- Lets you check the stack before the results. A broad name like "Cisco switches" becomes several close matches, marked `?` and never hidden. Tick Edge device on anything the internet can reach (VPNs, firewalls and gateways are ticked for you) and Has ESU on a release you pay extended support for. A description that reads as an enterprise stack gives each item a team, which you can change.
- Shows the results: counts by priority, Fix first, out-of-support notices, what changed in the last 7 days, then every CVE, grouped by priority, by component or by team. Similar CVEs in one product fold under the highest-ranked one.
- Shares them: copy the page link, the Atom link or badge Markdown, or use Export for AI to save a Markdown file of every CVE with its priority, reasons and fix, for a coding agent (or a person) to work through.

## Ranking

Evidence of exploitation beats prediction (EPSS, NIST LEV), and prediction beats severity (CVSS).

| Priority | When | Respond |
|---|---|---|
| **Act now** | On CISA KEV, or CISA reports active exploitation. Before any exploitation is seen: a critical (CVSS 9.0+) with EPSS 10%+ or LEV 20%+, EPSS 50%+ at any severity, or an edge device bug CISA rates automatable with total technical impact | 24 hours if exploited, else 3 days |
| **Attend** | EPSS 10%+, LEV 20%+, CVSS 9.0+, a Metasploit exploit module, a similar CVE in the same product on KEV or actively exploited, public exploit code for a bug that is automatable or gives total control, an automatable or total-impact bug on an edge device, or CVSS 8.0+ and public for 60 days | 7 days |
| **Watch** | CVSS 8.0+, public proof-of-concept code, a bug CISA rates automatable (or, where CISA hasn't rated it, one with a Nuclei template), any bug CISA has assessed on an edge device, or CVSS 7.0+ and public for 60 days | 30 days |
| **Track** | Affects your stack, and nothing above applies | Next routine update |

Within a priority, a 0–100 risk score orders the results. It multiplies threat (1 for KEV, otherwise the higher of EPSS and LEV, with floors for criticals and public exploit code) by impact (CVSS ÷ 10), then by 1.25 if automatable, 1.25 on an edge device and 1.2 if used in ransomware. The score is a heuristic for ordering, not a probability. Fix first lists the components to upgrade: the most urgent priority first, then the highest total score, since one upgrade often closes several CVEs.

**Out of support** releases rank with Act now in Fix first whatever their CVEs (Windows 7 or 10, Windows Server 2012 R2, Ubuntu 18.04, an end-of-life router), since no more fixes will come; support ending within 90 days ranks with Attend. Only releases you name specifically count, never a broad "Windows". Paid extended support (ESU, ELS, LTSS) counts once you tick Has ESU.

Results cover the last 7, 30 or 90 days. CVEs from the last year that are on KEV, or have EPSS 10%+, LEV 20%+ or CVSS 9.9+, show whatever the window, marked Older. Every result says which signal decided it, what data was missing, and what to do. Full detail: [docs/RANKING.md](docs/RANKING.md).

## Feeds and badge

```
https://vulnder.com/?s=npm:next@14.2.3,pypi:fastapi,p:postgresql/postgresql@16
https://vulnder.com/feed.xml?s=…      Atom, one entry per change
https://vulnder.com/badge.svg?s=…     "N known-exploited CVEs", green at zero
https://vulnder.com/api/feed?s=…      JSON, for scripts and agents
```

The results page doesn't link the JSON feed, but it's the API the page loads, with the same priorities, scores, reasons and Fix first list ([fields](docs/RANKING.md#in-the-feeds)). `days` sets the window (1–90, default 30). A stack holds up to 200 components and 2,000 CVE IDs. The `s` format is a versioned public contract: [docs/STACK_FORMAT.md](docs/STACK_FORMAT.md).

## Privacy

A list of what you run is useful to an attacker, so Vulnder keeps as little as it can.

- **Nothing you enter is stored by Vulnder.** Free text goes to Workers AI only to pick out names; parses are cached under a hash of the text, never the text. On vulnder.com, only those free-text entries are logged, by Cloudflare's AI Gateway; self-hosters can turn that off (see [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md)).
- **Lockfiles, SBOMs, CVE lists and scan reports stay in your browser.** Only package names and versions, or CVE IDs, are sent.
- **Stack URLs aren't logged.** IPs are used only as rate-limit keys or a daily-salted hash, and there's no analytics.
- **Feed passes hold no stacks**, only keyed hashes, and are deleted after a day.
- **Not indexed.** Stack pages and feeds are `noindex`, and no `Referer` is sent.

Vulnder runs on Cloudflare, which sees every request, including the stack in the URL. If that's too much, self-host.

## Data

[CVE records](https://github.com/CVEProject/cvelistV5) with [CISA Vulnrichment](https://github.com/cisagov/vulnrichment), the [GitHub Advisory Database](https://github.com/advisories) (CC BY 4.0), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [EPSS](https://www.first.org/epss) (*scores courtesy of FIRST*), [OSV](https://osv.dev) for version checks, vendor support dates from [endoflife.date](https://endoflife.date) (MIT), and exploit availability from the [Metasploit](https://github.com/rapid7/metasploit-framework) module index (BSD-3-Clause) and [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) (MIT). CVEs published or changed in the last 90 days are kept, so an old CVE that lands on KEV today still shows up. Exploited, likely-exploited and CVSS 7.0+ CVEs are kept for a year, and a slim index of every CVE ID ranks pasted lists of any age.

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

See [CONTRIBUTING.md](CONTRIBUTING.md). New data sources and manifest parsers help most. Working with an AI coding agent? Point it at [AGENTS.md](AGENTS.md). A star helps other people find it.

## Licence

[Apache 2.0](LICENSE). Copyright 2026 Pete Salmond ([@fullymiddleaged](https://github.com/fullymiddleaged)). Keep the [NOTICE](NOTICE) file with any redistribution.

The licence covers the code, not the name. Please give a fork or public deployment its own name; [docs/FORKING.md](docs/FORKING.md) explains what a fork needs. Found a security problem? See [SECURITY.md](SECURITY.md). Pete Salmond is the maintainer and security contact.
