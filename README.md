# Vulnder

[![CI](https://github.com/fullymiddleaged/vulnder/actions/workflows/ci.yml/badge.svg)](https://github.com/fullymiddleaged/vulnder/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/fullymiddleaged/vulnder/badge)](https://scorecard.dev/viewer/?uri=github.com/fullymiddleaged/vulnder)

**CVE alerts for your hardware and software, ranked by what to fix first.**

This is a Cloudflare Worker and D1 database designed to help with the sheer number of CVEs generated today. Give it a description of your stack, a lockfile, or an SBOM or scanner report. It then ranks every matching CVE by evidence of exploitation and other factors beyond CVSS, and says why. No account needed. Or fork this repo and host yourself on your own worker.

<!-- Screenshot: add docs/screenshot.png once the app is deployed. -->

## What it does

- **Reads your stack** from a description, a lockfile, SBOM or MCP config, or a list of CVE IDs (pasted, or from a Nessus, Qualys, Tenable, Trivy or Grype report). Files are read in your browser.
- **Lets you check it first.** Broad names like "Cisco switches" become close matches, marked `?` and never hidden. You can mark edge devices and paid extended support.
- **Shows the results:** which components to fix first, every CVE by priority, component or team, and what changed in the last 7 days.
- **Shares them** as a link, Atom feed, badge or Markdown file for a coding agent.

## Ranking

Evidence of exploitation beats prediction (EPSS, NIST LEV), and prediction beats severity (CVSS).

| Priority | Main rules | Respond |
|---|---|---|
| **Act now** | On CISA KEV, or CISA reports active exploitation. Before any exploitation is seen: EPSS 50%+, a critical with EPSS 10%+ or LEV 20%+, or a critical that trusted security teams are warning about | 24 hours if exploited, else 3 days |
| **Attend** | EPSS 10%+ or LEV 20%+, CVSS 9.0+, a Metasploit exploit module, or a similar CVE in the same product on KEV or actively exploited | 7 days |
| **Watch** | CVSS 8.0+, public proof-of-concept code, or a bug CISA rates automatable | 30 days |
| **Track** | Affects your stack, and nothing above applies | Next routine update |

- A 0–100 score orders results within a priority. It's a heuristic, not a probability.
- **Fix first** lists the components to upgrade, most urgent first, since one upgrade often closes several CVEs.
- **Out of support** releases you name rank with Act now in Fix first, whatever their CVEs. Support ending within 90 days ranks with Attend.
- Results cover the last 7, 30 or 90 days. CVEs from the last year on KEV, or with EPSS 10%+, LEV 20%+ or CVSS 9.9+, show whatever the window, marked Older.

All the rules, including edge devices: [docs/RANKING.md](docs/RANKING.md).

## Feeds, badge and MCP

```
https://vulnder.com/?s=npm:next@14.2.3,pypi:fastapi,p:postgresql/postgresql@16
https://vulnder.com/feed.xml?s=…      Atom, one entry per change
https://vulnder.com/badge.svg?s=…     "N known-exploited CVEs", green at zero
https://vulnder.com/api/feed?s=…      JSON, for scripts and agents
https://vulnder.com/mcp               MCP server for AI agents
https://vulnder.com/api/v1/stack      POST: names and versions in, a stack out
https://vulnder.com/api/v1/rank       POST: a stack or CVE IDs in, flat rows out
```

`days` sets the window (1–90, default 30). A stack holds up to 200 components and 2,000 CVE IDs.

- [Stack link format](docs/STACK_FORMAT.md) (a versioned public contract)
- [JSON feed fields](docs/RANKING.md#in-the-feeds)
- [`/api/v1/` for scheduled runners and SIEMs](docs/API.md)
- [Microsoft Sentinel and Defender template](docs/AZURE.md)

## Use it with AI agents

No account or key. In Claude Code:

```sh
claude mcp add --transport http vulnder https://vulnder.com/mcp
```

Then ask: "We run FortiGate firewalls and Postgres 16: what should we patch first?" Other clients: [docs/AI_AGENTS.md](docs/AI_AGENTS.md). Agents without MCP can read [llms.txt](https://vulnder.com/llms.txt).

To check your agent's own MCP servers, drop `.mcp.json`, `mcp.json` or `claude_desktop_config.json` on the home page.

Advisory text in results is third-party data, never instructions.

In the EU? [docs/NIS2.md](docs/NIS2.md) maps Vulnder to NIS2 and the CRA, with a [weekly review routine](docs/agents/nis2-weekly-review.md) for your agent.

## Privacy

- **Nothing you enter is stored by Vulnder.** Free text goes to Workers AI only to pick out names; parses are cached under a hash of the text, never the text. On vulnder.com, only those free-text entries are logged, by Cloudflare's AI Gateway; self-hosters can turn that off (see [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md)).
- **Lockfiles, SBOMs, MCP configs, CVE lists and scan reports stay in your browser.** Only package names and versions, or CVE IDs, are sent. An MCP config's `env` and headers are never read.
- **MCP and `/api/v1/` requests aren't logged or stored.** The stack travels in the request body, and neither calls a model.
- **Stack URLs aren't logged.** IPs are used only as rate-limit keys or a daily-salted hash, and there's no analytics.
- **Feed passes hold no stacks**, only keyed hashes, and are deleted after a day.
- **Not indexed.** Stack pages and feeds are `noindex`, and no `Referer` is sent.

Vulnder runs on Cloudflare, which sees every request, including the stack in the URL. If that's too much, self-host.

## Data

- **CVEs:** [CVE records](https://github.com/CVEProject/cvelistV5) with [CISA Vulnrichment](https://github.com/cisagov/vulnrichment), [GitHub Advisory Database](https://github.com/advisories) (CC BY 4.0)
- **Exploitation and prediction:** [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [EPSS](https://www.first.org/epss) (*scores courtesy of FIRST*)
- **Version checks:** [OSV](https://osv.dev)
- **Support dates:** [endoflife.date](https://endoflife.date) (MIT)
- **Exploit availability:** [Metasploit](https://github.com/rapid7/metasploit-framework) module index (BSD-3-Clause), [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) (MIT)
- **Security team write-ups:** RSS feeds from [Huntress](https://www.huntress.com/blog), [Rapid7](https://www.rapid7.com/blog/), [watchTowr](https://labs.watchtowr.com/), [CERT-EU](https://cert.europa.eu/publications/security-advisories) and [NCSC UK](https://www.ncsc.gov.uk/)

Vulnder keeps CVEs published or changed in the last 90 days. It keeps those CISA reports exploited, those likely to be exploited, and CVSS 7.0+ for a year. A slim index of every CVE ID ranks pasted lists of any age.

## Self-hosting

Runs on Cloudflare Workers, D1 and Workers AI, including the free plan.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/fullymiddleaged/vulnder)

```sh
npm ci
cp .dev.vars.example .dev.vars
npm run db:migrate:local
npm run backfill      # last 90 days into local D1 (~2 GB clone)
npm run dev           # http://localhost:8787
```

Deploying, bindings and secrets: [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md). Design decisions: [docs/ENGINEERING.md](docs/ENGINEERING.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New data sources and manifest parsers help most. Using an AI coding agent? Point it at [AGENTS.md](AGENTS.md). A star helps other people find it.

## Licence

[Apache 2.0](LICENSE). Copyright 2026 Pete Salmond ([@fullymiddleaged](https://github.com/fullymiddleaged)). Keep the [NOTICE](NOTICE) file with any redistribution.

The licence covers the code, not the name. Please give a fork or public deployment its own name; [docs/FORKING.md](docs/FORKING.md) explains what a fork needs. Found a security problem? See [SECURITY.md](SECURITY.md). Pete Salmond is the maintainer and security contact.
