# Changelog

Notable changes to Vulnder. Versions follow [semantic versioning](https://semver.org/). The public contracts are the stack link format (`?s=`, [docs/STACK_FORMAT.md](docs/STACK_FORMAT.md)), the JSON feed's fields, the Atom feed, the badge, the MCP tools and `/api/v1/`. A change that breaks any of them gets a new major version, and its entry says what to do.

## [Unreleased]

## [1.0.1] - 2026-11-20

### Fixed

- A product named with its vendor now finds the vendor's products whose names repeat the vendor. "VirtualBox" from Oracle reaches Oracle VM VirtualBox and "WebLogic" Oracle WebLogic Server, as close matches; before, only names starting the same way were searched.
- A package with no advisories of its own now also brings in the product of the same name as a close match, when CVEs are filed there instead. "Ultralytics" found nothing before, because its CVEs are under the product, not the PyPI package.
- "Java", "JDK", "JRE" and "OpenJDK" resolve to Oracle Java SE, which holds Java SE and OpenJDK CVEs such as Java4Shell (CVE-2026-114938).
- Fix first leads each item with the CVE whose fix is newest among its most urgent ones, so the first fixed version you see is the upgrade that closes the rest. A bug fixed in nginx 1.30.1 no longer leads one fixed in 1.30.7 from the same band.

## [1.0.0] - 2026-11-17

The first release. Vulnder takes what you run, as a description, a manifest or a list of CVE IDs, and ranks the CVEs that affect it by what to fix first, saying why for each one. It runs on Cloudflare Workers, D1 and Workers AI, including the free plan, and [vulnder.com](https://vulnder.com) runs this code.

### Ways in

- Describe your stack in up to 500 characters. A Workers AI model picks out the products and versions, and code matches them to the CVE catalog. If the model hasn't answered within 8 seconds, or fails, a second one is asked too and the first answer wins.
- Drop or paste a manifest: `package.json` and `package-lock.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `pom.xml`, `Gemfile.lock`, `composer.json`, a Dockerfile, a CycloneDX or SPDX SBOM, or an MCP client config (`.mcp.json`, `mcp.json`, `claude_desktop_config.json`). It's read in your browser, up to 10 MB, and the first 5,000 entries are checked, direct dependencies first.
- Rank a list of CVE IDs on the By CVE list tab, pasted or dropped from a Nessus, Qualys, Tenable, Trivy or Grype report. Up to 2,000 IDs, of any age. Rejected duplicates are ranked by their replacement, and IDs that aren't published CVEs are listed for you to check.
- Check the stack before you search. Broad names ("Cisco switches", "Windows") expand to close matches, marked `?` and never hidden, while a named version resolves exactly. Under Edit stack you can remove what isn't yours, add what's missing, change teams, and mark edge devices and paid extended support.
- Common acronyms and everyday names resolve (RHEL, IIS, M365, AnyConnect, Entra ID), as do AI runtimes and coding agents. A Linux distribution brings its kernel, at the series its release ships when you name one.

### Ranking

- Four priorities, each with a window to respond in: Act now (24 hours, or 3 days before any exploitation is seen), Attend (7 days), Watch (30 days) and Track (your next routine update). The full rules are in [docs/RANKING.md](docs/RANKING.md).
- Exploitation evidence comes first: a CVE on CISA KEV, or one CISA reports as actively exploited, is Act now at any severity. Predictions come next (EPSS, a predicted probability of exploitation, and NIST LEV), then severity (CVSS) and how an attacker reaches the bug.
- A critical CVE that the security teams at Huntress, Rapid7, watchTowr, CERT-EU or NCSC UK are warning about ranks Act now before EPSS and CISA catch up. A write-up never counts as exploitation.
- Public exploit code (an exploit reference on the CVE record, a Metasploit module or a Nuclei template) raises a CVE to Watch or Attend.
- Edge devices (VPNs, firewalls, gateways) rank ahead within their priority and get CISA BOD 26-04's shorter windows. Similar CVEs in one product are grouped, and one on KEV or reported actively exploited lifts the rest. High-severity bugs left unfixed for 60 days move up.
- Releases out of vendor support (from endoflife.date) rank with Act now in Fix first, unless you've marked extended support. Products with a CISA KEV addition in the last 90 days are flagged as targeted by attackers.
- CVE records' affected and fixed versions are applied: a version you name rules out what a record says it isn't affected by, and the fix shown is the one on your release branch.
- Whatever window you pick (7, 30 or 90 days), CVEs from the last year that are on KEV, have EPSS 10% or more, LEV 20% or more, or CVSS 9.9 or more still show, marked Older.
- Every result says which signal decided its priority, what data was missing, and what to do: upgrade to the fixed version, or CISA's required action and the advisory when there's no fix yet. A 0–100 score orders results within a priority. It's a heuristic, not a probability.

### Results

- The results page leads with Fix first, the components to upgrade in order, then every CVE by priority, component or team. What changed in the last 7 days has its own tab.
- Large organisations' stacks get a team per item (Network, Database, Platform and so on), so fixes can be handed out.
- Export for AI saves a Markdown file for a coding agent or a person to work through, with a record of the check and a decisions table for each item that needs a response.
- The header shows how fresh the CVE data is, and the footer shows each data source's age.

### Feeds, API and agents

- A stack is a link, so results, the JSON feed (`/api/feed`), the Atom feed (`/feed.xml`) and the badge (`/badge.svg`) can be shared or subscribed to.
- An MCP server at `/mcp`, with no account or key, gives AI agents two read-only tools: `rank_stack` and `rank_cves`. Setup for Claude Code, Cursor, VS Code and Claude Desktop is in [docs/AI_AGENTS.md](docs/AI_AGENTS.md), and `llms.txt` explains Vulnder to agents without MCP.
- A machine API for scheduled runners and SIEMs ([docs/API.md](docs/API.md)): `POST /api/v1/stack` turns product names, versions and an Intune inventory into a stack, using catalog matching only, and `POST /api/v1/rank` returns one flat row per CVE, ranked as the feed ranks them.
- A Microsoft Sentinel and Defender template ([docs/AZURE.md](docs/AZURE.md)), deployable from a Deploy to Azure button. An hourly Logic App in your subscription ranks your tenant's CVEs, from Defender Vulnerability Management, Intune's discovered apps or a stack you write, into a `Vulnder_CL` table, and an optional Sentinel rule opens an incident when a CVE becomes Act now. It runs under a managed identity with no secrets, and Vulnder receives CVE IDs or app names and versions, never device names. Each GitHub release attaches the built template and its portal form, so a deployment can pin a version.
- A Compliance page (`/compliance`, [docs/NIS2.md](docs/NIS2.md)) maps Vulnder to NIS2's vulnerability handling rules and CRA Article 14, and [a weekly review routine](docs/agents/nis2-weekly-review.md) lets an AI agent keep the record. It isn't legal advice.

### Privacy

- No accounts. Vulnder's code never stores or logs your stack or free text. On vulnder.com, only free-text entries describing your stack are logged, by Cloudflare's AI Gateway.
- Manifests, MCP configs, CVE lists and scan reports are read in your browser, and only package names and versions, or CVE IDs, are sent. An MCP config's `env` and headers are never read.
- Feed passes hold keyed hashes of stacks, never stacks, and are deleted after a day. IPs are used only as rate-limit keys or a daily-salted hash. Stack links, feeds and badges aren't indexed by search engines.

### Self-hosting

- Runs on Workers Free, with ingest from GitHub Actions, or on Workers Paid, with an hourly cron. Setup, bindings and secrets are in [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md).
- Upgrading a deployment from before 1.0.0: run `npm run db:migrate:remote` to apply migrations up to 0014 before you deploy. docs/SELF_HOSTING.md gives each migration's cost in row writes and the two one-off backfills, the CVE index (0009) and exploit references (0010).
