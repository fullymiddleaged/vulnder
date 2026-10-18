# NIS2 and the CRA

Vulnder can be one of the ways an EU organisation monitors and handles vulnerabilities under NIS2, and an early warning for manufacturers under the Cyber Resilience Act (CRA). It's free and needs no account. Your own AI agent can run the routine and keep the record; Vulnder keeps no copy of your stack or its results.

This maps Vulnder's features to the texts. It isn't legal advice, and using Vulnder doesn't make anyone compliant. The same content is on the site at [vulnder.com/nis2](https://vulnder.com/nis2).

## Who the detailed rules cover

NIS2 ([Directive (EU) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj)) Article 21 asks essential and important entities for "appropriate and proportionate" measures, including "vulnerability handling and disclosure" (Article 21(2)(e)). Each member state sets the details in national law.

[Implementing Regulation (EU) 2024/2690](https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj) spells them out for DNS service providers, TLD name registries, cloud computing, data centre and content delivery network providers, managed service providers, managed security service providers, online marketplaces, online search engines, social networking platforms and trust service providers. Its Annex, section 6.10, is the vulnerability part. Other entities often meet similar expectations through national law or as a supplier to one of these.

## How Vulnder helps, point by point

| Implementing Regulation 2024/2690, Annex | What Vulnder does | What stays with you |
|---|---|---|
| 6.10.2(a): "monitor information about vulnerabilities through appropriate channels" | Your stack link and its Atom feed track CVE records, GitHub advisories and CISA KEV hourly, and EPSS and end-of-life dates daily. An agent can check through the MCP server on a schedule. | Keeping the stack list matching what you run. |
| 6.10.4: review the monitoring channels "at planned intervals" | Every saved record and agent log lists each data source and when it last updated. | The review itself. |
| 6.10.2(b): vulnerability scans where appropriate, with "evidence of the results" recorded | Vulnder doesn't scan. It ranks your scanner's report (Nessus, Qualys, Tenable, Trivy, Grype) by its CVE IDs, and Export for AI saves a dated record. | Running the scans. |
| 6.10.2(c): address critical vulnerabilities "without undue delay" | Act now and Attend, with suggested response windows, a Fix first list, and out-of-support notices. | Deciding what is critical to your operations, and fixing it. |
| 6.10.2(d) and 6.6.1(a): fit change and patch management; patches "within a reasonable time" | Teams per item, Export for AI for a coding agent, and the weekly routine that opens tickets with a respond-by date. | Your change process. |
| 6.10.3: a mitigation plan, or documented reasons for not remediating | Mitigations for results with no fix yet, and a decisions table in every saved record. | The decisions and their reasons. |
| 6.10.2(e): a disclosure procedure under your national CVD policy | Nothing. | All of it. |

Incident reporting (NIS2 Article 23), asset inventory, risk acceptance and keeping your records are yours too.

## With your own AI agent

1. Connect your AI agent to Vulnder: see [AI_AGENTS.md](AI_AGENTS.md).
2. Keep your stack in your repository and schedule the [weekly review](agents/nis2-weekly-review.md). It ranks the stack, opens or updates a ticket for everything due soon, and writes a dated log.
3. Keep the logs. They live in your repository, not with Vulnder.

Without an agent, save Export for AI from the results page each week instead. It ends with a record of the check: when it ran, how fresh each source was, and a decisions table to fill in.

## Manufacturers and the CRA

Since 11 September 2026, [Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) Article 14 has required manufacturers to notify any actively exploited vulnerability in a product with digital elements through ENISA's single reporting platform: an early warning within 24 hours of becoming aware, a notification within 72 hours, and a final report within 14 days of a fix being available. They must also inform affected users (Article 14(8)).

Rank your product's SBOM in Vulnder and follow its Atom feed. A component CVE on CISA KEV is an Act now result, and "Targeted by attackers" flags components with recent KEV additions. CISA KEV doesn't list every exploited vulnerability, so other sources of awareness count too. The rest of the CRA, including Article 24 for open-source software stewards, applies from 11 December 2027.

## Privacy and where it runs

Nothing you enter is stored by Vulnder; manifests, SBOMs and scan reports are read in your browser. Vulnder runs on Cloudflare, which processes every request. To keep everything on infrastructure you choose, [self-host it](SELF_HOSTING.md): Apache 2.0, on Cloudflare Workers.
