# Security policy

## Security maintainer

Vulnder's security is maintained by **Pete Salmond** ([@fullymiddleaged](https://github.com/fullymiddleaged), [LinkedIn](https://www.linkedin.com/in/pete-salmond/)), who triages reports, fixes vulnerabilities, publishes advisories and runs the deployment at vulnder.com.

## Reporting a vulnerability

Please report security problems privately through GitHub: [open a private advisory](https://github.com/fullymiddleaged/vulnder/security/advisories/new) (Security tab → Report a vulnerability). Don't open a public issue or pull request for them.

Include what you found, how to reproduce it, and what an attacker could do with it. You'll get a reply when the report has been read, and credit in the advisory once it's fixed, if you want it.

## In scope

- The code in this repository.
- The deployment at [vulnder.com](https://vulnder.com).
- Anything that breaks the privacy model in the [README](README.md#privacy): a way to recover someone's stack or free text from logs, caches, feed passes or rate-limit keys, or to learn what another person looked up.
- Prompt injection that gets the model to change results, hide a match or reach anything beyond its extraction task.

## Out of scope

- Wrong or missing CVE data that comes from an upstream source (CVE records, GitHub advisories, CISA KEV, EPSS, OSV, endoflife.date). Report it to that source. A wrong match that Vulnder itself makes is a normal bug: use the "Wrong or missing match" issue form.
- Rate limits, Turnstile challenges and daily model caps working as designed.
- Denial of service by volume, and findings that need a compromised Cloudflare account.
- Forks and other deployments of this code. Report those to whoever runs them.

## Supported versions

Only the latest commit on `main`, which is what vulnder.com runs.
