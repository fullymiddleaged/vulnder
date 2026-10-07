# Changelog

Notable changes to Vulnder. Stack URLs, the JSON feed fields and the Atom feed stay compatible unless an entry says otherwise.

## [Unreleased]

### Added

- Mark stack items as **internet-facing**, with a toggle on the Edit page or `!` in front of an item in the link (`!p:f5/nginx`). On those items, a bug an attacker can reach with no login or user action ranks higher: CVSS 7.0 or more goes to Watch and its score is raised. Older deployments reject links that use `!`.
- When you describe your stack in words, Jev marks the components your description says face the internet (for example "nginx in front"). The results page lists what it marked; untick any of them under Edit stack. Manifests are never marked automatically.
- Products that face the internet by what they are (VPN and remote-access gateways, edge firewalls, ADCs and mail gateways, such as FortiGate, Cisco ASA, PAN-OS and NetScaler) are marked internet-facing from a description even when Jev doesn't mark them or isn't available.
- **LEV**, NIST's estimate (CSWP 41) of the chance a CVE has already been exploited, built from its EPSS history. At 20% or more a result goes to **Attend** with the reason "NIST LEV estimate: N% chance it has already been exploited", so a CVE that was hot for weeks and has cooled since stays near the top. It never puts a result in Act now. Results show a LEV badge, and the JSON feed has `evidence.lev`.
- **Similar CVEs** in the same product are grouped into families: one flaw filed twice, variants of one flaw, or a vendor bulletin's batch. The results page folds each family under its highest-ranked member ("+3 similar CVEs in this product"), and nothing is hidden. When a family member is on KEV or actively exploited, the others go to at least **Attend** with the reason "Similar to exploited CVE-… in the same product". The JSON feed adds `family` and `related` to each result. On the free plan, the GitHub Actions token needs Workers AI read and edit for this; without them ingest skips it.
- Each result now shows **which signal decided its priority**, the other reasons, and what data wasn't available (no CISA assessment, no CVSS score, no EPSS score yet), so an unknown doesn't read as safe.
- A suggested **response window** on each result: 24 hours for Act now on an internet-facing item, 48 hours otherwise, 7 days for Attend, 30 days for Watch. It's guidance, based on 2026 time-to-exploit data, not a deadline.
- Act now and Attend results with no fixed version known say **what to do meanwhile**: CISA's required action when it's on KEV, and a link to the advisory.
- The JSON feed adds `why`, `respondWithinHours` and `mitigation` to each result (`reasons` is unchanged), and Atom entries now include the priority, the window and the reasons.
- A loader, built from the logo, while your stack is read and while matches load. It stays still if your system asks for reduced motion.

### Changed

- The most urgent priority is now labelled **Act now** (was Act). The feed's `priority` value is still `act`.
- CVSS 9.0 or more now puts a result in **Attend** (was Watch), but only when an attacker can reach it: over the network, with no login and no user action, or judged automatable by CISA. Criticals that need local access, a login or someone's help go to **Watch**.
- **Watch** now starts at CVSS 8.0 (was 9.0). Results from 8.0 to 8.9 with no exploit signal move up from Track.
- Results from CVSS 7.0 up say whether an attacker can reach them, for example "Needs a login and user action".
- `GET /api/health` no longer returns record counts. It reports source freshness only and is cached for 15 minutes. Counting the tables read every row in the database on each page load.
- New look: a cooler palette, the Atkinson Hyperlegible typefaces (self-hosted, so no font requests leave the site), and a results page that opens with a strip showing how your matches split across the four priorities.

### Fixed

- A focus outline no longer frames the whole page after loading or changing view.
