# Changelog

Notable changes to Vulnder. Stack URLs, the JSON feed fields and the Atom feed stay compatible unless an entry says otherwise.

## [Unreleased]

### Added

- Mark stack items as **internet-facing**, with a toggle on the Edit page or `!` in front of an item in the link (`!p:f5/nginx`). On those items, a bug an attacker can reach with no login or user action ranks higher: CVSS 7.0 or more goes to Watch and its score is raised. Older deployments reject links that use `!`.
- When you describe your stack in words, Jev marks the components your description says face the internet (for example "nginx in front"). The results page lists what it marked; untick any of them under Edit stack. Manifests are never marked automatically.
- Products that face the internet by what they are (VPN and remote-access gateways, edge firewalls, ADCs and mail gateways, such as FortiGate, Cisco ASA, PAN-OS and NetScaler) are marked internet-facing from a description even when Jev doesn't mark them or isn't available.
- **LEV**, NIST's estimate (CSWP 41) of the chance a CVE has already been exploited, built from its EPSS history. At 20% or more a result goes to **Attend** with the reason "NIST LEV estimate: N% chance it has already been exploited", so a CVE that was hot for weeks and has cooled since stays near the top. It never puts a result in Act now. Results show a LEV badge, and the JSON feed has `evidence.lev`.
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
