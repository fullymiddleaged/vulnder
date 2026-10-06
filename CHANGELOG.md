# Changelog

Notable changes to Vulnder. Stack URLs, the JSON feed fields and the Atom feed stay compatible unless an entry says otherwise.

## [Unreleased]

### Added

- Mark stack items as **internet-facing**, with a toggle on the Edit page or `!` in front of an item in the link (`!p:f5/nginx`). On those items, a bug an attacker can reach with no login or user action ranks higher: CVSS 7.0 or more goes to Watch and its score is raised. Older deployments reject links that use `!`.

### Changed

- The most urgent priority is now labelled **Act now** (was Act). The feed's `priority` value is still `act`.
- CVSS 9.0 or more now puts a result in **Attend** (was Watch), but only when an attacker can reach it: over the network, with no login and no user action, or judged automatable by CISA. Criticals that need local access, a login or someone's help go to **Watch**.
- **Watch** now starts at CVSS 8.0 (was 9.0). Results from 8.0 to 8.9 with no exploit signal move up from Track.
- Results from CVSS 7.0 up say whether an attacker can reach them, for example "Needs a login and user action".
- New look: a cooler palette, the Atkinson Hyperlegible typefaces (self-hosted, so no font requests leave the site), and a results page that opens with a strip showing how your matches split across the four priorities.

### Fixed

- A focus outline no longer frames the whole page after loading or changing view.
