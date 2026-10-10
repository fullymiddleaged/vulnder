# Changelog

Notable changes to Vulnder. Stack URLs, the JSON feed fields and the Atom feed stay compatible unless an entry says otherwise.

## [Unreleased]

### Changed

- **Results lead with the answer.** The headline comes first, then your stack in one line ("5 items: 4 exact, 1 close match, 1 internet-facing") with the time window and Edit stack, then priorities and Fix first. Long stacks fold their items away. Copy links and exports move to a "Share and follow" section at the end.
- **Every result says what to do** in plain words: confirm it's yours for a close match, check your version when only the product matched, then upgrade to the fixed version or apply the mitigation. These are the same steps the Markdown and JSON exports give.
- Each priority shows its **response window** (Act now within 24–48 hours, Attend within 7 days, Watch within 30 days, Track in your next routine update), and the Attend description now lists everything that puts a CVE there.
- **Exact and close matches are labelled in words**, on the stack and in results, not just with a dashed border. "Product match" is now "Version not confirmed".
- A **glossary** under the priorities explains KEV, EPSS, LEV, CVSS, the risk scores and the match labels, and results link to how ranking works.
- **Notes about your lookup stay on the page**: names that couldn't be matched, items marked internet-facing, and dependencies left out. With no matches, the headline no longer says your stack is clear when some names weren't checked.
- **Errors show next to the form** you're using, not in a line under the page. If the verification check can't run, the page says so and offers adding items by hand, instead of asking you to wait forever.
- "What changed this week" is now "What changed in the last 7 days", since it ignores the time window. Empty priorities are no longer listed in the By priority view.
- **Accessibility:** field and button borders now meet 3:1 contrast in both themes. Keyboard focus on "choose a file" is visible. Empty priorities and pending loader steps keep readable contrast. CVE links in the priority tiles and the remove buttons are easier to tap. Start over and Start again move focus and reset the page title. "+N more below" respects reduced motion and moves focus to the results. The How it works diagram scrolls sideways on phones rather than shrinking its labels.

### Added

- **About** (`/about`) and **How it works** (`/how-it-works`) pages: why Vulnder exists, the data pipeline, where AI is used and where code decides, how priorities work, and how to hand results to an AI assistant. Linked from the top right of every page, with a direct "Use it with AI" link, and from the sitemap and `llms.txt`.
- A CVE with no CVSS score whose CNA or GitHub advisory rates it **critical or high** now goes to **Watch** (it was Track), with the reason "Rated critical by its advisory (no CVSS score yet)", and ranks higher within it. A score, when one exists, always decides instead, and a rating alone never reaches Attend. Records pick up the rating as their sources next update them. Needs migration 0007.
- Mark stack items as **internet-facing**, with a toggle on the Edit page or `!` in front of an item in the link (`!p:f5/nginx`). On those items, a bug an attacker can reach with no login or user action ranks higher: CVSS 7.0 or more goes to Watch and its score is raised. Older deployments reject links that use `!`.
- When you describe your stack in words, Jev marks the components your description says face the internet (for example "nginx in front"). The results page lists what it marked; untick any of them under Edit stack. Manifests are never marked automatically.
- Products that face the internet by what they are (VPN and remote-access gateways, edge firewalls, ADCs and mail gateways, such as FortiGate, Cisco ASA, PAN-OS and NetScaler) are marked internet-facing from a description even when Jev doesn't mark them or isn't available.
- **LEV**, NIST's estimate (CSWP 41) of the chance a CVE has already been exploited, built from its EPSS history. At 20% or more a result goes to **Attend** with the reason "NIST LEV estimate: N% chance it has already been exploited", so a CVE that was hot for weeks and has cooled since stays near the top. It never puts a result in Act now. Results show a LEV badge, and the JSON feed has `evidence.lev`.
- **Similar CVEs** in the same product are grouped into families: one flaw filed twice, variants of one flaw, or a vendor bulletin's batch. The results page folds each family under its highest-ranked member ("+3 similar CVEs in this product"), and nothing is hidden. When a family member is on KEV or actively exploited, the others go to at least **Attend** with the reason "Similar to exploited CVE-… in the same product". The JSON feed adds `family` and `related` to each result. On the free plan, the GitHub Actions token needs Workers AI read and edit for this; without them ingest skips it.
- Each result now shows **which signal decided its priority**, the other reasons, and what data wasn't available (no CISA assessment, no CVSS score, no EPSS score yet), so an unknown doesn't read as safe.
- A suggested **response window** on each result: 24 hours for Act now on an internet-facing item, 48 hours otherwise, 7 days for Attend, 30 days for Watch. It's guidance, based on 2026 time-to-exploit data, not a deadline.
- Act now and Attend results with no fixed version known say **what to do meanwhile**: CISA's required action when it's on KEV, and a link to the advisory.
- The JSON feed adds `why`, `respondWithinHours` and `mitigation` to each result (`reasons` is unchanged), and Atom entries now include the priority, the window and the reasons.
- **Feed passes.** After its Turnstile check, a browser gets a pass (an HttpOnly cookie, no account) that loads 2 different stacks an hour, counted from the first; until the second, the first stack and its other time windows load as often as you like. Once both are used, the browser is locked until the hour is over: nothing loads, including stacks already opened, and the server turns it away from a lock cookie without reading the database. The page greys out Start over, Edit stack, the time window and new lookups, shows a red countdown next to them, and points at it when you click one. A browser with a pass is rate-limited by its pass instead of its IP, so people sharing an office IP no longer limit each other; feed readers, badges and scripts without one keep the per-IP limits. Needs migration 0005.
- A loader, built from the logo, while your stack is read and while matches load. While matches load it ticks off each source it checks (CVE records, GitHub advisories, CISA KEV, EPSS, OSV) and then the exact and close matches. It stays still if your system asks for reduced motion.
- **Export** the results as Markdown or JSON from the results page: every CVE with its priority, risk score, response window, why, exploitation evidence, fixed versions and what to do, plus the fix-first order and instructions for a person or an AI assistant to work through it. Built in your browser from the page, so it costs no request.
- `robots.txt`, `sitemap.xml` and `llms.txt`, and search and link-preview tags on the home page. The footer links to the source on GitHub.

### Security

- Pasted manifests could make the server spend minutes of CPU on one request: a long run of spaces or blank lines, or unclosed tags in a `pom.xml`, made the format detection and the Maven parser quadratic. They now run in linear time.
- A description or manifest repeating one product thousands of times, or naming a product category many times, made one request do millions of comparisons. Each distinct product is now looked up once, repeats share the result, each name is compared only with catalog entries that share its first letters, and a request whose names would match more than 2,000 products is refused.
- Resolving a vendor name ("Cisco", "Microsoft Exchange") now reads only that vendor's top few products from the database instead of all of them, up to 12,000 fewer rows read per request. Needs migration 0006.
- IPv6 clients are rate-limited and counted by their /64 rather than their full address, which one connection can change at will.
- Updated Wrangler to 4.149 for CVE-2026-96889 in `sharp`'s bundled librsvg (development tooling only; the deployed Worker doesn't include it).

### Changed

- Close matches for a misspelt or partial name ("grafanna", "exchange srv") are listed with the most-affected product first, like the close matches for a vendor or a category. Which matches you get is unchanged, and a name now resolves the same whatever else you list alongside it.
- Search engines are told not to index stack links, feeds or badges, so a shared link doesn't put what you run in search results. Only the home page is indexed.
- The manifest upload is now one short line under the examples, inside the form, and the page no longer suggests pasting a manifest into the description box, which has a length limit. Uploads were never held to that limit, and now accept files up to 10 MB (was 5 MB) and 300,000 lines. Only manifest names and text extensions (.json, .txt, .toml, .xml, .lock, .mod, .in) are read, and binary files are refused with a reason.
- The most urgent priority is now labelled **Act now** (was Act). The feed's `priority` value is still `act`.
- CVSS 9.0 or more now puts a result in **Attend** (was Watch), but only when an attacker can reach it: over the network, with no login and no user action, or judged automatable by CISA. Criticals that need local access, a login or someone's help go to **Watch**.
- **Watch** now starts at CVSS 8.0 (was 9.0). Results from 8.0 to 8.9 with no exploit signal move up from Track.
- Results from CVSS 7.0 up say whether an attacker can reach them, for example "Needs a login and user action".
- `GET /api/health` no longer returns record counts. It reports source freshness only and is cached for 15 minutes. Counting the tables read every row in the database on each page load.
- New look: a cooler palette, the Atkinson Hyperlegible typefaces (self-hosted, so no font requests leave the site), and a results page that opens with a strip showing how your matches split across the four priorities.

- Feeds, Atom and badges are kept at the edge for up to an hour (until new data arrives); browsers still keep them for 5 minutes. Each component's CVEs are cached too, so a new stack or window that shares components with an earlier one loads without re-reading them: a Linux kernel stack reads about 2,700 database rows instead of 30,500.
- Stacks touching 1,000 or more CVEs, such as the Linux kernel, are limited to 6 uncached requests a minute per IP (`FEED_HEAVY_LIMITER`); other stacks keep the limit of 60. Self-hosters add the binding from `wrangler.jsonc`.
- `POST /api/resolve` refuses requests that look up more than 200 different products, the most a stack can hold, with HTTP 413.
- The examples on the input page are 2026 stacks: a SaaS app, an AI app, a cloud platform on AWS and an office network. The empty text box shows one of them at random.
- Free-text descriptions are limited to 500 characters (was 2,000), and "Find vulnerabilities" greys out while a description is over it. Longer lists belong in a manifest, which has no such limit.
- Ingest from Node (GitHub Actions on the free plan) assigns similar-CVE families to at most 8,000 CVEs a day, so the first pass stays inside the free plan's D1 writes; `--family-daily` changes it (0 for no cap). The Paid cron has no cap.

### Fixed

- **New CVEs no longer stop arriving when GitHub's API rate limit runs out.** CVE ingest finds the CVE Program's hourly files through the GitHub API; when that is rate limited (for example on shared Cloudflare IPs without a `GITHUB_TOKEN`), it now downloads them directly by release name instead of waiting, sometimes for hours, with CVE records marked stale.
- A manifest with more than 5,000 entries, such as a large monorepo lockfile, no longer fails with "invalid request": the first 5,000 are checked, direct dependencies first, and the results say how many were left out.
- A focus outline no longer frames the whole page after loading or changing view.
- Large stacks no longer fail on the free plan's 50 database queries per request: the feed now reads the biggest stacks in 15.
- The daily EPSS update writes about a third of the database rows it did.
- Ingest is gentler with GitHub and recovers from its hiccups. Calls are spaced at least 250 ms apart. A GitHub 5xx, dropped connection or short secondary rate limit is retried up to twice before the source gives up until the next run. A rejected advisory page token restarts the pass once a run instead of looping. Release listing stops at GitHub's 1,000-release limit instead of failing with HTTP 422. Ingest errors now include GitHub's own message.
- `POST /api/resolve` stops reading a body once it passes 1 MB. Before, a body sent without a `Content-Length` was read in full.
