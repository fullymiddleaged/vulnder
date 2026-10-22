# How Vulnder ranks results

The short version is on the site at [How it works](https://vulnder.com/how-it-works#ranking). This is the detail.

## Priorities

Each result gets a priority, named after CISA's [SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc) decisions (Act, Attend, Track), with Watch added between Attend and Track. The SSVC assessments themselves (exploitation, automatable, technical impact) come from CISA's [Vulnrichment](https://github.com/cisagov/vulnrichment), attached to CVE records. Evidence of exploitation always outranks prediction and severity, and severity never holds either back: attackers chain lower-severity bugs, such as an information leak or a login bypass, into serious attacks. A CVSS 5.4 on KEV is Act now, and one with EPSS of 0.10 or more is at least Attend.

| Priority | When |
|---|---|
| **Act now** (red) | On CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog, or CISA reports active exploitation, at any severity. Also, before any exploitation is seen: a critical (CVSS 9.0 or more) with EPSS of 0.10 or more or LEV of 0.20 or more, EPSS of 0.50 or more at any severity, an edge device that CISA rates automatable with total technical impact, or a critical that trusted security teams are warning about (see [Written up](#written-up)). Exploited results always sort first. |
| **Attend** (amber) | A similar CVE in the same product is on KEV or actively exploited, a [Metasploit](https://github.com/rapid7/metasploit-framework) exploit module, [EPSS](https://www.first.org/epss) of 0.10 or more or a [NIST LEV](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.41.pdf) estimate of 0.20 or more (at any severity), CVSS 9.0 or more (or, with no CVSS score at all, a CNA or GitHub advisory rating it critical), a proof-of-concept exploit that is automatable or gives total control, an edge device with a bug CISA rates automatable or total technical impact, or CVSS 8.0 or more and public for 60 days or more (see [Overdue](#overdue)). |
| **Watch** (yellow) | CVSS 8.0 or more, a proof-of-concept exploit, a bug CISA rates automatable (or, unrated, one with a Nuclei template), any bug CISA has assessed on an edge device, or CVSS 7.0 or more and public for 60 days or more. With no CVSS score at all, also a CVE whose CNA or GitHub advisory rates it high (Red Hat's "important" counts as high). |
| **Track** (grey) | Everything else: it affects your stack, but nothing above applies. |

EPSS is a *predicted* probability of exploitation in the next 30 days, not evidence that it has happened. LEV (NIST CSWP 41) adds up a CVE's daily EPSS scores into the chance it has *already* been exploited, so a CVE that was hot for weeks and has since cooled stays visible. It's an estimate, and a lower bound, because Vulnder counts only the EPSS history it has seen since it first ingested the CVE.

## Exploit code

Most CVEs have no CISA assessment, so CISA's "proof of concept" isn't the only sign of public exploit code Vulnder reads:

- **A reference the CVE record tags "exploit"**, from its CNA or a CISA-ADP container. It counts as a proof-of-concept exploit: at least Watch, and Attend when the bug is automatable or gives total control. Reason: "Public exploit code (reference in the CVE record)".
- **A [Metasploit](https://github.com/rapid7/metasploit-framework) module.** An exploit module is a ready-made attack tool: at least Attend, with a threat of at least 0.3, as for an exploited similar CVE. An auxiliary module (a scanner, a denial of service) counts as a proof of concept.
- **A [Nuclei](https://github.com/projectdiscovery/nuclei-templates) template** means the bug can be found across the internet with a scanner. Where CISA hasn't rated the CVE automatable or not, it counts as automatable: at least Watch, × 1.25 on the score, and with public exploit code, Attend. CISA's own rating always wins, and it never counts toward the edge-device rules or reachability, which stay CISA's.

None of this is evidence of exploitation, and it never reaches Act now on its own: only CISA KEV and CISA reporting active exploitation are evidence. EPSS already uses exploit code and scanner templates as inputs, so these mostly add explicit reasons, and cover CVEs EPSS hasn't caught up with. Metasploit's and Nuclei's indexes are fetched once a day.

## Written up

A critical CVE reaches the news, and the security teams' blogs, days before EPSS scores it or CISA revisits its first assessment. PHP2Shell (CVE-2026-109618 and CVE-2026-109619) was written up by Huntress, Rapid7, CERT-EU and NCSC UK on the day it was published, while Vulnder had it in Attend: CVSS 9.2, no EPSS yet, and CISA saying not exploited and not automatable.

So every hour Vulnder reads the RSS feeds of five trusted sources: Huntress, Rapid7, watchTowr, CERT-EU and NCSC UK. A post counts for the CVEs it names, all of them when it names five or fewer (ten for CERT-EU's and NCSC UK's advisories), otherwise only those in its title, so a Patch Tuesday roundup counts for none. CERT-EU's feed names products only, so each new advisory's page is read once for its CVE IDs, and so is NCSC UK news about a vulnerability.

- **Act now within 3 days**: a critical (CVSS 9.0 or more, or rated critical with no score) that two of them have written up, or that one has called critical or urgent, in the last 30 days, whatever its EPSS. A critical with EPSS of 10% or more is Act now already, so this lifts the ones EPSS hasn't scored or scores low. "Critical or urgent" means a keyword in a post's title or the opening of its summary: critical, urgent, emergency, immediate or immediately, zero-day, or exploitation as it happens (exploiting, exploitation, actively or being exploited, exploited in the wild). Bare "exploit" doesn't count, since disclosures use it for what could happen. On the five feeds in October 2026 that marked 39 of 63 counted posts urgent, every one of them an alert or a write-up of attacks, and none of the research write-ups or fixed disclosures. The reason says who: "Critical bug reported by Huntress, Rapid7, CERT-EU and NCSC UK: Act now while EPSS and CISA catch up".
- **Any other write-up** adds a reason ("Reported by watchTowr") and × 1.25 on the score, so it orders ahead of similar results within its priority. It never changes the priority of a CVE below critical.

A write-up is never evidence of exploitation, even when the post says attacks have started: only CISA KEV and CISA's own reports are. So a CVE on KEV still sorts above it, with a day to respond, and nothing a feed says is called "exploited". No model reads the posts: fixed code finds the CVE IDs and the wording. Only the CVE ID, the post's link (https, on the source's own site) and its date are kept, for a year. The JSON feed lists the posts in `links.reports`. A failed or broken feed changes nothing; ranking carries on without it.

## Reachability

Every critical goes to Attend, whatever its EPSS: EPSS is often near zero in a CVE's first days, and a login is a thin barrier when accounts can be signed up for, bought or guessed. What an attacker needs only orders criticals within Attend. One reachable over the network with no login and no user action, or that CISA judges automatable, ranks above one that needs local access, a login or someone's help. A critical with no CVSS 3 or 4 vector gets the benefit of the doubt and ranks as reachable. From CVSS 7.0 up, each result says which applies ("Reachable over the network without a login", "Needs a login and user action").

Vulnder doesn't know which of your systems face the internet, and doesn't guess: a guess would sometimes miss one and quietly rank real risk lower. Every result is ranked as if it could be reached, so every exploited result asks for a response within 24 hours. Act now results not yet exploited get 3 days, the window CISA's [BOD 26-04](https://certcc.github.io/SSVC/howto/cisa_response/) gives an internet-facing system with an automatable, total-impact bug that isn't on KEV. If something is air-gapped or internal only, that's your call to make when you plan the fix.

BOD 26-04 itself turns on whether a system is publicly exposed: the same automatable, total-impact bug gets 3 days exposed and 60 days not. Vulnder treats edge devices as exposed, the one place it knows a system faces the internet, and everything else as not, and never gives a result longer than BOD 26-04 would. So an automatable bug is at least Watch (BOD: 60 days), and on an edge device an automatable or total-impact bug is at least Attend (14 days) and any bug CISA has assessed at least Watch (60 days). Treating everything as exposed would put about 37 times as many results in Act now as KEV does, which would bury the exploited ones. Each result lifted by one of these rules says so, for example "Edge device with an automatable bug: CISA gives internet-facing systems 14 days".

## Overdue

A high-severity bug that has been public for 60 days and still affects you is overdue for a fix. With CVSS 8.0 or more it's at least Attend; with CVSS 7.0 or more, at least Watch. Sixty days is BOD 26-04's deadline for a system that isn't exposed, and twice Watch's 30-day window.

Older CVEs need this most. CISA's SSVC assessment is usually made once, around publication, and rarely revisited; EPSS often stays low; and a CVE from before the window has no EPSS history for a LEV estimate. Without it, an old CVSS 8.2 with nothing else known would sit in Watch however long it went unpatched. The reason says how long it's been public ("Public for 17 months at CVSS 8.0 or more: a fix is overdue").

It's checked after every other rule, so it decides a priority only when nothing stronger does, and it never reaches Act now. Age says the fix is late, not that anyone is attacking it, so it never changes the risk score: overdue results sort below anything with threat data in the same priority.

## Safety net

Results come from the time window you pick (7, 30 or 90 days), at every severity. Whatever the window, these CVEs from the last year show too, at any severity, marked "Older":

- added to CISA KEV in the last year, or published in it and reported by CISA as actively exploited;
- published in the last year with EPSS of 10% or more, a NIST LEV estimate of 20% or more, or CVSS 9.9 or more.

An exploited bug from six months ago that's still unpatched is exactly what shouldn't drop out of view. Ingest keeps these for a year instead of 90 days. It also keeps CVEs with CVSS 7.0 or more for a year, with everything it knows about them (affected versions, EPSS history for LEV, similar CVEs), but shows them only inside the window you pick. They're there so a listed CVE from the last year ranks on its full record (see [Listed CVEs](#listed-cves)). EPSS only scores CVEs Vulnder already holds, so once a day ingest also asks FIRST for this and last year's CVEs with EPSS of 10% or more and fetches any it doesn't have; one that was dropped at 90 days and has since turned hot comes back.

## Edge devices

Some products face the internet by what they are: VPN and remote-access gateways, edge firewalls, ADCs and load balancers, web application firewalls and mail gateways (FortiGate, PAN-OS, Cisco ASA, NetScaler, BIG-IP, Ivanti Connect Secure and the like). They make up much of CISA KEV. Fixed code recognises them by product name, leaving out their management consoles and client apps, and labels them "Edge device".

Their CVEs get × 1.25 on the risk score, so they rank ahead of similar results **within the same priority**, and their item rises in Fix first. BOD 26-04's deadlines for an internet-facing system also raise their priority: automatable with total technical impact goes to Act now with 3 days, automatable or total impact to at least Attend, and anything else CISA has assessed to at least Watch (see Reachability). Being an edge device never lowers a priority, a response window or another result's score, so a wrong guess can only lift a result.

"Edge device" means internet-facing, and you know your network better than a product name does. Under Edit stack, tick **Edge device** on anything else the internet can reach directly (a customer portal, an exposed file server) and it's ranked the same way; untick it on a firewall that sits inside your network and it's ranked like any other product. Your choice goes into the link (`;edge` or `;internal`, see [STACK_FORMAT.md](STACK_FORMAT.md#edge-devices)). Only you set it: Jev never guesses it from a description. Unticking is the one way a priority can go down, and only back to what any other product would get, never below BOD 26-04's deadlines for a system that isn't exposed.

## Out of support

A product its vendor no longer supports gets no more security fixes, so every new bug in it stays open, whatever any one CVE says. That's a finding about the component, not a CVE, so it never changes a CVE's priority, and Act now stays about as big as KEV. Instead the item gets an **Out of support** notice above the priorities, and in Fix first it ranks with **Act now**, whatever its CVEs; one whose support ends within 90 days ranks with **Attend**. It shows even when the item has no CVEs in the window.

Support dates come from [endoflife.date](https://endoflife.date), fetched once a day: Windows and Windows Server, Exchange, SQL Server, Office, SharePoint, macOS, iOS, Android, Ubuntu, Debian, RHEL, CentOS, Oracle Linux, SLES, ESXi, vCenter, FortiOS, PAN-OS, Cisco IOS XE and BIG-IP. A fixed table (`src/stack/eol.ts`) maps catalog keys to its products and releases; the dates themselves are never typed in by hand. For hardware endoflife.date doesn't cover, such as home and small-office routers, a CVE record its vendor tagged "unsupported-when-assigned" marks the product, until a newer CVE for it comes without the tag.

Only what you named counts. An item is out of support when every release it could mean is past its end of support, so "Windows 7" and "Windows 10" are, and a bare "Windows", "Windows 11" or "macOS" never is. A close match counts only through the version you gave, never through the product it was expanded to. LTSC and IoT editions are left out unless you name one.

Paid extended support (Microsoft ESU, Red Hat ELS, SUSE LTSS, Ubuntu Pro) keeps a release patched past its normal end. Vulnder assumes you don't have it, and says when it's available and until when. If you do, tick **Has ESU** under Edit stack, or say so in your description ("Windows Server 2012 R2 with ESU"), and the item is covered until the extended support ends: Attend in its last 90 days, then out of support. The choice goes into the link as `;esu` (see [STACK_FORMAT.md](STACK_FORMAT.md#extended-support)).

An out-of-support edge device also cites CISA's BOD 26-02, which has US federal agencies replace end-of-support edge devices.

## Targeted by attackers

When CISA has added any of a stack item's CVEs to KEV in the last 90 days, whatever version they affect, the item gets a **Targeted by attackers** notice above the priorities and a "Targeted" badge in Fix first. The notice names the latest KEV add and says whether those CVEs are in your results (they're Act now when they are) or affect only versions you don't run. A pasted CVE list gets the same for each product its CVEs are grouped under in Fix first, saying whether the KEV CVEs are in your list.

It's advice about the product, not a ranking signal. It never changes a CVE's priority, score or response window, or Fix first's order. A backtest over KEV adds from January 2025 to October 2026 (`npm run backtest -- --trend --product-kev`, docs/plans/product-pressure.md) found:
- a product with a KEV add in the last 90 days had another within 90 days about a third of the time (31.8%), 12 times the rate for products overall;
- ranking that product's other CVEs higher made the ranking worse: it added 24,000 flags and moved KEV CVEs out of the top 1%, because the next KEV add is usually a new CVE.

So the notice says: patch this product's next advisory within days, and check whether it faces the internet.

## Teams

When a description reads as an enterprise stack (Jev's screen says enterprise with 0.5 confidence or more), each item gets the team that usually looks after it: Network, Database, Front-end, Back-end, Platform, Endpoints or Business apps. Jev answers for each component you named, reading your own description; a fixed table of ecosystems, vendors and product names fills whatever Jev leaves open or can't answer. Items neither knows are Unassigned. The team goes into the link (see [STACK_FORMAT.md](STACK_FORMAT.md)), and you can change it under Edit stack. Home, small-business and lockfile stacks get no teams.

Teams only group results ("By team") and label the export. They never change a priority, a score or the order within a group.

## Risk score

Within a priority, results are ordered by a 0–100 score:

- **threat**: 1 for KEV, otherwise the higher of EPSS and LEV; at least 0.01, at least 0.1 for a critical (the EPSS that earns Attend; 0.05 when it needs a login, a user's help or local access), at least 0.2 with a proof-of-concept exploit, at least 0.3 when a similar CVE is exploited or a Metasploit exploit module exists
- × **impact**: CVSS ÷ 10, at least 0.9 for total technical impact, 0.5 without CVSS
- × 1.25 if automatable (or, unrated by CISA, with a Nuclei template), × 1.25 on an edge device, × 1.2 if used in ransomware
- capped at 100

It's a heuristic for ordering, not a probability. Exploitation status, automatability and technical impact come from CISA's [Vulnrichment](https://github.com/cisagov/vulnrichment) data in CVE records.

**Fix first** ranks the items in your stack: the one with the most urgent priority first, then by the total risk score of its CVEs, since one upgrade usually closes several.

## Similar CVEs

CVEs in the same product whose descriptions are nearly the same are grouped into families: one flaw filed twice (by a CNA and in a GitHub advisory), variants of one flaw, or a vendor bulletin's batch. Ingest embeds each CVE's title once with a Workers AI embedding model (CVE text only, never yours, with the product's own name removed) and compares it with similar CVEs in the same product. Code decides at a calibrated threshold.

The results page folds each family under its highest-ranked member ("+3 similar CVEs in this product") and hides nothing. When a member is on KEV or actively exploited, the others go to at least Attend with the reason "Similar to exploited CVE-… in the same product". That's a reason to look, not evidence about the CVE itself, so it never reaches Act now.

## Why, when, and what to do

Each result names the signal that decided its priority, lists the rest, and says what data wasn't available ("No CVSS score yet"), so a quiet result reads as unknown, not safe. It suggests a time to respond: 24 hours for Act now, 7 days for Attend, 30 days for Watch. These are guidance, not deadlines. It also says what to do: confirm a close match or an unconfirmed version, then upgrade to a fixed version or, with none known, apply CISA's required action or a mitigation.

## Match confidence

- **Version confirmed**: you gave a version, and [OSV](https://osv.dev) says that exact version is affected.
- **Version not confirmed**: the product is named as affected, but the version is unknown or couldn't be checked.

A vague name like "Cisco switches" becomes several **close matches**, in catalog order (most-affected first). When your description makes the stack's scale (enterprise, small business, home) or hosting (cloud, on-premises) clear, [Jev](https://developers.cloudflare.com/ai/models/typesafe/jev/) judges how well each close match fits, and they're sorted by that, so a home lab sees small-business gear before data-centre switches. That only changes the order; it never hides a match. Manifests aren't sent to Jev.

## Listed CVEs

A pasted list of CVEs (the By CVE list tab, or `cve:` items in the link) is ranked with the same rules, whatever each CVE's age. CVEs from the last 90 days, and those from the last year with CVSS 7.0 or more or in the safety net, come from the same data as everything else. Older ones come from an index of every CVE ever assigned, which keeps CVSS, CISA's SSVC assessment, KEV and EPSS, so a 2014 CVE on KEV still ranks above a 2025 CVSS 10 nobody exploits. The index keeps no EPSS history, references (apart from the first exploit reference) or similar-CVE families, so an old CVE has no LEV estimate, and `why.missing` says what wasn't there.

A listed CVE says it's **from your list** in place of a match confidence. Nothing says which version you run, so there's no fixed version to compare: its advisory has the fix. A CVE whose product the index knows is held to edge-device deadlines when that product is one (see [Edge devices](#edge-devices)). Fix first groups listed CVEs by their product, and a CVE with no product known stands alone.

A rejected CVE isn't ranked. When its rejection names a replacement (rejected as a duplicate of another CVE), the replacement is ranked in its place and carries `replaces`. One rejected with no replacement is reported so you can drop it, and so is an ID that isn't a published CVE (reserved, or a typo). The feed lists both under `listed`.

## Prompt injection

Free text that reads like instructions for an AI rather than a list of what you run is refused, first by a phrase check, then by Jev. Text that gets past both still can't add anything: the extraction model's answer is checked against your words, and components you didn't name are dropped. If Jev is unavailable, parsing carries on without the second check and close matches keep catalog order.

## In the feeds

The JSON feed carries on each result:

| Field | Meaning |
|---|---|
| `priority`, `score`, `reasons` | The priority, the 0–100 score, and why |
| `why` | `decisive`, `others` (each with a `kind`: evidence, prediction, severity or context) and `missing` |
| `respondWithinHours` | The suggested window (null for Track) |
| `mitigation` | Set for urgent results with no fixed version known |
| `links` | `advisory`, `patch`, `exploit`: public attack code (a Metasploit module or the record's exploit reference), or null, and `reports`: trusted sources' write-ups of it (see [Written up](#written-up)) |
| `family`, `related` | Similar CVEs; `related` lists the other results in the feed from the same family |
| `tier` | The older exploited / likely / backlog field, from KEV and EPSS only; unchanged |
| `confidence` | `version_confirmed`, `product_match`, or `listed` for a CVE from your list |
| `replaces` | Listed CVEs rejected as duplicates of this one; present only when there are some |

For a stack with listed CVEs the feed also carries `listed`: `rejected` (each `id` with the `replacedBy` IDs its rejection names, empty when none) and `notFound`. Fix first entries that group listed CVEs have `listed: true` and the product's `label`.

The feed also carries `support`: one entry per out-of-support finding, with `state` (`eol`, `ending` or `covered`), `name`, `date`, `esuUntil`, `esu`, `edge`, `source` (`endoflife` or `cve`), `cve` and the stack `items` it's about. Fix first entries carry the same `support` state. The Atom feed has an entry for each item out of support or losing it soon.

The feed also carries `targeted`: one entry per set of stack `items` with CVEs CISA added to KEV in the last 90 days, with `kev`, those CVEs newest first (`id`, `addedAt` as YYYY-MM-DD). Close matches with the same KEV adds share one entry. An entry for a listed CVE's product, rather than an item the stack names, has `listed: true` and the product's `label`. The Atom feed has an entry for each, dated by the latest add, with a new entry when CISA adds another.

The feed's `changes` lists what happened in the window, each with a `type`: `published`, `kev_added`, `exploitation_reported` (CISA's Vulnrichment assessment newly reports active exploitation of a CVE not on KEV; it brings a CVE of any age or CVSS into the window for 90 days, as a KEV add does), `epss_crossed` or `fix_released`. The Atom feed has an entry for each.

The feed also has a `fixFirst` list. Atom entries carry the priority, the window and the reasons. The badge counts exploited CVEs.
