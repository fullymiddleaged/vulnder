# How Vulnder ranks results

The short version is on the site at [How it works](https://vulnder.com/how-it-works#ranking). This is the detail.

## Priorities

Each result gets a priority, named after CISA's [SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc) decisions (Act, Attend, Track), with Watch added between Attend and Track. Evidence of exploitation always outranks prediction and severity.

| Priority | When |
|---|---|
| **Act now** (red) | On CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog, or CISA reports active exploitation. Also, before any exploitation is seen: a critical (CVSS 9.0 or more) with EPSS of 0.10 or more or LEV of 0.20 or more, EPSS of 0.50 or more at any severity, or an edge device that CISA rates automatable with total technical impact. Exploited results always sort first. |
| **Attend** (amber) | A similar CVE in the same product is on KEV or actively exploited, [EPSS](https://www.first.org/epss) of 0.10 or more, a [NIST LEV](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.41.pdf) estimate of 0.20 or more, CVSS 9.0 or more (or, with no CVSS score at all, a CNA or GitHub advisory rating it critical), a proof-of-concept exploit that is automatable or gives total control, or an edge device with a bug CISA rates automatable or total technical impact. |
| **Watch** (yellow) | CVSS 8.0 or more, a proof-of-concept exploit, a bug CISA rates automatable, or any bug CISA has assessed on an edge device. With no CVSS score at all, also a CVE whose CNA or GitHub advisory rates it high (Red Hat's "important" counts as high). |
| **Track** (grey) | Everything else: it affects your stack, but nothing above applies. |

EPSS is a *predicted* probability of exploitation in the next 30 days, not evidence that it has happened. LEV (NIST CSWP 41) adds up a CVE's daily EPSS scores into the chance it has *already* been exploited, so a CVE that was hot for weeks and has since cooled stays visible. It's an estimate, and a lower bound, because Vulnder counts only the EPSS history it has seen since it first ingested the CVE.

## Reachability

Every critical goes to Attend, whatever its EPSS: EPSS is often near zero in a CVE's first days, and a login is a thin barrier when accounts can be signed up for, bought or guessed. What an attacker needs only orders criticals within Attend. One reachable over the network with no login and no user action, or that CISA judges automatable, ranks above one that needs local access, a login or someone's help. A critical with no CVSS 3 or 4 vector gets the benefit of the doubt and ranks as reachable. From CVSS 7.0 up, each result says which applies ("Reachable over the network without a login", "Needs a login and user action").

Vulnder doesn't know which of your systems face the internet, and doesn't guess: a guess would sometimes miss one and quietly rank real risk lower. Every result is ranked as if it could be reached, so every exploited result asks for a response within 24 hours. Act now results not yet exploited get 3 days, the window CISA's [BOD 26-04](https://certcc.github.io/SSVC/howto/cisa_response/) gives an internet-facing system with an automatable, total-impact bug that isn't on KEV. If something is air-gapped or internal only, that's your call to make when you plan the fix.

BOD 26-04 itself turns on whether a system is publicly exposed: the same automatable, total-impact bug gets 3 days exposed and 60 days not. Vulnder treats edge devices as exposed, the one place it knows a system faces the internet, and everything else as not, and never gives a result longer than BOD 26-04 would. So an automatable bug is at least Watch (BOD: 60 days), and on an edge device an automatable or total-impact bug is at least Attend (14 days) and any bug CISA has assessed at least Watch (60 days). Treating everything as exposed would put about 37 times as many results in Act now as KEV does, which would bury the exploited ones. Each result lifted by one of these rules says so, for example "Edge device with an automatable bug: CISA gives internet-facing systems 14 days".

## Safety net

Results come from the time window you pick (7, 30 or 90 days). Whatever the window, these CVEs from the last year show too, marked "Older":

- added to CISA KEV in the last year, or published in it and reported by CISA as actively exploited;
- published in the last year with EPSS of 10% or more, a NIST LEV estimate of 20% or more, or CVSS 9.9 or more.

An exploited bug from six months ago that's still unpatched is exactly what shouldn't drop out of view. Ingest keeps these for a year instead of 90 days. EPSS only scores CVEs Vulnder already holds, so once a day ingest also asks FIRST for this and last year's CVEs with EPSS of 10% or more and fetches any it doesn't have; one that was dropped at 90 days and has since turned hot comes back.

## Edge devices

Some products face the internet by what they are: VPN and remote-access gateways, edge firewalls, ADCs and load balancers, web application firewalls and mail gateways (FortiGate, PAN-OS, Cisco ASA, NetScaler, BIG-IP, Ivanti Connect Secure and the like). They make up much of CISA KEV. Fixed code recognises them by product name, leaving out their management consoles and client apps, and labels them "Edge device".

Their CVEs get × 1.25 on the risk score, so they rank ahead of similar results **within the same priority**, and their item rises in Fix first. BOD 26-04's deadlines for an internet-facing system also raise their priority: automatable with total technical impact goes to Act now with 3 days, automatable or total impact to at least Attend, and anything else CISA has assessed to at least Watch (see Reachability). Being an edge device never lowers a priority, a response window or another result's score, so a wrong guess can only lift a result.

"Edge device" means internet-facing, and you know your network better than a product name does. Under Edit stack, tick **Edge device** on anything else the internet can reach directly (a customer portal, an exposed file server) and it's ranked the same way; untick it on a firewall that sits inside your network and it's ranked like any other product. Your choice goes into the link (`;edge` or `;internal`, see [STACK_FORMAT.md](STACK_FORMAT.md#edge-devices)). Only you set it: Jev never guesses it from a description. Unticking is the one way a priority can go down, and only back to what any other product would get, never below BOD 26-04's deadlines for a system that isn't exposed.

## Teams

When a description reads as an enterprise stack (Jev's screen says enterprise with 0.5 confidence or more), each item gets the team that usually looks after it: Network, Database, Front-end, Back-end, Platform, Endpoints or Business apps. Jev answers for each component you named, reading your own description; a fixed table of ecosystems, vendors and product names fills whatever Jev leaves open or can't answer. Items neither knows are Unassigned. The team goes into the link (see [STACK_FORMAT.md](STACK_FORMAT.md)), and you can change it under Edit stack. Home, small-business and lockfile stacks get no teams.

Teams only group results ("By team") and label the export. They never change a priority, a score or the order within a group.

## Risk score

Within a priority, results are ordered by a 0–100 score:

- **threat**: 1 for KEV, otherwise the higher of EPSS and LEV; at least 0.01, at least 0.1 for a critical (the EPSS that earns Attend; 0.05 when it needs a login, a user's help or local access), at least 0.2 with a proof-of-concept exploit, at least 0.3 when a similar CVE is exploited
- × **impact**: CVSS ÷ 10, at least 0.9 for total technical impact, 0.5 without CVSS
- × 1.25 if automatable, × 1.25 on an edge device, × 1.2 if used in ransomware
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
| `family`, `related` | Similar CVEs; `related` lists the other results in the feed from the same family |
| `tier` | The older exploited / likely / backlog field, from KEV and EPSS only; unchanged |

The feed also has a `fixFirst` list. Atom entries carry the priority, the window and the reasons. The badge counts exploited CVEs.
