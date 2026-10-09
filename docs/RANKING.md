# How Vulnder ranks results

The short version is on the site at [How it works](https://vulnder.com/how-it-works#ranking). This is the detail.

## Priorities

Each result gets a priority, named after CISA's [SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc) decisions (Act, Attend, Track), with Watch added between Attend and Track. Evidence of exploitation always outranks prediction and severity.

| Priority | When |
|---|---|
| **Act now** (red) | On CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog, or CISA reports active exploitation. |
| **Attend** (amber) | A similar CVE in the same product is on KEV or actively exploited, [EPSS](https://www.first.org/epss) of 0.10 or more, a [NIST LEV](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.41.pdf) estimate of 0.20 or more, CVSS 9.0 or more that an attacker can reach, or a proof-of-concept exploit that is automatable or gives total control. |
| **Watch** (yellow) | CVSS 8.0 or more, CVSS 7.0 or more within reach on an internet-facing item, a proof-of-concept exploit, or automatable with total technical impact. With no CVSS score at all, also a CVE whose CNA or GitHub advisory rates it critical or high (Red Hat's "important" counts as high). |
| **Track** (grey) | Everything else: it affects your stack, but nothing above applies. |

EPSS is a *predicted* probability of exploitation in the next 30 days, not evidence that it has happened. LEV (NIST CSWP 41) adds up a CVE's daily EPSS scores into the chance it has *already* been exploited, so a CVE that was hot for weeks and has since cooled stays visible. It's an estimate, and a lower bound, because Vulnder counts only the EPSS history it has seen since it first ingested the CVE.

## Reachability

A CVSS score says how bad a bug is, not whether anyone can get at it. A critical goes to Attend only when its CVSS vector says it's reachable over the network with no login and no user action, or CISA judges it automatable. Criticals that need local access, a login or someone's help go to Watch. A critical with no CVSS 3 or 4 vector stays in Attend. From CVSS 7.0 up, each result says which applies ("Reachable over the network without a login", "Needs a login and user action").

## Internet-facing items

Mark items as internet-facing on the Edit page, or with `!` in the link (see [STACK_FORMAT.md](STACK_FORMAT.md)). On those items, a bug reachable with no login and no user action, or that CISA judges automatable, counts for more: CVSS 7.0 or more goes to Watch, its score gets × 1.25, and its reasons say "Internet-facing". A missing vector gets no benefit of the doubt. The mark only reorders results; it never hides one.

From a description, two things mark components for you:

- Products that face the internet by what they are (VPN and remote-access gateways, edge firewalls, ADCs, mail gateways such as FortiGate, Cisco ASA, PAN-OS or NetScaler) are always marked.
- Jev marks what your description says or clearly implies faces the internet ("nginx in front", "our public API"), when it is fairly sure (0.7 or more).

The results page lists what was marked; untick any under Edit stack. Manifests are never marked automatically. The mark goes into the link, so a shared link says which of your systems face the internet.

## Risk score

Within a priority, results are ordered by a 0–100 score:

- **threat**: 1 for KEV, otherwise the higher of EPSS and LEV; at least 0.2 with a proof-of-concept exploit, at least 0.3 when a similar CVE is exploited, 0.01 before EPSS has scored it
- × **impact**: CVSS ÷ 10, at least 0.9 for total technical impact, 0.5 without CVSS
- × 1.25 if automatable, × 1.25 if internet-facing and within reach, × 1.2 if used in ransomware
- capped at 100

It's a heuristic for ordering, not a probability. Exploitation status, automatability and technical impact come from CISA's [Vulnrichment](https://github.com/cisagov/vulnrichment) data in CVE records.

**Fix first** ranks the items in your stack: the one with the most urgent priority first, then by the total risk score of its CVEs, since one upgrade usually closes several.

## Similar CVEs

CVEs in the same product whose descriptions are nearly the same are grouped into families: one flaw filed twice (by a CNA and in a GitHub advisory), variants of one flaw, or a vendor bulletin's batch. Ingest embeds each CVE's title once with a Workers AI embedding model (CVE text only, never yours, with the product's own name removed) and compares it with similar CVEs in the same product. Code decides at a calibrated threshold.

The results page folds each family under its highest-ranked member ("+3 similar CVEs in this product") and hides nothing. When a member is on KEV or actively exploited, the others go to at least Attend with the reason "Similar to exploited CVE-… in the same product". That's a reason to look, not evidence about the CVE itself, so it never reaches Act now.

## Why, when, and what to do

Each result names the signal that decided its priority, lists the rest, and says what data wasn't available ("No CVSS score yet"), so a quiet result reads as unknown, not safe. It suggests a time to respond: 24 hours for Act now on an internet-facing item, 48 hours otherwise, 7 days for Attend, 30 days for Watch. These are guidance, not deadlines. It also says what to do: confirm a close match or an unconfirmed version, then upgrade to a fixed version or, with none known, apply CISA's required action or a mitigation.

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
