# Product pressure: when a product or release line is under fire

Status: built 2026-10-17/18 as "Targeted by attackers" (`src/match/targeted.ts`, the `targeted`
feed field), for stack items and for pasted CVE lists' products. The filings trend is weak. KEV history is strong for the product but fails as a CVE ranking signal, so it ships as an
item note only (see Decision). Raised 2026-10-17. Nothing ships until `npm run backtest -- --trend`
says it adds something KEV history doesn't already tell us. Related:
[chain-risk-and-cve-roles.md](chain-risk-and-cve-roles.md).

## The idea
Keep a running log per product, and per release line where we can (Python 3.12, FortiOS 7.2). When
high and critical CVEs in one of them pick up, tell the user to fix that item's CVEs soon or move
to a newer line, because attackers may be getting better at that code.

## What counts as pressure
CVE counts mostly measure attention: who's looking and how a CNA files. When the Linux kernel
became a CNA in 2024 its count jumped overnight. A bug-bounty push, a new fuzzer or a vendor
splitting one bulletin into twenty does the same. So a rise in filings is weak evidence that
attackers have got better.

The attacker signal is a rise in evidence for a product: KEV adds, Metasploit modules, EPSS mass
across its CVEs. That follows "evidence beats severity". The backtest tests both versions.

## The test (phase 0)
`npm run backtest -- --trend` (`runTrend` in `scripts/lib/backtest.ts`). On the first of each month,
for products with at least 10 CVEs in the previous 455 days (`cve_index.product`, the first
affected product):
- **Filings rising:** high and critical CVEs (CVSS 7.0+, or rated so when unscored) in the last 90
  days are at least 3, and more than two standard deviations (Poisson) above the previous year's
  rate.
- **Outcome:** a KEV add for that product in the next 90 days.
- **Compared with:** all eligible products, products with a KEV add in the last 90 or 365 days,
  and, the real question, products with **no** KEV add in the last year, with and without rising
  filings.

To pass, "filings rising, no KEV add in last 365 days" has to be followed by a KEV add clearly more
often than "no KEV add in last 365 days" alone, over enough product-months to trust. If only KEV
history predicts KEV, the feature becomes "this product keeps getting exploited", which is
cheaper and needs no trend maths.

## If it passes: how it would ship
- A component finding, like support dates (`src/match/support.ts`). It orders Fix first and adds
  a note to the item. It never changes a CVE's band or score, and only KEV earns "exploited".
- Data: a small daily aggregate table (product, month, high, critical, KEV adds, Metasploit
  modules), a few thousand rows, written at ingest from what `cve_index` and `exploits` already
  hold. The feed reads it by product key. Nothing per request beyond that read.
- Release lines: `vulns` keeps CVSS 7.0+ for a year (`RETAIN_CVSS`), and `eol_releases` names the
  lines. Matching `affected` ranges to lines gives "N high CVEs open on 3.12, none on 3.13". The
  most useful sentence is probably the upgrade: "Move to 3.13: none of the open high CVEs on 3.12
  affect it, and 3.12 loses support in 5 months." Code decides it, and anyone can check it.

## Not needed for this
Vectorize. Product and release-line counts are aggregates, not similarity search. Its turn comes
with the strong form of this idea: a burst of similar exploited bugs across many products at once,
meaning a new bug class rather than one product. That can start as an offline clustering job over
the embeddings families already makes, before any stored index. Storing all ~400k CVEs at 256
dimensions is about 100M stored dimensions, over the free allowance; KEV and high-EPSS CVEs alone
would fit.

## Results
First run, 2026-10-17 (local D1, monthly from 2025-01 to 2026-07, 10,800 product-months):

| Group | Product-months | Followed by a KEV add | Rate |
| --- | --- | --- | --- |
| all eligible | 10,800 | 285 | 2.6% |
| filings rising | 1,757 | 94 | 5.4% |
| KEV add in last 90 days | 283 | 90 | 31.8% |
| KEV add in last 365 days | 749 | 171 | 22.8% |
| no KEV add in last 365 days | 10,051 | 114 | 1.1% |
| filings rising, no KEV add in last 365 days | 1,559 | 31 | 2.0% |

- KEV history dominates. A product with a KEV add in the last 90 days has about a 1 in 3 chance
  of another within 90 days, 12 times the base rate.
- Rising filings add a little beyond that: among products with no KEV add in a year, 2.0% against
  0.98% for the rest. Both rates are small, and overlapping monthly windows make the result look
  stronger than it is.
- So the filings-trend version doesn't earn a feature, and the evidence version does.

### Product KEV as a CVE ranking signal (2026-10-17, `--product-kev`): it fails
Lift a CVE when another CVE of its product was added to KEV in the last 90 days.

| Variant | Act+Attend | KEV per 1,000 flags | Recall | Top 1% | Top 5% | T-7 recall |
| --- | --- | --- | --- | --- | --- | --- |
| Today | 36,084 | 2.7 | 57.5% | 45 | 64 | 69.9% |
| + product KEV, to Attend (like a sibling) | 60,184 | 1.9 | 68.9% | 38 | 53 | 78.0% |
| + product KEV, score ×1.25 only | 36,084 | 2.7 | 57.5% | 44 | 67 | 69.9% |

- The Attend version raises recall but adds 24,000 flags, lowers precision and pushes KEV CVEs out
  of the top 1%. Of the 26,287 CVE-snapshots it lifted, 32 reached KEV within 90 days (1.2 per
  1,000, under today's 2.7). It fails the bar.
- The score-only version changes almost nothing (top 1% −1, top 5% +3).
- Why: a targeted product's next KEV add is usually a *new* CVE (220 of 506 KEV CVEs were public
  for under a week before KEV), not one of its existing ones. The signal belongs to the product,
  not to its CVEs.

## Decision
Ship it as a **component finding**, the way support dates work: a note on the stack item saying
CISA has added N of its CVEs to KEV in the last 90 days (naming the latest), so the user patches
that item quickly and watches it closely. No CVE band or score changes, and no Fix first
reordering, since the backtest can't show that helps. Wording: "added to CISA KEV", never "this
product is exploited".

Cost: none per request for stack items. `vulns` keeps every CVE added to KEV within the keep window,
whatever its age (`keptLonger()` in `retention.ts`), and the component loaders already read every
row for a product, so the last 90 days of KEV adds are in memory. Pasted CVE lists take one
query (`RECENT_KEV_PRODUCTS_SQL`) over the last 90 days' KEV adds and their product rows, matched
to the list's Fix first groups in code.
