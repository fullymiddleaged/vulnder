---
target: home page and results view
total_score: 24
max_score: 40
na_heuristics: 
p0_count: 0
p1_count: 4
target_identity: "file:C:\\vscode\\vulnture\\public\\index.html"
target_fingerprint: "sha256:0b21281a75479f292d78d8eded79096ddfe759c083642d6b94319bf597104c3e"
target_path: "C:\\vscode\\vulnture\\public\\index.html"
timestamp: 2026-10-09T08-06-13Z
slug: public-index-html
---
Method: dual-agent (A: design review · B: detector + contrast + markup). No browser automation; assessed from source.

## Design health score
| # | Heuristic | Score | Key issue |
|---|---|---|---|
| 1 | Visibility of system status | 3 | Loader steps are timed, not real progress; messages land in a muted line below everything |
| 2 | Match with real world | 2 | KEV, EPSS, LEV, "Automatable", "Total technical impact" with no inline explanation |
| 3 | User control and freedom | 3 | URL-based, Back works; no confirm step before results, chip removal has no undo |
| 4 | Consistency and standards | 3 | Close-match chips not amber as designed; Attend note omits criteria listed on How it works |
| 5 | Error prevention | 2 | Add-item needs ecosystem:pkg@ver / p:vendor/product syntax; Turnstile failures never surfaced |
| 6 | Recognition over recall | 2 | Definitions only in title tooltips |
| 7 | Flexibility and efficiency | 3 | Feeds/badge/export strong; forced ~1.75s loader floor |
| 8 | Aesthetic and minimalist | 2 | One CVE can appear four times; eight controls above the answer |
| 9 | Error recovery | 2 | Errors are grey text under results; Turnstile failure loops on "Please wait" |
| 10 | Help and documentation | 2 | /how-it-works#ranking exists but the app never links to it |
| Total | | 24/40 | Acceptable |

## Design specificity verdict
Top half is distinctly Vulnder (Atkinson, ruled ledger, mono IDs, risk strip, numbered Fix first, magnifier-heart loader). Result cards are a generic row of up to seven badges; the "match" idea lives only in copy because submit skips the confirm step. Detector: 30 findings in public/; true: SVG text 8-9px on phones, .notice 3px vs 4px, loader size vs DESIGN.md; false: six side-tab (deliberate tier borders), seven colour (dark tokens only in prose). web/ TS not scanned.

## Priority issues
- [P1] Answer buried under tooling: stack chips + 7 buttons + select before the headline (web/main.ts:541-566). Fix: headline, ledger, Fix first first; collapse stack; Share and subscribe group after results; remove duplicate CVE listings. /impeccable layout, /impeccable distill
- [P1] Important notes vanish: "Couldn't match", "Checked N of M", exposure notes only via say() to #status (web/main.ts:526); zero-results headline can falsely reassure. Fix: persistent notice in stack section; honest headline. /impeccable harden, /impeccable clarify
- [P1] No plain "what to do": export.ts remediation() steps only in export file; "Product match" consequence unexplained; no tier time windows; jargon in tooltips only. Fix: What to do line, Upgrade to ≥X, windows per tier, inline definitions, How we rank link. /impeccable clarify, /impeccable onboard
- [P1] Playful headline at the most stressful moment: "It's a match. Unfortunately." / "Red flags, ranked:" (web/format.ts:25-26); exploited count only in document.title. Fix: lead with the fact; keep play for zero state. /impeccable clarify
- [P2] Forced wait: done(true) ticks remaining steps at 250ms (web/main.ts:330-338). Fix: skip for fast responses. /impeccable optimize

## Persona red flags
- Jordan: "manifest" jargon; EPSS percentile, LEV, "Total risk 143" vs 0-100 scores; add-item syntax dead end.
- Sam: invisible focus on file input; Fix first summary reads as run-on; focus lost after Start over/Edit; errors polite, unstyled, last.
- Alex: 1.75s floor every load; days change spends the hourly pass; can't hide Track or duplicates.
- Priya (ops owner, no security team): no tier time windows; Fix first lacks target version; "What changed this week" fixed at 7 days while selector says 30.

## Minor observations
- .chip.ambiguous dead; .chip.close only a faint dashed hairline.
- Ransomware pill and KEV/EPSS event tags reuse tier colours (breaks Risk Colour Rule).
- "+N more below" smooth-scrolls regardless of reduced motion (web/main.ts:625).
- Empty tiers render "Nothing here." in By priority view.

## Questions to consider
- If "the match" is the brand, why skip the moment a user could confirm their matches?
- If the page answered only "what do I patch this week, and to which version", would four tiers, two scores and seven badges survive?
- Would you ship "It's a match. Unfortunately." on the day someone finds an Act now CVE on their own firewall?

## Audit (technical) 15/20 Good
A11y 2 (--rule 1.57:1 fails 1.4.11 for input borders; invisible #file focus; opacity-dimmed text 2.17-2.38:1; .tile-vulns links ~21px stacked), Performance 3, Theming 4, Responsive 3, Integrity 3.
