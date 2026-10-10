---
name: Vulnder
description: CVE alerts for your stack, ranked by real-world exploitation.
colors:
  match-violet: "#5e2ca5"
  match-violet-dark: "#b897ee"
  lavender-paper: "#f5f3f8"
  night-paper: "#131118"
  plum-ink: "#1b1724"
  pale-ink: "#eeeaf4"
  dusk-muted: "#5e5869"
  card-white: "#ffffff"
  night-card: "#1c1922"
  hairline: "#ddd8e5"
  rule: "#c9c2d4"
  control-edge: "#8d849b"
  night-hairline: "#36303f"
  night-rule: "#4a4256"
  night-control-edge: "#6f6682"
  night-muted: "#a79fb4"
  act-red-dark: "#ff8a80"
  attend-amber-dark: "#ffb74d"
  watch-yellow-dark: "#fde047"
  track-slate-dark: "#b0b6c3"
  fixed-green-dark: "#81c784"
  act-red: "#b3261e"
  attend-amber: "#b45309"
  watch-yellow: "#ca8a04"
  watch-ink: "#854d0e"
  track-slate: "#545a66"
  fixed-green: "#2e7d32"
typography:
  display:
    fontFamily: "Atkinson Next, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "clamp(2.1rem, 6vw, 3.4rem)"
    fontWeight: 800
    lineHeight: 1.02
    letterSpacing: "-0.035em"
  headline:
    fontFamily: "Atkinson Next, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "clamp(1.9rem, 5vw, 2.6rem)"
    fontWeight: 800
    lineHeight: 1.1
    letterSpacing: "-0.03em"
  title:
    fontFamily: "Atkinson Next, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "1.3rem"
    fontWeight: 700
    lineHeight: 1.25
    letterSpacing: "-0.01em"
  body:
    fontFamily: "Atkinson Next, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "Atkinson Next, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.8rem"
    fontWeight: 700
    lineHeight: 1.4
  mono:
    fontFamily: "Atkinson Mono, ui-monospace, Cascadia Code, Menlo, monospace"
    fontSize: "0.9em"
    fontWeight: 400
rounded:
  hairline: "2px"
  tag: "3px"
  control: "4px"
  pill: "999px"
spacing:
  gutter: "1rem"
  stack: "0.6rem"
  section: "2.25rem"
  column: "48rem"
components:
  button-primary:
    backgroundColor: "{colors.match-violet}"
    textColor: "{colors.card-white}"
    rounded: "{rounded.control}"
    padding: "0.6rem 1.2rem"
    height: "2.5rem"
  button-secondary:
    backgroundColor: "{colors.card-white}"
    textColor: "{colors.plum-ink}"
    rounded: "{rounded.control}"
    padding: "0.45rem 0.85rem"
    height: "2.5rem"
  input-text:
    backgroundColor: "{colors.card-white}"
    textColor: "{colors.plum-ink}"
    rounded: "{rounded.control}"
    padding: "0.6rem 0.75rem"
  chip-stack-item:
    backgroundColor: "{colors.card-white}"
    textColor: "{colors.plum-ink}"
    rounded: "{rounded.pill}"
    padding: "0.2rem 0.4rem 0.2rem 0.75rem"
  pill-priority:
    typography: "{typography.label}"
    rounded: "{rounded.tag}"
    padding: "0.05rem 0.45rem"
  result-card:
    backgroundColor: "{colors.card-white}"
    rounded: "{rounded.control}"
    padding: "0.75rem 1rem"
---

# Design System: Vulnder

## Overview

**Creative North Star: "The Triage Ledger"**

Vulnder reads like a working ledger kept by someone who patches things for a living. Sections sit directly on the page, divided by hairline rules, not boxed into cards. The order is the point: the headline count, a strip in proportion to each priority, then a numbered "Fix first" list and the evidence behind every line. IDs, versions and package names are set in mono so they can be copied and compared. Colour is spent almost entirely on risk; everything else is lavender-tinted paper and plum ink.

The density is that of a tool, not a landing page. One column (48rem) carries everything, and type does the hierarchy work: a large heavy headline asks or answers the question, and the rest is body text at a comfortable 1.55 line height. Playfulness is kept to the logo (a magnifier with a heart inside, the "it's a match" nod), the loader that sweeps the lens and beats the heart, and the tagline. Anything that describes a vulnerability stays plain.

Atkinson Hyperlegible was chosen because it tells 0/O and 1/l/I apart on pages full of CVE IDs and version strings. Fonts are self-hosted: the CSP allows no third-party fonts, and a font CDN would see every visitor.

**Key Characteristics:**
- Flat, ruled sections on tinted paper; containers only for individual results and changes.
- Traffic-light colour reserved for priority; Match Violet for action, links and brand.
- Heavy, tightly tracked headlines over calm body text.
- Mono for every identifier.
- Full light and dark themes from the same tokens, following the system setting.

## Colors

Lavender-tinted neutrals with one violet accent and a four-step traffic-light scale that means risk and nothing else.

### Primary
- **Match Violet** (light #5e2ca5, dark #b897ee): links, the primary button, the logo, focus rings and the AI tag on How it works. In dark mode, text on violet switches to Night Paper.

### Tertiary
The priority scale. Each tier sets a `--light` (fills, left borders, strip segments) and an `--ink` (text in that colour).
- **Act Red** (light #b3261e, dark #ff8a80): Act now. Exploited (on CISA KEV, or CISA reports active exploitation), or about to be. Also blocking problems: form errors, the spent-pass notice and the over-length counter.
- **Attend Amber** (light #b45309, dark #ffb74d): Attend. Likely to be exploited, or critical. Also "check this" states: close-match (`?`) chips and badges, lookup notes, and stale-data warnings.
- **Watch Yellow** (light #ca8a04, dark #fde047): Watch. High severity or a public exploit. As text on light paper it uses **Watch Ink** (#854d0e), and fills carry dark text.
- **Track Slate** (light #545a66, dark #b0b6c3): Track. Affects the stack, nothing more applies.
- **Fixed Green** (light #2e7d32, dark #81c784): good news only: a fix released, a version confirmed, a finished loader step.

### Neutral
- **Lavender Paper** (#f5f3f8; dark Night Paper #131118): page background.
- **Plum Ink** (#1b1724; dark Pale Ink #eeeaf4): body text and headings.
- **Dusk Muted** (#5e5869; dark #a79fb4): secondary text, notes, the tagline.
- **Card White** (#ffffff; dark Night Card #1c1922): result and change containers, inputs, secondary buttons.
- **Hairline** (#ddd8e5; dark #36303f): container borders, Fix-first row dividers.
- **Rule** (#c9c2d4; dark #4a4256): section rules and other decorative hairlines.
- **Control Edge** (#8d849b; dark #6f6682): the border of anything you operate (fields, buttons, segmented options, the drop zone). It holds 3:1 against paper and card in both themes (WCAG 1.4.11), which Rule does not.

### Named Rules
**The Risk Colour Rule.** Red, amber, yellow and slate mean the four priority tiers, plus the two documented extensions above (red: something blocks you; amber: something to check). Never use them for decoration, branding or generic emphasis, and never for evidence badges such as ransomware use.

**The No Opacity Dimming Rule.** Quiet text recedes through Dusk Muted, never through opacity, so it keeps its contrast. Opacity is kept for disabled controls only.

**The Green Is Good News Rule.** Green appears only when something got better (fixed, confirmed, done). It is never a tier colour.

**The Tinted Neutral Rule.** Paper and ink lean towards the brand violet. No pure greys and no pure black.

## Typography

**Display Font:** Atkinson Next (with system-ui, -apple-system, Segoe UI, sans-serif)
**Body Font:** Atkinson Next
**Label/Mono Font:** Atkinson Mono (with ui-monospace, Cascadia Code, Menlo, monospace)

**Character:** One hyperlegible family in two cuts. The sans goes very heavy (800) and tight for headlines, and stays plain for reading. The mono marks anything a user might copy or compare.

### Hierarchy
- **Display** (800, clamp(2.1rem, 6vw, 3.4rem), 1.02): the results headline ("the match"). One per view.
- **Headline** (800, clamp(1.9rem, 5vw, 2.6rem), 1.1): the compose question on the home page, prose page titles, the loader message.
- **Title** (700, 1.3rem, 1.25): section headings (h2), tier headings.
- **Body** (400, 1rem, 1.55): everything else, within the 48rem column. Small text is 0.875rem.
- **Label** (700, 0.8rem): priority pills, scores, counts, tags. Counts and scores use tabular numerals.
- **Mono** (0.9em): CVE and GHSA IDs, package names, versions, code.

### Named Rules
**The Mono Means Identifier Rule.** If a string is an ID, a package name or a version, it is set in Atkinson Mono. Prose never is.

**The One Big Line Rule.** Each view has one display or headline line. Every other heading is a title or smaller.

**The Legible For Everyone Rule.** Atkinson is the statement: a typeface built for low-vision readers, in a category where every other tool is set in Geist or Inter. Don't swap it for a trend font; push hierarchy with weight, size and tracking instead.

## Layout

A single centred column, max 48rem, with a 1rem gutter on each side. The header, main, status line and footer all share it. Sections in `main` stack on a grid with a 2.25rem gap; inside a section, items stack at about 0.6rem. The results summary is a four-column ledger (one column per tier) that drops to two columns below 48rem and one below 36rem. Rows wrap rather than scroll on narrow screens; tallies move from the right edge to their own line. There is no horizontal page scroll at phone width.

## Elevation & Depth

Flat. There are no shadows anywhere. Depth comes from three things only: a section rule above each block, a Card White surface with a hairline border for individual results, and a 4px coloured left border that ties a result, change or component row to its tier.

### Named Rules
**The Ruled Not Boxed Rule.** Sections sit on the page, divided by a rule. Only individual results and changes get a container, and containers never nest.

## Shapes

Small, square-shouldered corners: 4px for controls and containers, 3px for pills, badges and rank squares, 2px for traffic-light swatches and strip segments. Fully rounded (999px) is kept for stack chips, segmented toggles and the team picker, the things a user picks or removes. Dashed borders always mean "less certain": a close match, a local-only box in the architecture diagram, a muted badge, the drop zone.

## Components

Quiet and exact: hairline borders, a small radius, one solid primary action per view, nothing decorative.

### Buttons
- **Shape:** gently squared (4px), at least 2.5rem tall.
- **Primary:** Match Violet fill, white text (Night Paper in dark mode), 700 weight, 0.6rem 1.2rem padding. Hover mixes 15% ink into the violet.
- **Secondary:** Card White with a Rule border; hover turns the border Match Violet.
- **Link button:** no border or fill, Match Violet underlined text.
- **Disabled:** 45% opacity, not-allowed cursor, no hover change. A button locked by a spent pass uses `aria-disabled` so it can still take clicks and point at the countdown.

### Chips
- **Stack item:** fully rounded, Card White, Hairline border, a remove button on the right. Close matches get a dashed Attend Amber border; unrecognised items drop to 75% opacity.
- **Team picker:** on stacks with teams, a small rounded select on each chip.
- **Segmented control:** fully rounded options with a Rule border; the selected option inverts to ink on paper.

### Cards / Containers
- **Corner Style:** 4px.
- **Background:** Card White.
- **Shadow Strategy:** none (see Elevation & Depth).
- **Border:** 1px Hairline, plus a 4px left border in the tier's colour.
- **Internal Padding:** 0.75rem 1rem for results, 0.6rem 0.9rem for changes.

### Inputs / Fields
- **Style:** Card White, 1px Control Edge border, 4px radius, 0.6rem 0.75rem padding, inherited font, violet caret. The description textarea is at least 9rem tall and resizes vertically.
- **Focus:** a 2px Match Violet outline flush with the field, and the border turns violet. The hidden file input shows its focus as an outline around the whole drop zone.
- **Error:** a bold Act Red line just above the button it blocks (`role="alert"`), offering a way out when there is one ("Add items by hand instead"). The character counter turns Act Red and bold when over the limit.

### Notices
- **Lookup notes** (couldn't match, given teams, entries left out): a 1px Attend Amber box with a 7% amber tint, in the stack section, staying on the page rather than passing through the status line.
- **Spent pass:** the same box in Act Red with a 4px left edge and a live countdown.

### Results stack line
One line under the headline: "Your stack", a summary ("5 items: 4 exact, 1 close match"), the time window and Edit stack. The items fold away behind it when there are more than 12. A close match says "Close match" in amber words beside a dashed amber chip, never by the dash alone.

### Navigation
Plain Match Violet links aligned right in the header, wrapping under the brand on narrow screens. The current page is ink-coloured, bold and not underlined.

### Priority Pill and Rank
A 3px-radius label filled with the tier colour, 0.8rem bold. Rank squares in Fix first use the same fill with an 800-weight tabular number.

### Risk Strip
Four segments sized by the count in each tier, 0.9rem tall and 3px apart. They grow in from the left on load (0.6s, staggered 80ms), and not at all under reduced motion.

### Loader
The logo's lens circles its own centre while the heart beats, beside a headline and a checklist of steps (pending, spinning, ticked green). It fades in after 150ms so a fast response never flashes it.

## Do's and Don'ts

### Do:
- **Do** keep every page in the single 48rem column with the 1rem gutter.
- **Do** tie each result to its tier with the 4px left border and the tier's `--light` / `--ink` pair.
- **Do** set IDs, package names and versions in Atkinson Mono.
- **Do** define every colour as a token in both the light and dark blocks.
- **Do** give every animation a `prefers-reduced-motion` fallback.
- **Do** use dashed borders to say "less certain", and only for that, always alongside words.
- **Do** put the answer first on results: headline, stack line, priorities, Fix first; sharing and export go last.
- **Do** give every result a plain "What to do" line, the same steps the export writes.
- **Do** keep stacked tap targets at least 24px tall (WCAG 2.5.8).

### Don't:
- **Don't** add shadows, gradients or glassy surfaces.
- **Don't** use red, amber, yellow or slate for anything but the four tiers, or green for anything but good news.
- **Don't** nest containers or wrap whole sections in cards.
- **Don't** load third-party fonts or font CDNs.
- **Don't** switch to the category's default faces (Geist, Geist Mono, Inter, Mona Sans, Space Grotesk, Instrument Sans).
- **Don't** add vulture imagery; the brand is bugs, scanning and the match.
- **Don't** put jokes or brand playfulness into tier names, scores, reasons or vulnerability text.
