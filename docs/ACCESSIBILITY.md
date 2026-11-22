# Accessibility (WCAG 2.2 AA)

## Automated checks (every push, in CI)
The browser tests (`frontend/e2e/`) run **axe-core** with the WCAG 2.0/2.1/2.2 A and AA rules on:
- **Public pages:** landing, sign-in, registration, password reset.
- **Customer pages:** every page in both light and dark themes, including the website and hosting wizards.
- **Staff portals:** every administration and operations menu entry.

Any violation fails the build.

## Fixed in the November 2026 review
| Issue (WCAG criterion) | Where | Fix |
|---|---|---|
| Text contrast below 4.5:1 (1.4.3) | Secondary ("dimmed") text everywhere: #868e96 = 3.1–3.3:1 | Theme colour #5f6b7a light (≥4.8:1), #94a3b8 dark (≥5.6:1) |
| White on brand blue 4.1:1 (1.4.3) | All primary buttons, links, active menu item | Interactive blue is shade #0f63db (5.5:1); #1677ff kept for borders/decoration only |
| Light badges/alerts below 4.5:1 (1.4.3) | e.g. amber badge 3.2:1 | Light-variant text uses the darkest shade per colour (scheme-aware) |
| Fixed light-theme shades on dark backgrounds (1.4.3) | Operations portal warnings, stat-card links | Scheme-aware text colours (`--cw-light-text-*`) |
| Links identified by colour only (1.4.1) | Links inside sentences | All links underlined |
| Accessible name hides visible text (2.5.3) | Logo link, account menu, overview stat cards | Names come from the visible content |
| Scrollable table not keyboard reachable (2.1.1) | Wide tables, chart data tables | Scroll regions are focusable, labelled regions |

## Still to be checked by a person
Automated tools find only part of the problems. Before claiming conformance, someone should do one review
pass covering:
- **Keyboard only:** every journey (sign-up, connect hosting, add website, close an incident, refund) with
  the Tab key, visible focus, no traps, and a working skip link.
- **Screen reader:** NVDA with Firefox on Windows, and VoiceOver on iPhone. Check that headings and
  landmarks make sense, that form errors are announced, and that toast notifications are announced (they
  should be polite live regions).
- **Zoom and reflow:** at 200% and 400% zoom, and at a 320 px width, there should be no horizontal page
  scroll except inside data tables.
- **Motion:** reduced motion is respected (the theme sets `respectReducedMotion`).
- **Content:** error messages say how to fix the problem, and time limits are announced (session expiry).

Record results and remaining issues here. Fix any blocker before calling the platform WCAG 2.2 AA
conformant.
