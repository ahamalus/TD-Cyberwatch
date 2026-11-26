# CyberWatch design system

Location: `frontend/src/design/` (tokens, Mantine theme, global CSS) and `frontend/src/components/`
(reusable components). All three portals use the same shell and components.

## Brand
- Name: **TrustData CyberWatch** — "TrustData" in Cyber Blue, "CyberWatch" in navy/white.
- Parent: Trust Data Compliance Ltd (shown under the wordmark and in reports).
- Tagline: *Continuous Monitoring. Smarter Protection. Greater Trust.*
- Mark: shield with check (`BrandMark` in `components/ui.tsx`, `public/favicon.svg`). Replace the SVG to
  rebrand; nothing else depends on it.

## Colour tokens (`design/tokens.ts`)
| Token | Hex | Use |
|---|---|---|
| Midnight Navy | #0B1220 | Operations background, headings |
| Deep Slate | #111B2E | Dark panels |
| Cyber Blue | #1677FF | Primary actions, links, active nav |
| Light Blue | #EAF2FF | Selection, active nav (light) |
| Cloud White | #F5F7FB | Light page background |
| Pure White | #FFFFFF | Cards |
| Slate Grey | #64748B | Secondary text |
| Border Grey | #E2E8F0 | Borders |
| Secure Green | #16A875 | Healthy/success |
| Warning Amber | #D99A17 | Warnings/partial |
| Threat Red | #DC4545 | Critical/failed |
| Informational Cyan | #0891B2 | Informational |

Each base colour is expanded to a 10-step Mantine scale (`cyber`, `navy`, `secure`, `amber`, `threat`,
`info`). Surfaces are CSS variables (`--cw-page-bg`, `--cw-surface`, `--cw-line`…) redefined for light
and dark schemes in `global.css`.

## Themes
- Customer and administration: light by default. Operations: dark by default.
- The theme toggle persists per portal (local storage) and, for customers, to the account preference.

## Typography and spacing
Inter / system UI; headings 26/20/16/14 px; body 14 px; metadata 12 px; metrics use tabular numerals
(`.cw-metric`). Spacing scale 6/10/16/24/32 px; radii 6/10/14 px; four elevation levels.

## Components
`PageHeader` (title, description, breadcrumbs, actions) · `Section` · `StatCard` (label, metric, context,
trend, drill-down) · `DataTable` (sorting, pagination, loading skeletons, empty and error states, row
actions, keyboard row activation) · `SearchInput` · `KeyValue` · `EmptyState` · `ErrorState` ·
`LoadingBlock` · `ConfirmButton` (confirmation dialog) · `DemoBanner` · charts `StackedBars` (with
chart/table toggle) and `Donut`.

Security status components (`components/status.tsx`), all icon + label + colour:
`SeverityBadge` (Critical/High/Medium/Low/Info) · `IncidentStatusBadge` · `HealthBadge`
(Healthy/Degraded/Failed/Unknown and coverage states) · `ConnectionBadge` (Connected/Disconnected/Expired…) ·
`ScanBadge` (Successful/Failed/Partial/Incomplete) · `VerificationBadge` (Verified/Unverified findings) ·
`SubscriptionBadge` (Active/Trial/Grace period/Cancelled/Expired) · `CapabilityBadge`.

## Accessibility
Skip link, landmark navigation, visible focus (Mantine focus ring), labelled inputs, `aria-label` on icon
buttons, `role="alert"` for errors, charts with text summaries and tabular alternatives, reduced-motion
respected, colour never the only signal. Target: WCAG 2.2 AA (not yet independently audited).

## Representative screens implemented
Customer dashboard, websites list + onboarding wizard + detail, hosting connection + capability discovery,
incident centre + investigation view, file integrity, notifications, reports, billing, support, settings;
platform overview, customers, access control, connectors, plans, payments, messaging, managed services,
analytics, audit, configuration; operations overview, scan queue, diagnostics, incidents, notifications,
worker health. Responsive from 360 px (drawer navigation, stacked cards, horizontally scrollable tables).
