/**
 * TrustData CyberWatch design tokens.
 *
 * All colours used by the application are defined here. Components reference
 * semantic tokens (status, severity, surface) rather than raw hex values.
 */

export const palette = {
  midnightNavy: "#0B1220",
  deepSlate: "#111B2E",
  cyberBlue: "#1677FF",
  lightBlue: "#EAF2FF",
  cloudWhite: "#F5F7FB",
  pureWhite: "#FFFFFF",
  slateGrey: "#64748B",
  borderGrey: "#E2E8F0",
  secureGreen: "#16A875",
  warningAmber: "#D99A17",
  threatRed: "#DC4545",
  infoCyan: "#0891B2",
} as const;

/** Ten-step scales for the component library (index 6 = base token). */
export const scales = {
  cyber: ["#EAF2FF", "#D3E4FF", "#A6C8FF", "#76AAFF", "#4C90FF", "#2F80FF", "#1677FF", "#0F63DB", "#0B50B3", "#073C88"],
  navy: ["#E8ECF3", "#C9D1DF", "#9AA8C0", "#6C7FA0", "#46597D", "#2B3D5F", "#1A2A47", "#111B2E", "#0B1220", "#060B14"],
  secure: ["#E6F7F0", "#C2EBDB", "#94DCC0", "#62CBA3", "#3BBC8C", "#22B07F", "#16A875", "#108A60", "#0B6C4B", "#064D35"],
  amber: ["#FDF6E5", "#FAEBC4", "#F4D88D", "#EEC457", "#E6B132", "#DFA31F", "#D99A17", "#B37E10", "#8C620B", "#654606"],
  threat: ["#FDECEC", "#F9D0D0", "#F2A6A6", "#EA7B7B", "#E35B5B", "#DF4D4D", "#DC4545", "#B93535", "#952828", "#6E1B1B"],
  info: ["#E5F6FA", "#BFE8F1", "#8FD5E6", "#5DC1DA", "#35AFCE", "#1A9FC2", "#0891B2", "#077692", "#055C72", "#034252"],
} as const;

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type Tone = "secure" | "amber" | "threat" | "info" | "gray" | "cyber";

/** Semantic status → tone. Colour is always paired with an icon and label. */
export const severityTone: Record<Severity, Tone> = {
  critical: "threat",
  high: "threat",
  medium: "amber",
  low: "info",
  informational: "gray",
};

export const space = { xs: 4, sm: 8, md: 16, lg: 24, xl: 32, xxl: 48 } as const;
export const radius = { sm: 6, md: 10, lg: 14 } as const;
export const breakpoints = { xs: "36em", sm: "48em", md: "62em", lg: "75em", xl: "88em" } as const;
