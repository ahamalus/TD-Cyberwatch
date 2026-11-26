import { createTheme, defaultVariantColorsResolver, type MantineColorsTuple, parseThemeColor, rem, type VariantColorsResolver } from "@mantine/core";
import { scales } from "./tokens";

const tuple = (s: readonly string[]) => [...s] as unknown as MantineColorsTuple;

const LIGHT_TEXT = new Set(["cyber", "secure", "amber", "threat", "info", "navy", "gray"]);

/** "light" variants (badges, alerts, buttons) use a darker text shade per colour scheme, for WCAG AA contrast. */
const variantColorResolver: VariantColorsResolver = (input) => {
  const base = defaultVariantColorsResolver(input);
  if (input.variant !== "light") return base;
  const parsed = parseThemeColor({ color: input.color || input.theme.primaryColor, theme: input.theme });
  if (parsed.isThemeColor && LIGHT_TEXT.has(parsed.color)) return { ...base, color: `var(--cw-light-text-${parsed.color})` };
  return base;
};

export const theme = createTheme({
  variantColorResolver,
  primaryColor: "cyber",
  // Shade 7 (#0F63DB): white text on filled buttons and blue link text meet WCAG AA (>= 4.5:1).
  primaryShade: { light: 7, dark: 7 },
  colors: {
    cyber: tuple(scales.cyber),
    navy: tuple(scales.navy),
    secure: tuple(scales.secure),
    amber: tuple(scales.amber),
    threat: tuple(scales.threat),
    info: tuple(scales.info),
    // Mantine's dark palette drives dark-surface colours: tuned to Midnight Navy / Deep Slate.
    dark: tuple(["#C9D3E3", "#A9B6CB", "#7D8BA3", "#55647E", "#2A3A57", "#1C2A44", "#111B2E", "#0E1726", "#0B1220", "#070C16"]),
  },
  fontFamily: "Inter, 'Segoe UI', system-ui, -apple-system, Roboto, 'Helvetica Neue', Arial, sans-serif",
  fontFamilyMonospace: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
  headings: {
    fontFamily: "Inter, 'Segoe UI', system-ui, -apple-system, Roboto, sans-serif",
    fontWeight: "650",
    sizes: {
      h1: { fontSize: rem(26), lineHeight: "1.25" },
      h2: { fontSize: rem(20), lineHeight: "1.3" },
      h3: { fontSize: rem(16), lineHeight: "1.35" },
      h4: { fontSize: rem(14), lineHeight: "1.4" },
    },
  },
  fontSizes: { xs: rem(12), sm: rem(13), md: rem(14), lg: rem(16), xl: rem(18) },
  radius: { xs: rem(4), sm: rem(6), md: rem(10), lg: rem(14), xl: rem(20) },
  defaultRadius: "md",
  spacing: { xs: rem(6), sm: rem(10), md: rem(16), lg: rem(24), xl: rem(32) },
  shadows: {
    xs: "0 1px 2px rgba(11,18,32,0.05)",
    sm: "0 1px 3px rgba(11,18,32,0.06), 0 1px 2px rgba(11,18,32,0.04)",
    md: "0 4px 12px rgba(11,18,32,0.07)",
    lg: "0 12px 28px rgba(11,18,32,0.10)",
  },
  focusRing: "auto",
  respectReducedMotion: true,
  cursorType: "pointer",
  components: {
    // Links are underlined so they are not distinguished by colour alone (WCAG 1.4.1).
    Anchor: { defaultProps: { underline: "always" } },
    Card: { defaultProps: { withBorder: true, radius: "md", padding: "lg", shadow: "xs" } },
    Paper: { defaultProps: { radius: "md" } },
    Button: { defaultProps: { radius: "md" } },
    TextInput: { defaultProps: { radius: "md" } },
    Badge: { defaultProps: { radius: "sm", variant: "light" } },
    Table: { defaultProps: { verticalSpacing: "sm", horizontalSpacing: "md" } },
    Modal: { defaultProps: { radius: "md", centered: true, overlayProps: { backgroundOpacity: 0.45, blur: 2 } } },
    Tooltip: { defaultProps: { withArrow: true, openDelay: 250, multiline: true, maw: 320 } },
  },
});
