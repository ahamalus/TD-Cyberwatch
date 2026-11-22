import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

/**
 * Automated WCAG 2.2 A/AA checks (axe-core) on public and customer pages, in light and dark themes.
 * Automated tools catch roughly a third of accessibility problems; the rest needs a manual review
 * (keyboard-only use, screen reader, zoom), recorded in docs/ACCESSIBILITY.md.
 */

const stamp = Date.now();
const user = { email: `a11y.${stamp}@e2e.example.com`, password: "Correct-Horse-Battery-9" };
const L = (label: string) => new RegExp(`^${label}( \\*)?$`);

async function scan(page: Page, label: string): Promise<string[]> {
  await page.waitForLoadState("networkidle");
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  return results.violations.map((v) =>
    `${label}: [${v.impact}] ${v.id} - ${v.help} (${v.nodes.length}x: ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ")})`);
}

test.describe.configure({ mode: "serial" });

test("public pages have no WCAG A/AA violations", async ({ page }) => {
  const found: string[] = [];
  for (const path of ["/", "/login", "/register", "/forgot-password", "/privacy"]) {
    await page.goto(path);
    found.push(...(await scan(page, path)));
  }
  expect(found, found.join("\n")).toEqual([]);
});

test("customer pages have no WCAG A/AA violations (light and dark)", async ({ page }) => {
  await page.goto("/register");
  await page.getByLabel(L("Full name")).fill("Ada A11y");
  await page.getByLabel(L("Work email")).fill(user.email);
  await page.getByLabel(L("Organisation name")).fill(`A11y Org ${stamp}`);
  await page.getByLabel(L("Password")).fill(user.password);
  const registered = page.waitForResponse((r) => r.url().endsWith("/api/v1/auth/register"));
  await page.getByRole("button", { name: /create account/i }).click();
  await registered;
  await page.goto("/login");
  await page.getByLabel(L("Email address")).fill(user.email);
  await page.getByLabel(L("Password")).fill(user.password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/app\/[0-9a-f-]+\//);
  const base = new URL(page.url()).pathname.split("/").slice(0, 3).join("/");
  const found: string[] = [];
  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    for (const path of ["overview", "websites", "websites/new", "hosting", "hosting/new", "files", "incidents",
      "notifications", "reports", "billing", "support", "settings"]) {
      await page.goto(`${base}/${path}`);
      await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible();
      found.push(...(await scan(page, `${scheme} ${path}`)));
    }
  }
  expect(found, found.join("\n")).toEqual([]);
});
