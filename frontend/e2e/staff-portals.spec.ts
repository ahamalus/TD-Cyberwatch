import { createHmac } from "node:crypto";
import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

/**
 * Trust Data staff: a platform administrator (created by e2e/stack.sh) must enrol MFA before any platform
 * function works, then every administration and operations page must render, staying in its own portal.
 */

const ADMIN = { email: "admin@e2e.example.com", password: "E2e-Staff-Password-42" };

test.describe.configure({ mode: "serial" });

/** RFC 6238 TOTP (SHA-1, 30 s, 6 digits) from a base32 secret, as an authenticator app computes it. */
function totp(secret: string, at = Date.now()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
  const h = createHmac("sha1", key).update(counter).digest();
  const o = h[h.length - 1] & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

let secret = "";

function trackErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(e.message));
  return errors;
}

async function passwordStep(page: Page) {
  await page.goto("/login");
  await page.getByLabel(/^Email address( \*)?$/).fill(ADMIN.email);
  await page.getByLabel(/^Password( \*)?$/).fill(ADMIN.password);
  await page.getByRole("button", { name: /sign in/i }).click();
}

async function enterCode(page: Page, code: string) {
  const first = page.getByLabel(/(verification|authentication) code/i).first();
  await first.click();
  await page.keyboard.type(code);
}

test("staff must enrol MFA before using platform functions", async ({ page }) => {
  const errors = trackErrors(page);
  await passwordStep(page);
  await expect(page).toHaveURL(/\/staff\/security/);
  await page.getByRole("button", { name: "Set up MFA" }).click();
  secret = ((await page.locator("pre, code").filter({ hasText: /^[A-Z2-7]{16,}=*$/ }).first().textContent()) ?? "").trim();
  expect(secret).toMatch(/^[A-Z2-7]{16,}/);
  await enterCode(page, totp(secret));
  await page.getByRole("button", { name: "Verify and enable" }).click();
  await expect(page.getByText("Save your recovery codes")).toBeVisible();
  expect(errors).toEqual([]);
});

test("every administration and operations page renders in its own portal", async ({ page }) => {
  const errors = trackErrors(page);
  await passwordStep(page);
  // Next 30-second window if the enrolment code was just used (codes are single-use).
  await enterCode(page, totp(secret, Date.now() + 30_000));
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page).toHaveURL(/\/admin/);
  // Walk exactly what each portal's menu offers this role: every entry must load, in its own portal.
  let visited = 0;
  const a11y: string[] = [];
  for (const portal of ["admin", "ops"]) {
    await page.goto(`/${portal}/overview`);
    const nav = page.getByRole("navigation", { name: `${portal} navigation` });
    await expect(nav.getByRole("link").first()).toBeVisible(); // the menu renders after the session loads
    const links = await nav.getByRole("link").evaluateAll((els) => els.map((e) => e.getAttribute("href") ?? ""));
    expect(links.length).toBeGreaterThan(3);
    for (const href of links) {
      await page.goto(href);
      await expect(page.getByRole("heading", { level: 1 }).first(), `${href} has a heading`).toBeVisible();
      await expect(page, `${href} stays in the ${portal} portal`).toHaveURL(new RegExp(`/${portal}/`));
      await expect(page.getByText(/something went wrong|could not be loaded|not authorised|do not have permission/i),
        `${href} loads its data`).toHaveCount(0);
      await page.waitForLoadState("networkidle");
      const scan = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
      a11y.push(...scan.violations.map((v) => `${href}: [${v.impact}] ${v.id} - ${v.help} (${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ")})`));
      visited++;
    }
  }
  expect(visited).toBeGreaterThan(15);
  expect(a11y, `WCAG A/AA violations:\n${a11y.join("\n")}`).toEqual([]);
  expect(errors).toEqual([]);
});

test("a customer's cleanup request reaches the service desk and the reply comes back", async ({ page, browser }) => {
  test.slow();
  const axe = async (p: Page, label: string) => (await new AxeBuilder({ page: p })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze()).violations
    .map((v) => `${label}: [${v.impact}] ${v.id} - ${v.help} (${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ")})`);
  const a11y: string[] = [];
  const L = (label: string) => new RegExp(`^${label}( \\*)?$`);

  // Customer: register, sign in, order a malware cleanup from the service catalogue.
  const stamp = Date.now();
  const ctx = await browser.newContext();
  const cust = await ctx.newPage();
  const errors = [...trackErrors(page), ...trackErrors(cust)];
  await cust.goto("/register");
  await cust.getByLabel(L("Full name")).fill("Desk Customer");
  await cust.getByLabel(L("Work email")).fill(`desk.${stamp}@e2e.example.com`);
  await cust.getByLabel(L("Organisation name")).fill(`Desk Org ${stamp}`);
  await cust.getByLabel(L("Password")).fill("Correct-Horse-Battery-9");
  const registered = cust.waitForResponse((r) => r.url().endsWith("/api/v1/auth/register"));
  await cust.getByRole("button", { name: /create account/i }).click();
  await registered;
  await cust.goto("/login");
  await cust.getByLabel(L("Email address")).fill(`desk.${stamp}@e2e.example.com`);
  await cust.getByLabel(L("Password")).fill("Correct-Horse-Battery-9");
  await cust.getByRole("button", { name: /sign in/i }).click();
  await expect(cust).toHaveURL(/\/app\/[0-9a-f-]+\//);
  const base = new URL(cust.url()).pathname.split("/").slice(0, 3).join("/");
  await cust.goto(`${base}/support`);
  await cust.getByRole("button", { name: "Request" }).first().click();
  const subject = `Hacked site ${stamp}`;
  await cust.getByLabel(L("Subject")).fill(subject);
  await cust.getByLabel(L("Details")).fill("Visitors are redirected to a spam site.");
  await cust.getByRole("button", { name: "Submit" }).click();
  await expect(cust).toHaveURL(/\/support\/[0-9a-f-]+$/);
  await expect(cust.getByRole("heading", { name: subject })).toBeVisible();
  await expect(cust.getByText("Authorise the work")).toBeVisible();
  await cust.waitForLoadState("networkidle");
  a11y.push(...(await axe(cust, "customer request page")));

  // Staff: next code window (codes are single-use), then work the request.
  await page.waitForTimeout(30_000 - (Date.now() % 30_000) + 1_000);
  await passwordStep(page);
  await enterCode(page, totp(secret, Date.now() + 30_000));
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page).toHaveURL(/\/admin/);
  await page.goto("/ops/service-desk");
  await page.getByText(subject).click();
  await expect(page).toHaveURL(/\/ops\/service-desk\/[0-9a-f-]+$/);
  await expect(page.getByText("Not authorised yet")).toBeVisible();
  await page.waitForLoadState("networkidle");
  a11y.push(...(await axe(page, "staff workbench")));
  await page.getByRole("button", { name: "Assign to me" }).click();
  await expect(page.getByText(/Assigned to/)).toBeVisible();
  await page.getByLabel("Message").fill("We are on it. Please authorise the cleanup on your request page.");
  await page.getByRole("button", { name: "Send to customer" }).click();
  await expect(page.getByText("We are on it.")).toBeVisible();

  await cust.reload();
  await expect(cust.getByText("We are on it.")).toBeVisible();
  expect(a11y, `WCAG A/AA violations:\n${a11y.join("\n")}`).toEqual([]);
  expect(errors).toEqual([]);
  await ctx.close();
});
