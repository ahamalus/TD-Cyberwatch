import { createHmac } from "node:crypto";
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
  for (const portal of ["admin", "ops"]) {
    await page.goto(`/${portal}/overview`);
    const nav = page.getByRole("navigation", { name: `${portal} navigation` });
    const links = await nav.getByRole("link").evaluateAll((els) => els.map((e) => e.getAttribute("href") ?? ""));
    expect(links.length).toBeGreaterThan(3);
    for (const href of links) {
      await page.goto(href);
      await expect(page.getByRole("heading", { level: 1 }).first(), `${href} has a heading`).toBeVisible();
      await expect(page, `${href} stays in the ${portal} portal`).toHaveURL(new RegExp(`/${portal}/`));
      await expect(page.getByText(/something went wrong|could not be loaded|not authorised|do not have permission/i),
        `${href} loads its data`).toHaveCount(0);
      visited++;
    }
  }
  expect(visited).toBeGreaterThan(15);
  expect(errors).toEqual([]);
});
