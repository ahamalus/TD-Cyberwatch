import { appendFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, type Page, test } from "@playwright/test";

/**
 * The core customer journey through the real UI and backend: sign up, connect hosting over SFTP, add a
 * website, take a baseline scan, detect a simulated compromise, and close a finding as a false positive.
 */

const SITE = join(process.env.E2E_STATE_DIR ?? "/tmp/cw-e2e", "site", "public_html");
const stamp = Date.now();
const user = { name: "Ada Okafor", email: `ada.${stamp}@e2e.example.com`, org: `E2E Org ${stamp}`, password: "Correct-Horse-Battery-9" };

/** Exact field label; Mantine appends " *" to required fields. */
const L = (label: string) => new RegExp(`^${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}( \\*)?$`);

test.describe.configure({ mode: "serial" });

function trackErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(e.message));
  return errors;
}

/** Customer portal base path (/app/<tenant>) of the signed-in user. */
function base(page: Page): string {
  return new URL(page.url()).pathname.split("/").slice(0, 3).join("/");
}

async function signIn(page: Page) {
  await page.goto("/login");
  await page.getByLabel(L("Email address")).fill(user.email);
  await page.getByLabel(L("Password")).fill(user.password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/app\/[0-9a-f-]+\//);
}

async function pick(page: Page, label: string, option: string | RegExp) {
  await page.getByRole("textbox", { name: L(label) }).click();
  await page.getByRole("option", { name: option }).click();
}

async function scanAndWait(page: Page) {
  // On the website page: /app/<tenant>/websites/<id>
  const [, , tenant, , website] = new URL(page.url()).pathname.split("/");
  const api = `/api/v1/tenants/${tenant}/websites/${website}`;
  const before = (await (await page.request.get(api)).json()).last_scan_at;
  await page.getByRole("button", { name: "Scan files" }).click();
  // The scan runs on the worker.
  await expect.poll(async () => {
    const w = await (await page.request.get(api)).json();
    return w.last_scan_at !== before ? w.last_scan_status : "pending";
  }, { timeout: 90_000, intervals: [1_000] }).toMatch(/completed|partial/);
}

test("sign up and see an empty overview", async ({ page }) => {
  const errors = trackErrors(page);
  await page.goto("/register");
  await page.getByLabel(L("Full name")).fill(user.name);
  await page.getByLabel(L("Work email")).fill(user.email);
  await page.getByLabel(L("Organisation name")).fill(user.org);
  await page.getByLabel(L("Password")).fill(user.password);
  const registered = page.waitForResponse((r) => r.url().endsWith("/api/v1/auth/register"));
  await page.getByRole("button", { name: /create account/i }).click();
  expect((await registered).status()).toBe(201);
  await signIn(page);
  await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible();
  expect(errors).toEqual([]);
});

test("connect hosting, add a website and take a baseline", async ({ page }) => {
  const errors = trackErrors(page);
  await signIn(page);
  await page.goto(`${base(page)}/hosting/new`);
  await page.getByLabel(L("Connection name")).fill("Sample SFTP");
  await page.getByLabel(L("Server hostname")).fill("127.0.0.1");
  await page.getByLabel(L("Port")).fill("2222");
  await page.getByLabel(L("SFTP username")).fill("sampleuser");
  await page.getByLabel(L("Authorised root directory")).fill("/public_html");
  await page.getByRole("textbox", { name: L("Password") }).fill("sample-password-e2e");
  await page.getByRole("button", { name: "Save and test connection" }).click();
  await expect(page.getByText(/connected/i).first()).toBeVisible({ timeout: 60_000 });

  await page.goto(`${base(page)}/websites/new`);
  await page.getByLabel(L("Display name")).fill("Sample site");
  await page.getByLabel(L("Website URL")).fill("https://sample.e2e.example.com/");
  await page.getByRole("button", { name: "Continue" }).click();
  await pick(page, "Hosting connection", /Sample SFTP/);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Add website" }).click();
  await expect(page.getByRole("heading", { name: "Sample site" })).toBeVisible();

  await scanAndWait(page);
  await page.goto(`${base(page)}/files`);
  await pick(page, "Website", "Sample site");
  await page.getByRole("tab", { name: "File inventory" }).click();
  await expect(page.getByText("index.html", { exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});

test("a simulated compromise opens an incident that can be closed as a false positive", async ({ page }) => {
  const errors = trackErrors(page);
  // Inert text that only looks like a web shell; nothing is executed.
  writeFileSync(join(SITE, "wp-content", "uploads", `wso-shell-${stamp}.php`), "<?php /* e2e test file, not code */ ?>\n");
  appendFileSync(join(SITE, "index.html"), "\n<!-- simulated defacement -->\n");
  await signIn(page);
  await page.goto(`${base(page)}/websites`);
  await page.getByRole("row", { name: /Sample site/ }).click();
  await expect(page.getByRole("heading", { name: "Sample site" })).toBeVisible();
  await scanAndWait(page);

  await page.goto(`${base(page)}/incidents`);
  const incident = page.getByText(`wso-shell-${stamp}.php`).first();
  await expect(incident).toBeVisible();
  await incident.click();
  await expect(page).toHaveURL(/\/incidents\/[0-9a-f-]+$/);
  await page.getByLabel(L("Resolution notes")).fill("E2E: planted test file, not a real threat.");
  await page.getByLabel(L("Classify as false positive")).check();
  await page.getByRole("button", { name: "Close" }).click();
  await expect(page.getByText("False positive").first()).toBeVisible();
  expect(errors).toEqual([]);
});

test("every customer page renders without errors", async ({ page }) => {
  const errors = trackErrors(page);
  await signIn(page);
  const root = base(page);
  for (const path of ["overview", "websites", "hosting", "files", "incidents", "notifications", "reports", "billing", "support", "settings"]) {
    await page.goto(`${root}/${path}`);
    await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible();
    await expect(page.getByText(/something went wrong|failed to load/i)).toHaveCount(0);
  }
  expect(errors).toEqual([]);
});
