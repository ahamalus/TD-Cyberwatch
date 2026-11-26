import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { theme } from "../design/theme";
import { InvestigationSection } from "../pages/ops/ServiceDesk";

afterEach(() => vi.restoreAllMocks());

const at = "2026-11-26T10:00:00+00:00";
const result = {
  logs: { requests: 33, from: at, to: at },
  notes: ["Vulnerability check not configured (set CW_WORDFENCE_API_KEY)."],
  hypotheses: [
    { kind: "password", confidence: "high", title: "WordPress login with a valid password", detail: "Reset passwords.", file: "wp-content/uploads/x.php",
      evidence: [{ at, ip: "203.0.113.66", method: "POST", path: "/wp-login.php", status: 302 }] },
  ],
  pivots: [{ path: "wp-content/uploads/x.php", time: at, time_source: "file modification time", reasons: ["script in upload dir"], logs_cover_time: true,
    used_by: [{ ip: "203.0.113.66", requests: 1, first: at }], window: [{ at, ip: "203.0.113.66", method: "POST", path: "/wp-content/plugins/p/u.php", query: "", status: 200, attacker_ip: true }], window_total: 1 }],
  attacker_ips: [{ ip: "203.0.113.66", requests: 28, first_seen: at, last_seen: at, logins: 26, agents: ["python-requests"],
    first_requests: [{ at, method: "POST", path: "/wp-login.php", status: 200 }] }],
  software: [
    { type: "plugin", slug: "hello-dolly", name: "Hello Dolly", root: "", version: "1.7.2", latest: "1.7.3", outdated: true,
      vulnerabilities: [{ id: "v1", cve: "CVE-2026-0001", cvss: 9.8, title: "File upload", patched_versions: ["1.7.3"] }] },
    { type: "core", slug: "wordpress", name: null, root: "", version: "6.8.0", latest: "6.8.0", outdated: false, vulnerabilities: [] },
  ],
};

it("renders a finished investigation", async () => {
  vi.spyOn(api, "get").mockResolvedValue({ allowed: true, investigation: { id: "i1", status: "done", started_at: at, finished_at: at, error: null, result, report_text: "How the attacker most likely got in:\n- ..." } });
  render(
    <MantineProvider theme={theme}>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter><InvestigationSection d={{ id: "t1", report: {} }} onReport={() => undefined} /></MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
  expect(await screen.findByText("WordPress login with a valid password")).toBeTruthy();
  expect(screen.getByText(/1 known vulnerability/)).toBeTruthy();
  expect(screen.getByText(/Up to date/)).toBeTruthy();
  expect(screen.getByRole("button", { name: "Add to report" })).toBeTruthy();
  expect(screen.getAllByText(/203\.0\.113\.66/).length).toBeGreaterThan(1);
});

it("shows nothing to staff without the access grant", async () => {
  vi.spyOn(api, "get").mockResolvedValue({ allowed: false, investigation: null });
  const { container } = render(
    <MantineProvider theme={theme}>
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter><InvestigationSection d={{ id: "t1", report: {} }} onReport={() => undefined} /></MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
  await new Promise((r) => setTimeout(r, 50));
  expect(container.textContent).not.toContain("Investigate entry point");
});
