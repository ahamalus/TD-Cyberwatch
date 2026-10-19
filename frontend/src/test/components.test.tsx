import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, errorMessage } from "../api/client";
import { humanize } from "../components/format";
import { CapabilityBadge, HealthBadge, ScanBadge, SeverityBadge } from "../components/status";
import { DataTable, ErrorState } from "../components/ui";
import { theme } from "../design/theme";
import { LoginPage } from "../pages/public/Auth";

function wrap(ui: ReactNode, path = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MantineProvider theme={theme}>
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route path="*" element={ui} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
}

afterEach(() => vi.restoreAllMocks());

describe("status indicators", () => {
  it("always render a text label, never colour alone", () => {
    wrap(
      <>
        <SeverityBadge severity="critical" />
        <HealthBadge state="degraded" />
        <ScanBadge status="partial" />
        <ScanBadge status={null} />
        <CapabilityBadge status="unsupported" />
      </>,
    );
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByText("Degraded")).toBeInTheDocument();
    expect(screen.getByText("Partial")).toBeInTheDocument();
    expect(screen.getByText("No scan yet")).toBeInTheDocument();
    expect(screen.getByText("Unsupported")).toBeInTheDocument();
  });

  it("distinguishes failed scans from successful ones", () => {
    wrap(
      <>
        <ScanBadge status="failed" />
        <ScanBadge status="completed" />
      </>,
    );
    expect(screen.getByText("Failed")).toBeInTheDocument();
    expect(screen.getByText("Successful")).toBeInTheDocument();
  });
});

describe("DataTable", () => {
  const cols = [{ key: "n", header: "Name", render: (r: { n: string }) => r.n }];

  it("shows the empty state", () => {
    wrap(<DataTable rows={[]} columns={cols} rowKey={(r) => r.n} empty={<p>Nothing here</p>} />);
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
  });

  it("shows the loading state accessibly", () => {
    const { container } = wrap(<DataTable rows={undefined} loading columns={cols} rowKey={(r) => r.n} />);
    expect(container.querySelectorAll(".mantine-Skeleton-root").length).toBeGreaterThan(0);
  });

  it("shows errors without stack traces and supports retry", async () => {
    const retry = vi.fn();
    wrap(<DataTable rows={undefined} error={new ApiError(500, "internal_error", "An unexpected error occurred.")} onRetry={retry} columns={cols} rowKey={(r) => r.n} />);
    expect(screen.getByRole("alert")).toHaveTextContent("An unexpected error occurred.");
    await userEvent.click(screen.getByRole("button", { name: /try again/i }));
    expect(retry).toHaveBeenCalled();
  });

  it("renders rows and sortable headers", async () => {
    const onSort = vi.fn();
    wrap(<DataTable rows={[{ n: "alpha" }, { n: "beta" }]} columns={[{ ...cols[0], sortable: true }]} rowKey={(r) => r.n} sort="n" onSort={onSort} />);
    expect(screen.getByText("alpha")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /name/i }));
    expect(onSort).toHaveBeenCalledWith("-n");
  });
});

describe("error messages", () => {
  it("include field validation details", () => {
    const e = new ApiError(422, "validation_failed", "The request was not valid.", [{ field: "url", message: "Only http and https URLs are supported." }]);
    expect(errorMessage(e)).toContain("url: Only http and https URLs are supported.");
    render(<MantineProvider><ErrorState error={e} /></MantineProvider>);
    expect(screen.getByRole("alert")).toBeInTheDocument();
  });

  it("humanize keeps acronyms", () => {
    expect(humanize("tls:expiring")).toBe("TLS expiring");
    expect(humanize("file_integrity")).toBe("File integrity");
  });
});

describe("login journey", () => {
  it("shows the server's error and then asks for MFA", async () => {
    const responses = [
      new Response(JSON.stringify({ error: { code: "invalid_credentials", message: "Email or password is incorrect." } }), { status: 401 }),
      new Response(JSON.stringify({ mfa_required: true, user: null }), { status: 200 }),
    ];
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => responses.shift()!);
    wrap(<LoginPage />, "/login");
    await userEvent.type(screen.getByLabelText(/email address/i), "a@b.example.com");
    await userEvent.type(screen.getByLabelText(/^password/i), "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Email or password is incorrect.");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    await waitFor(() => expect(screen.getByText("Verify it's you")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: /verify/i })).toBeDisabled();
  });

  it("sends the CSRF token on state-changing requests", async () => {
    document.cookie = "cw_csrf=test-csrf-token";
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response("{}", { status: 200 }));
    const { api } = await import("../api/client");
    await api.post("/anything", { a: 1 });
    const headers = (spy.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
    expect(headers["X-CSRF-Token"]).toBe("test-csrf-token");
    await api.get("/anything");
    const getHeaders = (spy.mock.calls[1][1] as RequestInit).headers as Record<string, string>;
    expect(getHeaders["X-CSRF-Token"]).toBeUndefined();
  });
});

describe("post-login redirect", () => {
  it("only allows same-origin paths", async () => {
    const { isSafeRedirect } = await import("../pages/public/Auth");
    expect(isSafeRedirect("/app/x/overview")).toBe(true);
    expect(isSafeRedirect("//evil.example.com")).toBe(false);
    expect(isSafeRedirect("/\\evil.example.com")).toBe(false);
    expect(isSafeRedirect("https://evil.example.com")).toBe(false);
    expect(isSafeRedirect(null)).toBe(false);
  });
});
