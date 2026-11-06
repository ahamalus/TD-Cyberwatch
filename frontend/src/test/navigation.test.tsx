import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { theme } from "../design/theme";
import { AppShellLayout } from "../layouts/AppShellLayout";
import { IconWorld, IconSettings } from "@tabler/icons-react";

describe("application shell", () => {
  it("only shows navigation items permitted for the user", () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ total: 0, memberships: [] }), { status: 200 }));
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <MantineProvider theme={theme}>
        <QueryClientProvider client={qc}>
          <MemoryRouter initialEntries={["/admin/overview"]}>
            <Routes>
              <Route
                path="/admin/*"
                element={
                  <AppShellLayout
                    area="admin"
                    defaultScheme="light"
                    groups={[
                      {
                        label: "Platform",
                        items: [
                          { label: "Customers", to: "/admin/customers", icon: IconWorld, visible: true },
                          { label: "Configuration", to: "/admin/config", icon: IconSettings, visible: false },
                        ],
                      },
                    ]}
                  />
                }
              />
            </Routes>
          </MemoryRouter>
        </QueryClientProvider>
      </MantineProvider>,
    );
    expect(screen.getAllByLabelText("Customers").length).toBeGreaterThan(0);
    expect(screen.queryByLabelText("Configuration")).not.toBeInTheDocument();
    expect(screen.getByText("Skip to main content")).toBeInTheDocument();
    expect(screen.getByLabelText("Toggle colour theme")).toBeInTheDocument();
  });
});
