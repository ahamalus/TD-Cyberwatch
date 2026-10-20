/**
 * Enterprise application shell shared by the customer, administration and
 * operations portals: persistent collapsible sidebar on desktop, drawer on
 * mobile, and a top bar with search, notifications, theme, help and profile.
 */
import {
  ActionIcon,
  AppShell,
  Avatar,
  Badge,
  Box,
  Burger,
  Divider,
  Group,
  Indicator,
  Menu,
  NavLink,
  ScrollArea,
  Select,
  Stack,
  Text,
  Tooltip,
  UnstyledButton,
  useMantineColorScheme,
} from "@mantine/core";
import { useDisclosure, useLocalStorage } from "@mantine/hooks";
import {
  IconBell,
  IconChevronLeft,
  IconChevronRight,
  IconHelpCircle,
  IconLogout,
  IconMoon,
  IconSettings,
  IconShieldLock,
  IconSun,
  IconUserCircle,
  type Icon,
} from "@tabler/icons-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type ReactNode, useEffect } from "react";
import { Link, NavLink as RouterNavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useMe } from "../api/auth";
import { api } from "../api/client";
import { BrandMark, Wordmark } from "../components/ui";

export interface NavItem {
  label: string;
  to: string;
  icon: Icon;
  visible?: boolean;
  badge?: ReactNode;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export function AppShellLayout({
  area,
  groups,
  headerExtra,
  banner,
  defaultScheme,
}: {
  area: "customer" | "admin" | "ops";
  groups: NavGroup[];
  headerExtra?: ReactNode;
  banner?: ReactNode;
  defaultScheme: "light" | "dark";
}) {
  const [mobileOpen, { toggle: toggleMobile, close: closeMobile }] = useDisclosure(false);
  const [collapsed, setCollapsed] = useLocalStorage({ key: `cw-sidebar-collapsed-${area}`, defaultValue: false });
  const [schemePref, setSchemePref] = useLocalStorage<"light" | "dark">({ key: `cw-scheme-${area}`, defaultValue: defaultScheme });
  const { setColorScheme } = useMantineColorScheme();
  const loc = useLocation();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const me = useMe();

  useEffect(() => setColorScheme(schemePref), [schemePref, setColorScheme]);
  useEffect(() => closeMobile(), [loc.pathname, closeMobile]);

  const width = collapsed ? 76 : 260;
  const toggleScheme = () => {
    const next = schemePref === "dark" ? "light" : "dark";
    setSchemePref(next);
    if (area === "customer") api.patch("/auth/me", { theme: next }).catch(() => undefined);
  };

  const logout = async () => {
    await api.post("/auth/logout").catch(() => undefined);
    qc.clear();
    navigate("/login");
  };

  return (
    <AppShell
      header={{ height: 60 }}
      navbar={{ width, breakpoint: "sm", collapsed: { mobile: !mobileOpen } }}
      padding={{ base: "md", sm: "lg" }}
      transitionDuration={150}
    >
      <a className="cw-skip-link" href="#main-content">
        Skip to main content
      </a>
      <AppShell.Header style={{ background: "var(--cw-surface)", borderColor: "var(--cw-line)" }}>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="sm" wrap="nowrap">
            <Burger opened={mobileOpen} onClick={toggleMobile} hiddenFrom="sm" size="sm" aria-label="Toggle navigation" />
            <Box hiddenFrom="sm">
              <BrandMark size={26} />
            </Box>
            <Box visibleFrom="sm">{headerExtra}</Box>
          </Group>
          <Group gap={6} wrap="nowrap">
            {area !== "customer" && (
              <Badge variant="outline" color={area === "ops" ? "cyber" : "navy"} visibleFrom="xs">
                {area === "ops" ? "Security Operations" : "Platform Administration"}
              </Badge>
            )}
            {area === "customer" && <NotificationBell />}
            <Tooltip label={schemePref === "dark" ? "Switch to light theme" : "Switch to dark theme"}>
              <ActionIcon variant="subtle" color="gray" size="lg" onClick={toggleScheme} aria-label="Toggle colour theme">
                {schemePref === "dark" ? <IconSun size={19} /> : <IconMoon size={19} />}
              </ActionIcon>
            </Tooltip>
            <Tooltip label="Help and documentation">
              <ActionIcon variant="subtle" color="gray" size="lg" component={Link} to="/help" aria-label="Help">
                <IconHelpCircle size={19} />
              </ActionIcon>
            </Tooltip>
            <Menu position="bottom-end" width={240} shadow="md">
              <Menu.Target>
                <UnstyledButton aria-label="Account menu">
                  <Avatar color="cyber" radius="xl" size={34}>
                    {(me.data?.full_name || me.data?.email || "?").slice(0, 2).toUpperCase()}
                  </Avatar>
                </UnstyledButton>
              </Menu.Target>
              <Menu.Dropdown>
                <Menu.Label>
                  <Text size="sm" fw={600} c="var(--cw-text)" truncate>
                    {me.data?.full_name}
                  </Text>
                  <Text size="xs" truncate>
                    {me.data?.email}
                  </Text>
                </Menu.Label>
                <Menu.Divider />
                {(me.data?.memberships.length ?? 0) > 0 && (
                  <Menu.Item leftSection={<IconUserCircle size={16} />} component={Link} to={`/app/${me.data?.memberships[0].tenant_id}/settings`}>
                    Account and security
                  </Menu.Item>
                )}
                {me.data?.is_platform_staff && (
                  <>
                    <Menu.Item leftSection={<IconSettings size={16} />} component={Link} to="/admin">
                      Platform administration
                    </Menu.Item>
                    <Menu.Item leftSection={<IconShieldLock size={16} />} component={Link} to="/ops">
                      Security operations
                    </Menu.Item>
                    {area !== "customer" && (
                      <Menu.Item leftSection={<IconUserCircle size={16} />} component={Link} to="/staff/security">
                        My staff account security
                      </Menu.Item>
                    )}
                  </>
                )}
                <Menu.Divider />
                <Menu.Item leftSection={<IconLogout size={16} />} color="threat" onClick={logout}>
                  Sign out
                </Menu.Item>
              </Menu.Dropdown>
            </Menu>
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar style={{ background: "var(--cw-sidebar-bg)", borderColor: "var(--cw-line)" }}>
        <AppShell.Section p="md" pb="xs">
          <Group justify="space-between" wrap="nowrap">
            <Link to="/" style={{ textDecoration: "none", color: "inherit" }} aria-label="CyberWatch home">
              <Wordmark compact={collapsed} />
            </Link>
          </Group>
        </AppShell.Section>
        <AppShell.Section grow component={ScrollArea} px="sm" pb="md">
          <nav aria-label={`${area} navigation`}>
            {groups.map((g) => {
              const items = g.items.filter((i) => i.visible !== false);
              if (!items.length) return null;
              return (
                <Stack key={g.label} gap={2} mt="md">
                  {!collapsed && (
                    <Text size="10px" fw={700} c="dimmed" tt="uppercase" px="sm" mb={2} style={{ letterSpacing: 0.8 }}>
                      {g.label}
                    </Text>
                  )}
                  {items.map((item) => {
                    const IconCmp = item.icon;
                    const link = (
                      <NavLink
                        key={item.to}
                        component={RouterNavLink}
                        to={item.to}
                        className="cw-nav-link"
                        label={collapsed ? undefined : item.label}
                        aria-label={item.label}
                        leftSection={<IconCmp size={19} stroke={1.7} />}
                        rightSection={!collapsed ? item.badge : undefined}
                        active={loc.pathname === item.to || loc.pathname.startsWith(item.to + "/")}
                      />
                    );
                    return collapsed ? (
                      <Tooltip key={item.to} label={item.label} position="right">
                        {link}
                      </Tooltip>
                    ) : (
                      link
                    );
                  })}
                </Stack>
              );
            })}
          </nav>
        </AppShell.Section>
        <AppShell.Section p="sm" visibleFrom="sm">
          <Divider mb="xs" color="var(--cw-line)" />
          <UnstyledButton
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            style={{ display: "flex", alignItems: "center", gap: 8, padding: 8, borderRadius: 8, width: "100%" }}
          >
            {collapsed ? <IconChevronRight size={18} /> : <IconChevronLeft size={18} />}
            {!collapsed && (
              <Text size="sm" c="dimmed">
                Collapse
              </Text>
            )}
          </UnstyledButton>
        </AppShell.Section>
      </AppShell.Navbar>

      <AppShell.Main id="main-content" style={{ background: "var(--cw-page-bg)" }}>
        <Box maw={1440} mx="auto">
          {banner}
          <Outlet />
        </Box>
      </AppShell.Main>
    </AppShell>
  );
}

function NotificationBell() {
  const loc = useLocation();
  const tenantId = loc.pathname.split("/")[2];
  const q = useQuery({
    queryKey: ["bell", tenantId],
    queryFn: () => api.get<{ total: number }>(`/tenants/${tenantId}/incidents`, { open_only: true, severity: ["critical", "high"], page_size: 1 }),
    enabled: !!tenantId,
    refetchInterval: 60_000,
  });
  const n = q.data?.total ?? 0;
  return (
    <Tooltip label={n ? `${n} open high-priority incident(s)` : "No open high-priority incidents"}>
      <Indicator disabled={!n} label={n > 9 ? "9+" : n} size={16} color="threat" offset={5}>
        <ActionIcon variant="subtle" color="gray" size="lg" component={Link} to={`/app/${tenantId}/incidents?open=1`} aria-label={`Incidents: ${n} open high-priority`}>
          <IconBell size={19} />
        </ActionIcon>
      </Indicator>
    </Tooltip>
  );
}

export function TenantSwitcher() {
  const me = useMe();
  const loc = useLocation();
  const navigate = useNavigate();
  const current = loc.pathname.split("/")[2];
  const options = (me.data?.memberships ?? []).map((m) => ({ value: m.tenant_id, label: m.tenant_name + (m.is_demo ? " (demo)" : "") }));
  if (options.length <= 1) {
    return (
      <Text fw={600} size="sm">
        {options[0]?.label}
      </Text>
    );
  }
  return (
    <Select
      aria-label="Switch organisation"
      data={options}
      value={current}
      allowDeselect={false}
      w={260}
      size="sm"
      onChange={(v) => v && navigate(`/app/${v}/overview`)}
    />
  );
}
