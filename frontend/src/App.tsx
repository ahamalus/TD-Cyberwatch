import { Alert, Box, Button, Card, Container, List, Stack, Text, Title } from "@mantine/core";
import {
  IconActivity,
  IconAlertTriangle,
  IconBell,
  IconBug,
  IconBuildingSkyscraper,
  IconCash,
  IconChartBar,
  IconClipboardList,
  IconCpu,
  IconDeviceDesktopAnalytics,
  IconCreditCard,
  IconFileDiff,
  IconFileSearch,
  IconFingerprint,
  IconHeadset,
  IconHeartRateMonitor,
  IconLayoutDashboard,
  IconLifebuoy,
  IconListDetails,
  IconLock,
  IconMessages,
  IconPlug,
  IconRadar,
  IconReportAnalytics,
  IconServer,
  IconSettings,
  IconStack2,
  IconUsersGroup,
  IconWorld,
} from "@tabler/icons-react";
import { Link, Navigate, Route, Routes, useParams } from "react-router-dom";
import { RequireAuth, useMe, usePlatformCan, useTenant } from "./api/auth";
import { DemoBanner, ErrorState, PageHeader, Wordmark } from "./components/ui";
import { AppShellLayout, type NavGroup, TenantSwitcher } from "./layouts/AppShellLayout";
import { Suspense, useEffect } from "react";
import { lazyModule } from "./lazyModule";
import {
  AcceptInvitePage,
  AppEntryRedirect,
  ForgotPasswordPage,
  LoginPage,
  RegisterPage,
  ResetPasswordPage,
  VerifyEmailPage,
} from "./pages/public/Auth";

// Portal pages are loaded on first use, so the sign-in and landing pages stay small.
const Admin = lazyModule<typeof import("./pages/admin/Admin")>(() => import("./pages/admin/Admin"));
const Ops = lazyModule<typeof import("./pages/ops/Ops")>(() => import("./pages/ops/Ops"));
const { BillingPage, ReportsPage, SupportPage, TicketPage } = lazyModule<typeof import("./pages/app/Commerce")>(() => import("./pages/app/Commerce"));
const { FilesPage, MonitoringPage } = lazyModule<typeof import("./pages/app/Files")>(() => import("./pages/app/Files"));
const { HostingDetailPage, HostingListPage, NewHostingPage } = lazyModule<typeof import("./pages/app/Hosting")>(() => import("./pages/app/Hosting"));
const { IncidentDetailPage, IncidentsPage } = lazyModule<typeof import("./pages/app/Incidents")>(() => import("./pages/app/Incidents"));
const { NotificationsPage } = lazyModule<typeof import("./pages/app/Notifications")>(() => import("./pages/app/Notifications"));
const { OverviewPage } = lazyModule<typeof import("./pages/app/Overview")>(() => import("./pages/app/Overview"));
const { AccountSecurity, SettingsPage } = lazyModule<typeof import("./pages/app/Settings")>(() => import("./pages/app/Settings"));
const { NewWebsitePage, WebsiteDetailPage, WebsitesPage } = lazyModule<typeof import("./pages/app/Websites")>(() => import("./pages/app/Websites"));
import { LandingPage } from "./pages/public/Landing";
import { PrivacyPage } from "./pages/public/Privacy";

function CustomerLayout() {
  const { tenantId } = useParams();
  const tenant = useTenant();
  const me = useMe();
  const base = `/app/${tenantId}`;
  const perms = new Set(tenant.data?.permissions ?? []);
  const can = (p: string) => perms.has(p);
  const membership = me.data?.memberships.find((m) => m.tenant_id === tenantId);
  const mfaGate = !!membership?.mfa_required;
  const refetchTenant = tenant.refetch;
  useEffect(() => {
    if (!mfaGate && membership) void refetchTenant();
  }, [mfaGate, membership, refetchTenant]);
  if (mfaGate) {
    return (
      <Container size="lg" py="xl">
        <Box mb="lg"><Wordmark /></Box>
        <PageHeader title="Set up multi-factor authentication" description={`${membership?.tenant_name} requires every member to use an authenticator app. Set it up below to continue to the organisation.`} />
        <AccountSecurity />
      </Container>
    );
  }
  if (tenant.error) {
    return (
      <Container py="xl">
        <ErrorState error={tenant.error} />
        <Button mt="md" component={Link} to="/app">Go to my organisation</Button>
      </Container>
    );
  }
  const groups: NavGroup[] = [
    {
      label: "Monitor",
      items: [
        { label: "Overview", to: `${base}/overview`, icon: IconLayoutDashboard },
        { label: "Websites", to: `${base}/websites`, icon: IconWorld, visible: can("websites:read") },
        { label: "Hosting Connections", to: `${base}/hosting`, icon: IconPlug, visible: can("hosting:read") },
        { label: "Monitoring", to: `${base}/monitoring`, icon: IconRadar, visible: can("monitoring:read") },
        { label: "File Integrity", to: `${base}/files`, icon: IconFileDiff, visible: can("inventory:read") },
      ],
    },
    {
      label: "Respond",
      items: [
        { label: "Incidents", to: `${base}/incidents`, icon: IconAlertTriangle, visible: can("incidents:read") },
        { label: "Notifications", to: `${base}/notifications`, icon: IconBell, visible: can("notifications:read") },
        { label: "Reports", to: `${base}/reports`, icon: IconReportAnalytics, visible: can("reports:read") },
      ],
    },
    {
      label: "Account",
      items: [
        { label: "Billing", to: `${base}/billing`, icon: IconCreditCard, visible: can("billing:read") },
        { label: "Support", to: `${base}/support`, icon: IconLifebuoy, visible: can("support:read") },
        { label: "Settings", to: `${base}/settings`, icon: IconSettings },
      ],
    },
  ];
  const banner = (
    <>
      {tenant.data?.is_demo && <DemoBanner />}
      {tenant.data?.via_managed_service_grant && (
        <Alert color="cyber" variant="light" mb="md" icon={<IconHeadset />} title="Managed-service access">
          You are working in this customer's workspace under a customer-approved grant. All actions are recorded with the grant ID.
        </Alert>
      )}
      {tenant.data?.read_only && (
        <Alert color="amber" variant="light" mb="md" icon={<IconLock />} title="Organisation suspended">
          Data remains available read-only. Monitoring is paused and changes are disabled. Contact Trust Data to restore service.
        </Alert>
      )}
    </>
  );
  return <AppShellLayout area="customer" groups={groups} headerExtra={<TenantSwitcher />} banner={banner} defaultScheme="light" />;
}

function StaffGuard({ children }: { children: React.ReactNode }) {
  const me = useMe();
  if (me.data && !me.data.is_platform_staff) return <Navigate to="/app" replace />;
  if (me.data?.platform_mfa_required) return <Navigate to="/staff/security" replace />;
  return <>{children}</>;
}

/**
 * Admin navigation. Every item must stay under /admin: a link into /ops would switch the
 * user into the Security Operations portal (badge, theme and menu change).
 */
export function adminNavGroups(can: (perm: string) => boolean): NavGroup[] {
  return [
    {
      label: "Platform",
      items: [
        { label: "Platform Overview", to: "/admin/overview", icon: IconLayoutDashboard, visible: can("platform:overview") },
        { label: "Customers", to: "/admin/customers", icon: IconBuildingSkyscraper, visible: can("platform:tenants:read") },
        { label: "Access Control", to: "/admin/access", icon: IconUsersGroup, visible: can("platform:overview") },
        { label: "Hosting Connectors", to: "/admin/connectors", icon: IconPlug, visible: can("platform:overview") },
      ],
    },
    {
      label: "Commercial",
      items: [
        { label: "Plans and Entitlements", to: "/admin/plans", icon: IconStack2, visible: can("platform:plans:manage") },
        { label: "Payments", to: "/admin/payments", icon: IconCash, visible: can("platform:payments:read") },
        { label: "Messaging", to: "/admin/messaging", icon: IconMessages, visible: can("platform:messaging:manage") },
      ],
    },
    {
      label: "Operations",
      items: [
        { label: "Global Incidents", to: "/admin/incidents", icon: IconAlertTriangle, visible: can("ops:incidents:read") },
        { label: "Managed Services", to: "/admin/grants", icon: IconHeadset, visible: can("grants:request") || can("grants:issue") },
        { label: "Analytics", to: "/admin/analytics", icon: IconChartBar, visible: can("platform:overview") },
        { label: "Audit and Compliance", to: "/admin/audit", icon: IconClipboardList, visible: can("platform:audit:read") },
        { label: "Configuration", to: "/admin/config", icon: IconSettings, visible: can("platform:config:manage") },
        { label: "System Health", to: "/admin/health", icon: IconHeartRateMonitor, visible: can("platform:health:read") },
      ],
    },
  ];
}

function AdminLayout() {
  const can = usePlatformCan();
  return (
    <StaffGuard>
      <AppShellLayout area="admin" groups={adminNavGroups(can)} headerExtra={<Text fw={600}>Platform Administration</Text>} defaultScheme="light" />
    </StaffGuard>
  );
}

/** Security Operations navigation; every item stays under /ops. */
export function opsNavGroups(can: (perm: string) => boolean): NavGroup[] {
  return [
    {
      label: "Security Operations",
      items: [
        { label: "Security Overview", to: "/ops/overview", icon: IconLayoutDashboard, visible: can("ops:jobs:read") },
        { label: "NOC Wall", to: "/ops/noc", icon: IconDeviceDesktopAnalytics, visible: can("ops:jobs:read") },
        { label: "Scan Queue", to: "/ops/jobs", icon: IconActivity, visible: can("ops:jobs:read") },
        { label: "Hosting Diagnostics", to: "/ops/diagnostics", icon: IconServer, visible: can("ops:diagnostics") },
        { label: "File Integrity", to: "/ops/files", icon: IconFingerprint },
        { label: "Malware Findings", to: "/ops/malware", icon: IconBug },
        { label: "Log Analysis", to: "/ops/logs", icon: IconListDetails },
        { label: "Incidents", to: "/ops/incidents", icon: IconAlertTriangle, visible: can("ops:incidents:read") },
        { label: "Notifications", to: "/ops/notifications", icon: IconBell, visible: can("ops:jobs:read") },
        { label: "Evidence", to: "/ops/evidence", icon: IconFileSearch },
        { label: "Worker Health", to: "/ops/workers", icon: IconCpu, visible: can("platform:health:read") },
      ],
    },
  ];
}

function OpsLayout() {
  const can = usePlatformCan();
  return (
    <StaffGuard>
      <AppShellLayout area="ops" groups={opsNavGroups(can)} headerExtra={<Text fw={600}>Security Operations Centre</Text>} defaultScheme="dark" />
    </StaffGuard>
  );
}

function StaffSecurityPage() {
  return (
    <Container size="lg" py="xl">
      <Box mb="lg"><Wordmark /></Box>
      <PageHeader title="Staff account security" description="Trust Data staff must enrol multi-factor authentication before platform functions are available." actions={<Button component={Link} to="/admin" variant="default">Continue to administration</Button>} />
      <AccountSecurity />
    </Container>
  );
}

function HelpPage() {
  return (
    <Container size="md" py="xl">
      <Box mb="lg"><Link to="/"><Wordmark /></Link></Box>
      <Title order={1}>Help</Title>
      <Stack mt="md">
        <Card>
          <Title order={3}>Getting started</Title>
          <List mt="xs" size="sm" spacing={6}>
            <List.Item>Add a website under Websites. Availability and TLS checks need only the public URL.</List.Item>
            <List.Item>Connect hosting (SFTP or a cPanel API token) to enable SHA-256 file-integrity monitoring.</List.Item>
            <List.Item>Enable file scans in the website's Monitoring settings. The first completed scan becomes the trusted baseline.</List.Item>
            <List.Item>Create an alert policy under Notifications so the right people are told about incidents.</List.Item>
          </List>
        </Card>
        <Card>
          <Title order={3}>What monitoring can and cannot do</Title>
          <Text size="sm" mt="xs">
            CyberWatch compares inventories between scans. It cannot see changes that appear and disappear between scans, and it never assumes a
            connection supports log access, malware scanning or real-time events unless that capability is verified. A failed or partial scan is never
            treated as proof that files were deleted. Heuristic findings require human verification.
          </Text>
        </Card>
        <Card>
          <Title order={3}>Contact</Title>
          <Text size="sm" mt="xs">Trust Data Compliance Ltd · team@trustdata.ng · or raise a request under Support.</Text>
        </Card>
      </Stack>
    </Container>
  );
}

function NotFound() {
  return (
    <Container py={80} ta="center">
      <Title>Page not found</Title>
      <Text c="dimmed" mt="sm">The page you requested does not exist or you do not have access to it.</Text>
      <Button mt="lg" component={Link} to="/app">Go to dashboard</Button>
    </Container>
  );
}

export function App() {
  return (
    <Suspense fallback={<Box p="xl"><Text c="dimmed">Loading…</Text></Box>}>
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route path="/verify-email" element={<VerifyEmailPage />} />
      <Route path="/invite" element={<AcceptInvitePage />} />
      <Route path="/help" element={<HelpPage />} />
      <Route path="/privacy" element={<PrivacyPage />} />
      <Route path="/staff/security" element={<RequireAuth><StaffSecurityPage /></RequireAuth>} />
      <Route path="/app" element={<RequireAuth><AppEntryRedirect /></RequireAuth>} />
      <Route path="/app/:tenantId" element={<RequireAuth><CustomerLayout /></RequireAuth>}>
        <Route index element={<Navigate to="overview" replace />} />
        <Route path="overview" element={<OverviewPage />} />
        <Route path="websites" element={<WebsitesPage />} />
        <Route path="websites/new" element={<NewWebsitePage />} />
        <Route path="websites/:websiteId" element={<WebsiteDetailPage />} />
        <Route path="hosting" element={<HostingListPage />} />
        <Route path="hosting/new" element={<NewHostingPage />} />
        <Route path="hosting/:accountId" element={<HostingDetailPage />} />
        <Route path="monitoring" element={<MonitoringPage />} />
        <Route path="files" element={<FilesPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="incidents/:incidentId" element={<IncidentDetailPage />} />
        <Route path="notifications" element={<NotificationsPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="billing" element={<BillingPage />} />
        <Route path="support" element={<SupportPage />} />
        <Route path="support/:ticketId" element={<TicketPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFound />} />
      </Route>
      <Route path="/admin" element={<RequireAuth><AdminLayout /></RequireAuth>}>
        <Route index element={<Navigate to="overview" replace />} />
        <Route path="overview" element={<Admin.AdminOverviewPage />} />
        <Route path="customers" element={<Admin.CustomersPage />} />
        <Route path="access" element={<Admin.AccessControlPage />} />
        <Route path="connectors" element={<Admin.ConnectorRegistryPage />} />
        <Route path="plans" element={<Admin.PlansAdminPage />} />
        <Route path="payments" element={<Admin.PaymentsAdminPage />} />
        <Route path="messaging" element={<Admin.MessagingAdminPage />} />
        <Route path="grants" element={<Admin.ManagedServicesPage />} />
        <Route path="analytics" element={<Admin.AnalyticsPage />} />
        <Route path="audit" element={<Admin.AuditAdminPage />} />
        <Route path="config" element={<Admin.ConfigurationPage />} />
        {/* Shared operations pages, shown inside the admin portal so the portal does not switch. */}
        <Route path="incidents" element={<Ops.OpsIncidentsPage />} />
        <Route path="health" element={<Ops.WorkerHealthPage />} />
        <Route path="jobs" element={<Ops.ScanQueuePage />} />
        <Route path="*" element={<NotFound />} />
      </Route>
      <Route path="/ops" element={<RequireAuth><OpsLayout /></RequireAuth>}>
        <Route index element={<Navigate to="overview" replace />} />
        <Route path="overview" element={<Ops.OpsOverviewPage />} />
        <Route path="noc" element={<Ops.NocWallPage />} />
        <Route path="jobs" element={<Ops.ScanQueuePage />} />
        <Route path="diagnostics" element={<Ops.DiagnosticsPage />} />
        <Route path="files" element={<Ops.CapabilityNoticePage kind="files" />} />
        <Route path="malware" element={<Ops.OpsMalwarePage />} />
        <Route path="logs" element={<Ops.CapabilityNoticePage kind="logs" />} />
        <Route path="evidence" element={<Ops.CapabilityNoticePage kind="evidence" />} />
        <Route path="incidents" element={<Ops.OpsIncidentsPage />} />
        <Route path="notifications" element={<Ops.OpsNotificationsPage />} />
        <Route path="workers" element={<Ops.WorkerHealthPage />} />
        <Route path="*" element={<NotFound />} />
      </Route>
      <Route path="*" element={<NotFound />} />
    </Routes>
    </Suspense>
  );
}

