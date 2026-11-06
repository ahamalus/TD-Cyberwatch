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
import * as Admin from "./pages/admin/Admin";
import { BillingPage, ReportsPage, SupportPage, TicketPage } from "./pages/app/Commerce";
import { FilesPage, MonitoringPage } from "./pages/app/Files";
import { HostingDetailPage, HostingListPage, NewHostingPage } from "./pages/app/Hosting";
import { IncidentDetailPage, IncidentsPage } from "./pages/app/Incidents";
import { NotificationsPage } from "./pages/app/Notifications";
import { OverviewPage } from "./pages/app/Overview";
import { AccountSecurity, SettingsPage } from "./pages/app/Settings";
import { NewWebsitePage, WebsiteDetailPage, WebsitesPage } from "./pages/app/Websites";
import * as Ops from "./pages/ops/Ops";
import {
  AcceptInvitePage,
  AppEntryRedirect,
  ForgotPasswordPage,
  LoginPage,
  RegisterPage,
  ResetPasswordPage,
  VerifyEmailPage,
} from "./pages/public/Auth";
import { LandingPage } from "./pages/public/Landing";

function CustomerLayout() {
  const { tenantId } = useParams();
  const tenant = useTenant();
  const base = `/app/${tenantId}`;
  const perms = new Set(tenant.data?.permissions ?? []);
  const can = (p: string) => perms.has(p);
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

function AdminLayout() {
  const can = usePlatformCan();
  const groups: NavGroup[] = [
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
        { label: "Global Incidents", to: "/ops/incidents", icon: IconAlertTriangle, visible: can("ops:incidents:read") },
        { label: "Managed Services", to: "/admin/grants", icon: IconHeadset, visible: can("grants:request") || can("grants:issue") },
        { label: "Analytics", to: "/admin/analytics", icon: IconChartBar, visible: can("platform:overview") },
        { label: "Audit and Compliance", to: "/admin/audit", icon: IconClipboardList, visible: can("platform:audit:read") },
        { label: "Configuration", to: "/admin/config", icon: IconSettings, visible: can("platform:config:manage") },
        { label: "System Health", to: "/ops/workers", icon: IconHeartRateMonitor, visible: can("platform:health:read") },
      ],
    },
  ];
  return (
    <StaffGuard>
      <AppShellLayout area="admin" groups={groups} headerExtra={<Text fw={600}>Platform Administration</Text>} defaultScheme="light" />
    </StaffGuard>
  );
}

function OpsLayout() {
  const can = usePlatformCan();
  const groups: NavGroup[] = [
    {
      label: "Security Operations",
      items: [
        { label: "Security Overview", to: "/ops/overview", icon: IconLayoutDashboard, visible: can("ops:jobs:read") },
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
  return (
    <StaffGuard>
      <AppShellLayout area="ops" groups={groups} headerExtra={<Text fw={600}>Security Operations Centre</Text>} defaultScheme="dark" />
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
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route path="/verify-email" element={<VerifyEmailPage />} />
      <Route path="/invite" element={<AcceptInvitePage />} />
      <Route path="/help" element={<HelpPage />} />
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
        <Route path="*" element={<NotFound />} />
      </Route>
      <Route path="/ops" element={<RequireAuth><OpsLayout /></RequireAuth>}>
        <Route index element={<Navigate to="overview" replace />} />
        <Route path="overview" element={<Ops.OpsOverviewPage />} />
        <Route path="jobs" element={<Ops.ScanQueuePage />} />
        <Route path="diagnostics" element={<Ops.DiagnosticsPage />} />
        <Route path="files" element={<Ops.CapabilityNoticePage kind="files" />} />
        <Route path="malware" element={<Ops.CapabilityNoticePage kind="malware" />} />
        <Route path="logs" element={<Ops.CapabilityNoticePage kind="logs" />} />
        <Route path="evidence" element={<Ops.CapabilityNoticePage kind="evidence" />} />
        <Route path="incidents" element={<Ops.OpsIncidentsPage />} />
        <Route path="notifications" element={<Ops.OpsNotificationsPage />} />
        <Route path="workers" element={<Ops.WorkerHealthPage />} />
        <Route path="*" element={<NotFound />} />
      </Route>
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

