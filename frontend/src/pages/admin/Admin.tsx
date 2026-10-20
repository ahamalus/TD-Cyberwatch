import {
  Alert,
  Badge,
  Box,
  Button,
  Card,
  Code,
  Grid,
  Group,
  JsonInput,
  Modal,
  MultiSelect,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import {
  IconAlertTriangle,
  IconBuilding,
  IconCash,
  IconDatabase,
  IconPlus,
  IconServer,
  IconShieldCheck,
} from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useMe, usePlatformCan } from "../../api/auth";
import { api, errorMessage } from "../../api/client";
import type { Page } from "../../api/types";
import { SERIES_COLORS, StackedBars } from "../../components/charts";
import { fmtDateTime, fmtMoney, fmtRelative, humanize, minCharsHint } from "../../components/format";
import { HealthBadge, SeverityBadge } from "../../components/status";
import { ConfirmButton, DataTable, EmptyState, ErrorState, KeyValue, LoadingBlock, PageHeader, SearchInput, Section, StatCard } from "../../components/ui";

const onError = (e: unknown) => notifications.show({ color: "threat", title: "Action failed", message: errorMessage(e) });

// ---------------------------------------------------------------- overview

export function AdminOverviewPage() {
  const q = useQuery({ queryKey: ["admin-overview"], queryFn: () => api.get<Record<string, any>>("/admin/overview"), refetchInterval: 60_000 }); // eslint-disable-line @typescript-eslint/no-explicit-any
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  const d = q.data;
  const sum = (o?: Record<string, number>) => Object.values(o ?? {}).reduce((a, b) => a + b, 0);
  return (
    <>
      <PageHeader title="Platform overview" description="Aggregate platform metrics. Customer monitoring content is not shown here." />
      {(d?.health?.alerts?.length ?? 0) > 0 && (
        <Alert color="threat" variant="light" icon={<IconAlertTriangle />} mb="md" title="Operational alerts">
          {d!.health.alerts.map((a: { severity: string; message: string }) => <Text key={a.message} size="sm">• [{a.severity}] {a.message}</Text>)}
        </Alert>
      )}
      <SimpleGrid cols={{ base: 1, xs: 2, lg: 4 }} mb="md">
        <StatCard label="Customer organisations" icon={IconBuilding} loading={!d} value={sum(d?.tenants)} context={d ? `${d.tenants.active ?? 0} active · ${d.tenants.suspended ?? 0} suspended · ${d.demo_tenants} demo` : ""} to="/admin/customers" />
        <StatCard label="Active subscriptions" icon={IconCash} loading={!d} value={(d?.subscriptions.active ?? 0) + (d?.subscriptions.trialing ?? 0)} context={d ? `${d.subscriptions.active ?? 0} paid · ${d.subscriptions.trialing ?? 0} trial · ${d.subscriptions.grace_period ?? 0} grace` : ""} to="/admin/payments" />
        <StatCard label="Websites / connections" icon={IconServer} loading={!d} value={`${d?.websites ?? 0} / ${sum(d?.hosting_accounts)}`} context={d ? `${(d.hosting_accounts.auth_failed ?? 0) + (d.hosting_accounts.error ?? 0) + (d.hosting_accounts.disconnected ?? 0)} failing connections` : ""} />
        <StatCard label="Jobs (24h)" icon={IconDatabase} loading={!d} value={sum(d?.jobs_24h)} context={d ? `${d.jobs_24h.failed ?? 0} failed · ${d.jobs_24h.partial ?? 0} partial` : ""} to="/ops/jobs" />
      </SimpleGrid>
      <Grid>
        <Grid.Col span={{ base: 12, md: 6 }}>
          <Section title="Open incidents by severity">
            {d ? (
              <Stack gap={6}>
                {["critical", "high", "medium", "low", "informational"].map((s) => (
                  <Group key={s} justify="space-between"><SeverityBadge severity={s} /><Text fw={600}>{d.open_incidents_by_severity[s] ?? 0}</Text></Group>
                ))}
              </Stack>
            ) : <LoadingBlock />}
          </Section>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 6 }}>
          <Section title="Verified revenue (last 6 months)" description="Only payments verified with the payment provider are included.">
            {!d ? <LoadingBlock /> : d.revenue_verified.length === 0 ? <EmptyState title="No verified payments yet" /> : (
              <Table>
                <Table.Tbody>
                  {d.revenue_verified.map((r: { month: string; currency: string; amount_minor: number; payments: number }) => (
                    <Table.Tr key={r.month + r.currency}><Table.Td>{r.month?.slice(0, 7)}</Table.Td><Table.Td>{fmtMoney(r.amount_minor, r.currency)}</Table.Td><Table.Td>{r.payments} payments</Table.Td></Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}
          </Section>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 6 }}>
          <Section title="Notification delivery (24h)">
            {d && <KeyValue items={Object.entries(d.notifications_24h as Record<string, number>).map(([k, v]) => [humanize(k), v])} />}
            {d && sum(d.notifications_24h) === 0 && <Text size="sm" c="dimmed">No notifications in the last 24 hours.</Text>}
          </Section>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 6 }}>
          <Section title="Core services">
            {d && <KeyValue items={[["Database", <HealthBadge key="d" state={d.health.database.ok ? "healthy" : "failed"} />], ["Redis / queue", <HealthBadge key="r" state={d.health.redis.ok ? "healthy" : "failed"} />], ["Scheduler", <HealthBadge key="s" state={d.health.scheduler.ok ? "healthy" : "degraded"} />]]} />}
          </Section>
        </Grid.Col>
      </Grid>
    </>
  );
}

// ---------------------------------------------------------------- customers

interface TenantRow { id: string; name: string; slug: string; status: string; is_demo: boolean; created_at: string; contact_email: string | null; plan: string | null; subscription_status: string | null; websites: number; hosting_accounts: number; members: number; open_incidents: number }

export function CustomersPage() {
  const can = usePlatformCan();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [target, setTarget] = useState<TenantRow | null>(null);
  const [newStatus, setNewStatus] = useState("suspended");
  const [reason, setReason] = useState("");
  const list = useQuery({ queryKey: ["admin-tenants", q, status, page], queryFn: () => api.get<Page<TenantRow>>("/admin/tenants", { q, status: status ?? undefined, page, page_size: 25 }) });
  const change = useMutation({
    mutationFn: () => api.post(`/admin/tenants/${target?.id}/status`, { status: newStatus, reason, confirm: true }),
    onSuccess: () => { setTarget(null); setReason(""); list.refetch(); },
    onError,
  });
  return (
    <>
      <PageHeader title="Customers" description="Organisations using CyberWatch. Suspension pauses monitoring and blocks changes without deleting data." />
      <Card>
        <Group mb="md">
          <SearchInput value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Search organisations" />
          <Select placeholder="Status" clearable w={160} data={["active", "suspended", "deactivated"].map((v) => ({ value: v, label: humanize(v) }))} value={status} onChange={setStatus} aria-label="Status" />
        </Group>
        <DataTable<TenantRow>
          rows={list.data?.items}
          loading={list.isLoading}
          error={list.error}
          rowKey={(t) => t.id}
          page={page}
          pageSize={25}
          total={list.data?.total}
          onPage={setPage}
          columns={[
            { key: "name", header: "Organisation", render: (t) => <Box><Text size="sm" fw={600}>{t.name}{t.is_demo && <Badge ml={6} size="xs" color="amber">demo</Badge>}</Text><Text size="xs" c="dimmed">{t.contact_email}</Text></Box> },
            { key: "status", header: "Status", render: (t) => <Badge color={t.status === "active" ? "secure" : t.status === "suspended" ? "amber" : "gray"}>{humanize(t.status)}</Badge> },
            { key: "plan", header: "Plan", render: (t) => <Text size="sm">{t.plan ?? "—"} <Text span size="xs" c="dimmed">{humanize(t.subscription_status)}</Text></Text> },
            { key: "usage", header: "Usage", render: (t) => <Text size="xs">{t.websites} sites · {t.hosting_accounts} hosts · {t.members} users</Text>, visibleFrom: "md" },
            { key: "inc", header: "Open incidents", render: (t) => <Text size="sm">{t.open_incidents}</Text>, visibleFrom: "sm" },
            { key: "created", header: "Created", render: (t) => <Text size="sm">{fmtDateTime(t.created_at)}</Text>, visibleFrom: "lg" },
            { key: "x", header: "", render: (t) => can("platform:tenants:manage") && <Button size="xs" variant="subtle" onClick={() => { setTarget(t); setNewStatus(t.status === "active" ? "suspended" : "active"); }}>Change status</Button> },
          ]}
        />
      </Card>
      <Modal opened={!!target} onClose={() => setTarget(null)} title={`Change status: ${target?.name}`}>
        <Stack>
          <Select label="New status" data={["active", "suspended", "deactivated"].map((v) => ({ value: v, label: humanize(v) }))} value={newStatus} onChange={(v) => setNewStatus(v ?? "suspended")} />
          <Textarea label="Reason (recorded in the audit trail)" required description={minCharsHint(reason, 5)} value={reason} onChange={(e) => setReason(e.currentTarget.value)} />
          <Alert color="amber" variant="light">Customer data is retained. Suspended organisations are read-only and monitoring pauses; deactivated organisations cannot sign in.</Alert>
          <Button color={newStatus === "active" ? "cyber" : "threat"} disabled={reason.length < 5} loading={change.isPending} onClick={() => change.mutate()}>Confirm change</Button>
        </Stack>
      </Modal>
    </>
  );
}

// ---------------------------------------------------------------- access control

export function AccessControlPage() {
  const roles = useQuery({ queryKey: ["admin-roles"], queryFn: () => api.get<{ key: string; name: string; scope: string; description: string; permissions: string[] }[]>("/admin/roles") });
  const staff = useQuery({ queryKey: ["admin-staff"], queryFn: () => api.get<{ id: string; email: string; full_name: string; is_active: boolean; mfa_enabled: boolean; roles: string[]; last_login_at: string | null }[]>("/admin/staff"), retry: false });
  const [opened, { open, close }] = useDisclosure(false);
  const [form, setForm] = useState({ email: "", full_name: "", roles: ["support_agent"] });
  const platformRoles = (roles.data ?? []).filter((r) => r.scope === "platform").map((r) => ({ value: r.key, label: r.name }));
  const create = useMutation({ mutationFn: () => api.post("/admin/staff", form), onSuccess: () => { close(); staff.refetch(); notifications.show({ color: "secure", title: "Staff account created", message: "An email to set the password was queued." }); }, onError });
  const setRoles = useMutation({ mutationFn: ({ id, r }: { id: string; r: string[] }) => api.put(`/admin/staff/${id}/roles`, { roles: r }), onSuccess: () => staff.refetch(), onError });
  return (
    <>
      <PageHeader title="Access control" description="Least-privilege roles for Trust Data personnel. Platform roles never grant customer data access on their own." actions={staff.data && <Button leftSection={<IconPlus size={16} />} onClick={open}>Add staff member</Button>} />
      <Stack>
        <Section title="Staff">
          {staff.error ? <ErrorState error={staff.error} /> : (
            <DataTable
              rows={staff.data}
              loading={staff.isLoading}
              rowKey={(s) => s.id}
              columns={[
                { key: "n", header: "Name", render: (s) => <Box><Text size="sm" fw={600}>{s.full_name}</Text><Text size="xs" c="dimmed">{s.email}</Text></Box> },
                { key: "r", header: "Roles", render: (s) => <MultiSelect size="xs" data={platformRoles} value={s.roles} onChange={(r) => setRoles.mutate({ id: s.id, r })} w={300} aria-label={`Roles for ${s.email}`} /> },
                { key: "m", header: "MFA", render: (s) => <Badge color={s.mfa_enabled ? "secure" : "threat"}>{s.mfa_enabled ? "Enrolled" : "Not enrolled"}</Badge> },
                { key: "l", header: "Last sign-in", render: (s) => <Text size="sm">{fmtRelative(s.last_login_at)}</Text>, visibleFrom: "md" },
              ]}
            />
          )}
        </Section>
        <Section title="Role definitions" description="Permissions are enforced by the API for every request.">
          <SimpleGrid cols={{ base: 1, md: 2 }}>
            {roles.data?.map((r) => (
              <Card key={r.key} shadow="none" p="md">
                <Group justify="space-between"><Text fw={600}>{r.name}</Text><Badge variant="outline" color={r.scope === "platform" ? "navy" : "cyber"}>{r.scope}</Badge></Group>
                <Text size="xs" c="dimmed" mt={2}>{r.description}</Text>
                <Group gap={4} mt="xs">{r.permissions.map((p) => <Code key={p} fz={10}>{p}</Code>)}</Group>
              </Card>
            ))}
          </SimpleGrid>
        </Section>
      </Stack>
      <Modal opened={opened} onClose={close} title="Add staff member">
        <Stack>
          <TextInput label="Full name" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.currentTarget.value })} />
          <TextInput label="Email" value={form.email} onChange={(e) => setForm({ ...form, email: e.currentTarget.value })} />
          <MultiSelect label="Roles" data={platformRoles} value={form.roles} onChange={(r) => setForm({ ...form, roles: r })} />
          <Text size="xs" c="dimmed">The staff member must enrol MFA before any platform permission takes effect.</Text>
          <Button onClick={() => create.mutate()} loading={create.isPending} disabled={!form.email || !form.full_name || !form.roles.length}>Create account</Button>
        </Stack>
      </Modal>
    </>
  );
}

// ---------------------------------------------------------------- connectors

export function ConnectorRegistryPage() {
  const can = usePlatformCan();
  const q = useQuery({ queryKey: ["admin-connectors"], queryFn: () => api.get<any[]>("/admin/connectors") }); // eslint-disable-line @typescript-eslint/no-explicit-any
  const [edit, setEdit] = useState<any | null>(null); // eslint-disable-line @typescript-eslint/no-explicit-any
  const save = useMutation({
    mutationFn: () => api.patch(`/admin/connectors/${edit.key}`, { connect_timeout_seconds: edit.connect_timeout_seconds, io_timeout_seconds: edit.io_timeout_seconds, max_retries: edit.max_retries, min_poll_interval_minutes: edit.min_poll_interval_minutes, max_concurrency_per_host: edit.max_concurrency_per_host, status: edit.status === "planned" ? undefined : edit.status }),
    onSuccess: () => { setEdit(null); q.refetch(); },
    onError,
  });
  return (
    <>
      <PageHeader title="Hosting connectors" description="Registered connection types, adapter versions, operational limits and observed error rates." />
      <SimpleGrid cols={{ base: 1, md: 2 }}>
        {q.data?.map((c) => (
          <Card key={c.key}>
            <Group justify="space-between" align="flex-start">
              <Box><Text fw={650}>{c.name}</Text><Text size="xs" c="dimmed">{c.key} · adapter v{c.adapter_version}</Text></Box>
              <Badge color={c.status === "implemented" ? "secure" : c.status === "planned" ? "gray" : "amber"}>{humanize(c.status)}</Badge>
            </Group>
            <Text size="sm" c="dimmed" mt="xs">{c.description}</Text>
            {c.status !== "planned" && (
              <KeyValue items={[["Timeouts", `${c.connect_timeout_seconds}s connect · ${c.io_timeout_seconds}s I/O`], ["Retries", c.max_retries], ["Min poll interval", `${c.min_poll_interval_minutes} min`], ["Accounts", Object.entries(c.accounts_by_status).map(([k, v]) => `${v} ${humanize(k).toLowerCase()}`).join(", ") || "none"], ["Job error rate (7d)", c.job_error_rate_7d === null ? "no data" : `${Math.round(c.job_error_rate_7d * 100)}%`]]} />
            )}
            {c.notes?.limitations && <Text size="xs" c="amber.8" mt="xs">{c.notes.limitations}</Text>}
            {can("platform:connectors:manage") && c.status !== "planned" && <Button mt="sm" size="xs" variant="light" onClick={() => setEdit({ ...c })}>Configure</Button>}
          </Card>
        ))}
      </SimpleGrid>
      <Modal opened={!!edit} onClose={() => setEdit(null)} title={`Configure ${edit?.name}`}>
        {edit && (
          <Stack>
            <Select label="Status" data={[{ value: "implemented", label: "Enabled" }, { value: "disabled", label: "Disabled" }]} value={edit.status} onChange={(v) => setEdit({ ...edit, status: v })} />
            <NumberInput label="Connect timeout (s)" value={edit.connect_timeout_seconds} onChange={(v) => setEdit({ ...edit, connect_timeout_seconds: Number(v) })} />
            <NumberInput label="I/O timeout (s)" value={edit.io_timeout_seconds} onChange={(v) => setEdit({ ...edit, io_timeout_seconds: Number(v) })} />
            <NumberInput label="Max retries" value={edit.max_retries} onChange={(v) => setEdit({ ...edit, max_retries: Number(v) })} />
            <NumberInput label="Min poll interval (min)" value={edit.min_poll_interval_minutes} onChange={(v) => setEdit({ ...edit, min_poll_interval_minutes: Number(v) })} />
            <Button onClick={() => save.mutate()} loading={save.isPending}>Save</Button>
          </Stack>
        )}
      </Modal>
    </>
  );
}

// ---------------------------------------------------------------- plans

export function PlansAdminPage() {
  const q = useQuery({ queryKey: ["admin-plans"], queryFn: () => api.get<any[]>("/admin/plans"), retry: false }); // eslint-disable-line @typescript-eslint/no-explicit-any
  const [edit, setEdit] = useState<any | null>(null); // eslint-disable-line @typescript-eslint/no-explicit-any
  const [ents, setEnts] = useState("");
  const save = useMutation({
    mutationFn: () => api.put(`/admin/plans/${edit.key}`, { ...edit, entitlements: JSON.parse(ents), id: undefined, subscribers: undefined }),
    onSuccess: () => { setEdit(null); q.refetch(); },
    onError,
  });
  if (q.error) return <ErrorState error={q.error} />;
  return (
    <>
      <PageHeader title="Plans and entitlements" description="Prices and limits are configuration. Limits are enforced by the backend for every request." actions={<Button leftSection={<IconPlus size={16} />} onClick={() => { setEdit({ key: "", name: "", description: "", currency: "NGN", price_monthly_minor: null, price_annual_minor: null, is_public: true, is_active: true, sort_order: 60, contact_sales: false }); setEnts(JSON.stringify({ max_websites: 1, max_hosting_accounts: 1, max_users: 1, min_file_scan_interval_minutes: 1440, min_availability_interval_minutes: 15, retention_days: 30, notifications_per_month: 100, reports: false, whatsapp_notifications: false, managed_service: false, api_access: false, support_level: "standard" }, null, 2)); }}>New plan</Button>} />
      <DataTable
        rows={q.data}
        loading={q.isLoading}
        rowKey={(p) => p.key}
        columns={[
          { key: "n", header: "Plan", render: (p) => <Box><Text size="sm" fw={600}>{p.name}</Text><Text size="xs" c="dimmed">{p.key}</Text></Box> },
          { key: "m", header: "Monthly", render: (p) => <Text size="sm">{p.contact_sales ? "Contact sales" : fmtMoney(p.price_monthly_minor, p.currency)}</Text> },
          { key: "a", header: "Annual", render: (p) => <Text size="sm">{p.contact_sales ? "—" : fmtMoney(p.price_annual_minor, p.currency)}</Text>, visibleFrom: "sm" },
          { key: "l", header: "Limits", render: (p) => <Text size="xs">{p.entitlements.max_websites} sites · {p.entitlements.max_users} users · {p.entitlements.retention_days}d</Text>, visibleFrom: "md" },
          { key: "s", header: "Subscribers", render: (p) => <Text size="sm">{p.subscribers}</Text> },
          { key: "st", header: "State", render: (p) => <Badge color={p.is_active ? "secure" : "gray"}>{p.is_active ? (p.is_public ? "Public" : "Private") : "Inactive"}</Badge> },
          { key: "x", header: "", render: (p) => <Button size="xs" variant="subtle" onClick={() => { setEdit({ ...p }); setEnts(JSON.stringify(p.entitlements, null, 2)); }}>Edit</Button> },
        ]}
      />
      <Modal opened={!!edit} onClose={() => setEdit(null)} title={edit?.name ? `Edit ${edit.name}` : "New plan"} size="lg">
        {edit && (
          <Stack>
            <Group grow>
              <TextInput label="Key" value={edit.key} disabled={!!edit.id} onChange={(e) => setEdit({ ...edit, key: e.currentTarget.value })} />
              <TextInput label="Name" value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.currentTarget.value })} />
            </Group>
            <Textarea label="Description" value={edit.description} onChange={(e) => setEdit({ ...edit, description: e.currentTarget.value })} />
            <Group grow>
              <NumberInput label="Monthly price (kobo)" value={edit.price_monthly_minor ?? ""} onChange={(v) => setEdit({ ...edit, price_monthly_minor: v === "" ? null : Number(v) })} />
              <NumberInput label="Annual price (kobo)" value={edit.price_annual_minor ?? ""} onChange={(v) => setEdit({ ...edit, price_annual_minor: v === "" ? null : Number(v) })} />
            </Group>
            <JsonInput label="Entitlements" autosize minRows={8} validationError="Invalid JSON" value={ents} onChange={setEnts} formatOnBlur />
            <Group>
              <Switch label="Active" checked={edit.is_active} onChange={(e) => setEdit({ ...edit, is_active: e.currentTarget.checked })} />
              <Switch label="Public" checked={edit.is_public} onChange={(e) => setEdit({ ...edit, is_public: e.currentTarget.checked })} />
              <Switch label="Contact sales" checked={edit.contact_sales} onChange={(e) => setEdit({ ...edit, contact_sales: e.currentTarget.checked })} />
            </Group>
            <Button onClick={() => save.mutate()} loading={save.isPending}>Save plan</Button>
          </Stack>
        )}
      </Modal>
    </>
  );
}

// ---------------------------------------------------------------- payments

export function PaymentsAdminPage() {
  const can = usePlatformCan();
  const [status, setStatus] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const payments = useQuery({ queryKey: ["admin-payments", status, page], queryFn: () => api.get<Page<any>>("/admin/payments", { status: status ?? undefined, page, page_size: 25 }), retry: false }); // eslint-disable-line @typescript-eslint/no-explicit-any
  const hooks = useQuery({ queryKey: ["admin-webhooks"], queryFn: () => api.get<Page<any>>("/admin/webhooks", { page_size: 15 }), retry: false }); // eslint-disable-line @typescript-eslint/no-explicit-any
  const reverify = useMutation({ mutationFn: (id: string) => api.post(`/admin/payments/${id}/reverify`), onSuccess: () => payments.refetch(), onError });
  if (payments.error) return <ErrorState error={payments.error} />;
  return (
    <>
      <PageHeader title="Payments and revenue" description="Transactions, verification state and webhook processing. Card data is never stored." />
      <Stack>
        <Section title="Transactions" actions={<Select placeholder="Status" clearable w={160} data={["initialized", "success", "failed", "abandoned"].map((v) => ({ value: v, label: humanize(v) }))} value={status} onChange={setStatus} aria-label="Status" />}>
          <DataTable
            rows={payments.data?.items}
            loading={payments.isLoading}
            rowKey={(p) => p.id}
            page={page}
            pageSize={25}
            total={payments.data?.total}
            onPage={setPage}
            empty={<EmptyState title="No transactions" />}
            columns={[
              { key: "t", header: "Created", render: (p) => <Text size="sm">{fmtDateTime(p.created_at)}</Text> },
              { key: "c", header: "Customer", render: (p) => <Text size="sm">{p.tenant}</Text> },
              { key: "a", header: "Amount", render: (p) => <Text size="sm">{fmtMoney(p.amount_minor, p.currency)}</Text> },
              { key: "s", header: "Status", render: (p) => <Badge color={p.status === "success" ? "secure" : p.status === "initialized" ? "gray" : "threat"}>{humanize(p.status)}</Badge> },
              { key: "r", header: "Reconciled", render: (p) => <Badge variant="outline" color={p.reconciled ? "secure" : "gray"}>{p.reconciled ? "Verified" : "No"}</Badge>, visibleFrom: "md" },
              { key: "ref", header: "Reference", render: (p) => <Text size="xs" className="cw-mono">{p.reference}</Text>, visibleFrom: "lg" },
              { key: "x", header: "", render: (p) => can("platform:payments:manage") && p.status !== "success" && <Button size="xs" variant="subtle" onClick={() => reverify.mutate(p.id)}>Re-verify</Button> },
            ]}
          />
        </Section>
        <Section title="Webhook events" description="Signature-verified, deduplicated and re-verified with the provider before any change.">
          <DataTable
            rows={hooks.data?.items}
            loading={hooks.isLoading}
            rowKey={(w) => w.id}
            empty={<EmptyState title="No webhook events received" />}
            columns={[
              { key: "t", header: "Received", render: (w) => <Text size="sm">{fmtDateTime(w.received_at)}</Text> },
              { key: "e", header: "Event", render: (w) => <Text size="sm" className="cw-mono">{w.event_type}</Text> },
              { key: "s", header: "Processing", render: (w) => <Badge color={w.status === "processed" ? "secure" : w.status === "failed" ? "threat" : "gray"}>{humanize(w.status)}</Badge> },
              { key: "err", header: "Error", render: (w) => <Text size="xs" c="dimmed">{w.error}</Text> },
            ]}
          />
        </Section>
      </Stack>
    </>
  );
}

// ---------------------------------------------------------------- messaging

export function MessagingAdminPage() {
  const [status, setStatus] = useState<string>("failed");
  const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: ["admin-messaging", status, page], queryFn: () => api.get<any>("/admin/messaging", { status, page, page_size: 25 }), retry: false }); // eslint-disable-line @typescript-eslint/no-explicit-any
  const retry = useMutation({ mutationFn: (id: string) => api.post(`/admin/notifications/${id}/retry`), onSuccess: () => q.refetch(), onError });
  if (q.error) return <ErrorState error={q.error} />;
  const d = q.data;
  return (
    <>
      <PageHeader title="Messaging" description="Email and WhatsApp Business delivery. Provider credentials are configured through protected environment secrets and never displayed." />
      <SimpleGrid cols={{ base: 1, md: 2 }} mb="md">
        <Section title="Email (SMTP)">{d && <KeyValue items={[["Status", <HealthBadge key="e" state={d.channels.email.configured ? "healthy" : "unavailable"} />], ["Host", d.channels.email.host ?? "Not configured"]]} />}</Section>
        <Section title="WhatsApp Cloud API">
          {d && <KeyValue items={[["Status", <HealthBadge key="w" state={d.channels.whatsapp.configured ? "healthy" : "unavailable"} />], ["Graph API version", d.channels.whatsapp.api_version], ...Object.entries(d.whatsapp_templates as Record<string, { name: string; language: string }>).map(([k, t]) => [`Template: ${humanize(k)}`, `${t.name} (${t.language})`] as [string, string])]} />}
          <Text size="xs" c="dimmed" mt="xs">Templates must be approved in WhatsApp Manager before delivery succeeds.</Text>
        </Section>
      </SimpleGrid>
      <Section title="Delivery queue" actions={<Select w={170} data={["failed", "pending", "unconfigured", "suppressed", "sent"].map((v) => ({ value: v, label: humanize(v) }))} value={status} onChange={(v) => setStatus(v ?? "failed")} aria-label="Status" />}>
        <DataTable
          rows={d?.items}
          loading={q.isLoading}
          rowKey={(n: { id: string }) => n.id}
          page={page}
          pageSize={25}
          total={d?.total}
          onPage={setPage}
          empty={<EmptyState title={`No ${status} notifications`} />}
          columns={[
            { key: "t", header: "Created", render: (n: any) => <Text size="sm">{fmtDateTime(n.created_at)}</Text> }, // eslint-disable-line @typescript-eslint/no-explicit-any
            { key: "c", header: "Customer", render: (n: any) => <Text size="sm">{n.tenant ?? "Platform"}</Text> }, // eslint-disable-line @typescript-eslint/no-explicit-any
            { key: "ch", header: "Channel", render: (n: any) => <Text size="sm">{humanize(n.channel)}</Text> }, // eslint-disable-line @typescript-eslint/no-explicit-any
            { key: "a", header: "Attempts", render: (n: any) => <Text size="sm">{n.attempts}</Text> }, // eslint-disable-line @typescript-eslint/no-explicit-any
            { key: "e", header: "Last error", render: (n: any) => <Text size="xs" c="dimmed">{n.last_error}</Text> }, // eslint-disable-line @typescript-eslint/no-explicit-any
            { key: "x", header: "", render: (n: any) => (n.status === "failed" || n.status === "unconfigured") && <Button size="xs" variant="subtle" onClick={() => retry.mutate(n.id)}>Retry</Button> }, // eslint-disable-line @typescript-eslint/no-explicit-any
          ]}
        />
      </Section>
    </>
  );
}

// ---------------------------------------------------------------- managed services

export function ManagedServicesPage() {
  const can = usePlatformCan();
  const grants = useQuery({ queryKey: ["admin-grants"], queryFn: () => api.get<any[]>("/admin/grants") }); // eslint-disable-line @typescript-eslint/no-explicit-any
  const tenants = useQuery({ queryKey: ["admin-tenant-options"], queryFn: () => api.get<Page<{ id: string; name: string }>>("/admin/tenants", { page_size: 200 }), enabled: can("platform:tenants:read") });
  const me = useMe();
  const staff = useQuery({
    queryKey: ["admin-staff"],
    queryFn: () => api.get<{ id: string; email: string; full_name: string; is_active: boolean }[]>("/admin/staff"),
    enabled: can("platform:users:manage"),
  });
  const [form, setForm] = useState({ tenant_id: "", grantee_user_id: "", permissions: ["tenant:read", "websites:read", "monitoring:read", "incidents:read"], reason: "", duration_hours: 72, customer_approval_reference: "" });
  const myId = me.data?.id ?? "";
  const grantee = form.grantee_user_id || myId;
  // The API refuses an administrator activating access for themselves; say so before submitting.
  const selfIssue = !!form.customer_approval_reference.trim() && grantee === myId;
  const request = useMutation({
    mutationFn: () =>
      api.post("/admin/grants", {
        ...form,
        grantee_user_id: form.grantee_user_id || null,
        customer_approval_reference: form.customer_approval_reference.trim() || null,
      }),
    onSuccess: (g: any) => { // eslint-disable-line @typescript-eslint/no-explicit-any
      grants.refetch();
      setForm((f) => ({ ...f, reason: "", customer_approval_reference: "" }));
      notifications.show(g?.status === "active"
        ? { color: "secure", title: "Grant active", message: "Access was activated with the approval reference. Open the workspace from the Grants list." }
        : { color: "secure", title: "Request recorded", message: "The customer must approve the request before access is granted." });
    },
    onError,
  });
  const PERMS = ["tenant:read", "members:read", "websites:read", "hosting:read", "monitoring:read", "inventory:read", "incidents:read", "incidents:manage", "notifications:read", "reports:read", "reports:generate", "support:read", "support:manage", "scans:run", "monitoring:manage"];
  return (
    <>
      <PageHeader title="Managed services" description="Customer-approved, time-limited access for Trust Data service staff. Every action under a grant is audited with the grant ID." />
      <Grid>
        <Grid.Col span={{ base: 12, lg: 5 }}>
          <Section title="Request access to a customer">
            <Stack>
              {tenants.data ? (
                <Select label="Customer" searchable data={tenants.data.items.map((t) => ({ value: t.id, label: t.name }))} value={form.tenant_id || null} onChange={(v) => setForm({ ...form, tenant_id: v ?? "" })} />
              ) : (
                <TextInput label="Customer organisation ID" value={form.tenant_id} onChange={(e) => setForm({ ...form, tenant_id: e.currentTarget.value })} />
              )}
              {staff.data && (
                <Select
                  label="Staff member who will receive access"
                  data={staff.data.filter((u) => u.is_active).map((u) => ({ value: u.id, label: `${u.full_name} (${u.email})${u.id === myId ? " - you" : ""}` }))}
                  value={grantee || null}
                  onChange={(v) => setForm({ ...form, grantee_user_id: v ?? "" })}
                />
              )}
              <MultiSelect label="Access requested" data={PERMS} value={form.permissions} onChange={(v) => setForm({ ...form, permissions: v })} />
              <Textarea label="Reason" required description={minCharsHint(form.reason, 10, "Why access is needed, e.g. the support ticket number.")} value={form.reason} onChange={(e) => setForm({ ...form, reason: e.currentTarget.value })} />
              <NumberInput label="Duration (hours)" min={1} max={2160} value={form.duration_hours} onChange={(v) => setForm({ ...form, duration_hours: Number(v) || 72 })} />
              {can("grants:issue") && (
                <TextInput
                  label="Customer approval reference (administrators only)"
                  description="Optional. The number of the customer's signed managed-service order or written approval, e.g. MSO-2026-014. Filling it in activates the grant immediately; leave it empty to send a request for the customer to approve."
                  placeholder="e.g. MSO-2026-014"
                  error={selfIssue ? "You cannot activate access for yourself. Choose another staff member above, or leave this empty and ask another administrator to approve." : undefined}
                  value={form.customer_approval_reference}
                  onChange={(e) => setForm({ ...form, customer_approval_reference: e.currentTarget.value })}
                />
              )}
              <Button onClick={() => request.mutate()} loading={request.isPending} disabled={!form.tenant_id || form.reason.trim().length < 10 || form.permissions.length === 0 || selfIssue}>Submit request</Button>
            </Stack>
          </Section>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 7 }}>
          <Section title="Grants">
            <DataTable
              rows={grants.data}
              loading={grants.isLoading}
              rowKey={(g) => g.id}
              empty={<EmptyState icon={IconShieldCheck} title="No grants" />}
              columns={[
                { key: "c", header: "Customer", render: (g) => <Text size="sm" fw={600}>{g.tenant_name}</Text> },
                { key: "s", header: "Staff", render: (g) => <Text size="sm">{g.grantee_name}</Text> },
                { key: "st", header: "Status", render: (g) => <Badge color={g.status === "active" ? "secure" : g.status === "requested" ? "amber" : "gray"}>{humanize(g.status)}</Badge> },
                { key: "e", header: "Expires", render: (g) => <Text size="sm">{fmtDateTime(g.expires_at)}</Text> },
                { key: "o", header: "", render: (g) => g.status === "active" && <Button size="xs" variant="light" component="a" href={`/app/${g.tenant_id}/overview`}>Open workspace</Button> },
              ]}
            />
          </Section>
        </Grid.Col>
      </Grid>
    </>
  );
}

// ---------------------------------------------------------------- analytics

export function AnalyticsPage() {
  const q = useQuery({ queryKey: ["admin-analytics"], queryFn: () => api.get<{ scans: { day: string; job_type: string; status: string; count: number; avg_seconds: number }[]; incidents: { day: string; severity: string; count: number }[]; notifications: { day: string; channel: string; status: string; count: number }[]; tenant_usage: { tenant: string; plan: string; websites: number; limit: number; over_limit: boolean }[] }>("/admin/analytics") });
  if (q.error) return <ErrorState error={q.error} />;
  const d = q.data;
  const pivot = (rows: { day: string; count: number }[] | undefined, key: (r: any) => string) => { // eslint-disable-line @typescript-eslint/no-explicit-any
    const out: Record<string, Record<string, number>> = {};
    rows?.forEach((r) => { out[r.day] = out[r.day] ?? {}; out[r.day][key(r)] = (out[r.day][key(r)] ?? 0) + r.count; });
    return out;
  };
  return (
    <>
      <PageHeader title="Analytics and usage" description="Platform-wide throughput, reliability and plan compliance over the last 30 days." />
      <SimpleGrid cols={{ base: 1, lg: 2 }}>
        <Section title="Monitoring jobs by outcome">{d ? <StackedBars label="Jobs" data={pivot(d.scans, (r) => r.status)} series={[{ key: "succeeded", label: "Succeeded", color: SERIES_COLORS.ok }, { key: "partial", label: "Partial", color: SERIES_COLORS.warn }, { key: "failed", label: "Failed", color: SERIES_COLORS.bad }, { key: "cancelled", label: "Cancelled", color: SERIES_COLORS.informational }]} /> : <LoadingBlock />}</Section>
        <Section title="Incidents by severity">{d ? <StackedBars label="Incidents" data={pivot(d.incidents, (r) => r.severity)} series={[{ key: "critical", label: "Critical", color: SERIES_COLORS.critical }, { key: "high", label: "High", color: SERIES_COLORS.high }, { key: "medium", label: "Medium", color: SERIES_COLORS.medium }, { key: "low", label: "Low", color: SERIES_COLORS.low }]} /> : <LoadingBlock />}</Section>
        <Section title="Notification delivery">{d ? <StackedBars label="Notifications" data={pivot(d.notifications, (r) => r.status)} series={[{ key: "sent", label: "Sent", color: SERIES_COLORS.ok }, { key: "pending", label: "Pending", color: SERIES_COLORS.blue }, { key: "failed", label: "Failed", color: SERIES_COLORS.bad }, { key: "unconfigured", label: "Unconfigured", color: SERIES_COLORS.warn }]} /> : <LoadingBlock />}</Section>
        <Section title="Tenant plan compliance">
          <DataTable rows={d?.tenant_usage} loading={!d} rowKey={(r) => r.tenant} columns={[
            { key: "t", header: "Customer", render: (r) => <Text size="sm">{r.tenant}</Text> },
            { key: "p", header: "Plan", render: (r) => <Text size="sm">{r.plan}</Text> },
            { key: "w", header: "Websites", render: (r) => <Text size="sm" c={r.over_limit ? "threat.6" : undefined}>{r.websites} / {r.limit}</Text> },
          ]} />
        </Section>
      </SimpleGrid>
    </>
  );
}

// ---------------------------------------------------------------- audit

export function AuditAdminPage() {
  const [page, setPage] = useState(1);
  const [action, setAction] = useState("");
  const [outcome, setOutcome] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["admin-audit", page, action, outcome], queryFn: () => api.get<Page<any>>("/admin/audit", { page, page_size: 40, action, outcome: outcome ?? undefined }), retry: false }); // eslint-disable-line @typescript-eslint/no-explicit-any
  const verify = useMutation({ mutationFn: () => api.get<{ valid: boolean; events_checked: number; first_invalid_seq: number | null; reason: string | null }>("/admin/audit/verify") });
  if (q.error) return <ErrorState error={q.error} />;
  return (
    <>
      <PageHeader title="Audit and compliance" description="Searchable, hash-chained audit trail of authentication, privileged and configuration events." actions={<Button variant="default" leftSection={<IconShieldCheck size={16} />} onClick={() => verify.mutate()} loading={verify.isPending}>Verify integrity</Button>} />
      {verify.data && <Alert mb="md" color={verify.data.valid ? "secure" : "threat"} title={verify.data.valid ? "Audit chain intact" : "Audit chain broken"}>{verify.data.events_checked} events checked.{verify.data.reason ? ` ${verify.data.reason} (sequence ${verify.data.first_invalid_seq})` : ""}</Alert>}
      <Card>
        <Group mb="md">
          <SearchInput value={action} onChange={(v) => { setAction(v); setPage(1); }} placeholder="Action prefix, e.g. auth." />
          <Select placeholder="Outcome" clearable w={150} data={["success", "denied", "failure"].map((v) => ({ value: v, label: humanize(v) }))} value={outcome} onChange={setOutcome} aria-label="Outcome" />
        </Group>
        <DataTable
          rows={q.data?.items}
          loading={q.isLoading}
          rowKey={(e) => e.id}
          page={page}
          pageSize={40}
          total={q.data?.total}
          onPage={setPage}
          columns={[
            { key: "t", header: "Time", render: (e) => <Text size="sm">{fmtDateTime(e.occurred_at)}</Text> },
            { key: "a", header: "Action", render: (e) => <Text size="sm" className="cw-mono">{e.action}</Text> },
            { key: "w", header: "Actor", render: (e) => <Text size="sm">{e.actor_email ?? humanize(e.actor_type)}</Text> },
            { key: "o", header: "Outcome", render: (e) => <Badge color={e.outcome === "success" ? "secure" : "threat"}>{humanize(e.outcome)}</Badge> },
            { key: "ip", header: "IP", render: (e) => <Text size="xs">{e.ip_address}</Text>, visibleFrom: "md" },
            { key: "d", header: "Details", render: (e) => <Text size="xs" c="dimmed" lineClamp={2} className="cw-mono">{JSON.stringify(e.details)}</Text>, visibleFrom: "lg" },
          ]}
        />
      </Card>
    </>
  );
}

// ---------------------------------------------------------------- configuration

export function ConfigurationPage() {
  const q = useQuery({ queryKey: ["admin-settings"], queryFn: () => api.get<{ editable: Record<string, { description: string; value: unknown; updated_at?: string }>; environment: Record<string, unknown> }>("/admin/settings"), retry: false });
  const [edit, setEdit] = useState<{ key: string; value: string } | null>(null);
  const save = useMutation({ mutationFn: () => api.put(`/admin/settings/${edit?.key}`, { value: JSON.parse(edit?.value ?? "{}") }), onSuccess: () => { setEdit(null); q.refetch(); }, onError });
  if (q.error) return <ErrorState error={q.error} />;
  return (
    <>
      <PageHeader title="Platform configuration" description="Environment settings are read-only here (set through protected deployment configuration). Editable settings are audited." />
      <SimpleGrid cols={{ base: 1, lg: 2 }}>
        <Section title="Deployment settings (read-only)">{q.data && <KeyValue items={Object.entries(q.data.environment).map(([k, v]) => [humanize(k), <Code key={k}>{JSON.stringify(v)}</Code>])} />}</Section>
        <Section title="Editable settings">
          <Stack>
            {q.data && Object.entries(q.data.editable).map(([k, s]) => (
              <Card key={k} p="sm" shadow="none">
                <Group justify="space-between"><Text size="sm" fw={600}>{humanize(k)}</Text>{k !== "backup_status" && <Button size="xs" variant="subtle" onClick={() => setEdit({ key: k, value: JSON.stringify(s.value ?? {}, null, 2) })}>Edit</Button>}</Group>
                <Text size="xs" c="dimmed">{s.description}</Text>
                <Code block mt={4}>{JSON.stringify(s.value)}</Code>
              </Card>
            ))}
          </Stack>
        </Section>
      </SimpleGrid>
      <Modal opened={!!edit} onClose={() => setEdit(null)} title={`Edit ${humanize(edit?.key)}`}>
        {edit && (
          <Stack>
            <JsonInput autosize minRows={6} value={edit.value} onChange={(v) => setEdit({ ...edit, value: v })} validationError="Invalid JSON" />
            <ConfirmButton title="Apply configuration change?" message="This change is recorded in the audit trail." onConfirm={() => save.mutateAsync()}>Save</ConfirmButton>
          </Stack>
        )}
      </Modal>
    </>
  );
}

