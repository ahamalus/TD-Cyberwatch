import {
  Alert,
  Badge,
  Box,
  Button,
  Card,
  Center,
  Code,
  CopyButton,
  Group,
  Modal,
  MultiSelect,
  NumberInput,
  PasswordInput,
  PinInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  TextInput,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconShieldCheck } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useMe, useRefreshMe, useTenant, useTenantId, useCan } from "../../api/auth";
import { api, errorMessage } from "../../api/client";
import type { Page } from "../../api/types";
import { fmtDateTime, fmtRelative, humanize } from "../../components/format";
import { ConfirmButton, DataTable, EmptyState, PageHeader, Section } from "../../components/ui";

const onError = (e: unknown) => notifications.show({ color: "threat", title: "Action failed", message: errorMessage(e) });
const ok = (message: string) => notifications.show({ color: "secure", title: "Saved", message });

export function SettingsPage() {
  const tid = useTenantId();
  const can = useCan();
  const [tab, setTab] = useState<string | null>("profile");
  return (
    <>
      <PageHeader title="Settings" description="Your account security and your organisation's team, access and activity." crumbs={[{ label: "Overview", to: `/app/${tid}/overview` }, { label: "Settings" }]} />
      <Tabs value={tab} onChange={setTab} keepMounted={false}>
        <Tabs.List mb="md" style={{ overflowX: "auto", flexWrap: "nowrap" }}>
          <Tabs.Tab value="profile">Profile</Tabs.Tab>
          <Tabs.Tab value="security">Security</Tabs.Tab>
          <Tabs.Tab value="organisation">Organisation</Tabs.Tab>
          {can("members:read") && <Tabs.Tab value="team">Team</Tabs.Tab>}
          <Tabs.Tab value="access">Managed-service access</Tabs.Tab>
          <Tabs.Tab value="tokens">API tokens</Tabs.Tab>
          {can("audit:read") && <Tabs.Tab value="activity">Activity</Tabs.Tab>}
        </Tabs.List>
        <Tabs.Panel value="profile"><ProfilePanel /></Tabs.Panel>
        <Tabs.Panel value="security"><AccountSecurity /></Tabs.Panel>
        <Tabs.Panel value="organisation"><OrganisationPanel /></Tabs.Panel>
        <Tabs.Panel value="team"><TeamPanel /></Tabs.Panel>
        <Tabs.Panel value="access"><GrantsPanel /></Tabs.Panel>
        <Tabs.Panel value="tokens"><TokensPanel /></Tabs.Panel>
        <Tabs.Panel value="activity"><ActivityPanel /></Tabs.Panel>
      </Tabs>
    </>
  );
}

function ProfilePanel() {
  const me = useMe();
  const refresh = useRefreshMe();
  const [name, setName] = useState(me.data?.full_name ?? "");
  const [phone, setPhone] = useState(me.data?.phone ?? "");
  const [wa, setWa] = useState(Boolean(me.data?.preferences?.whatsapp_opt_in));
  const save = useMutation({
    mutationFn: () => api.patch("/auth/me", { full_name: name, phone: phone || null, whatsapp_opt_in: wa }),
    onSuccess: () => { ok("Profile updated."); refresh(); },
    onError,
  });
  return (
    <Card maw={640}>
      <Stack>
        <TextInput label="Full name" value={name} onChange={(e) => setName(e.currentTarget.value)} />
        <TextInput label="Email" value={me.data?.email ?? ""} disabled description={me.data?.email_verified ? "Verified" : "Not yet verified"} />
        <TextInput label="Mobile number (international format)" placeholder="+2348012345678" value={phone} onChange={(e) => setPhone(e.currentTarget.value)} />
        <Switch label="I consent to receive security alerts on WhatsApp" description="You can withdraw consent at any time." checked={wa} onChange={(e) => setWa(e.currentTarget.checked)} />
        <Button w="fit-content" onClick={() => save.mutate()} loading={save.isPending}>Save profile</Button>
      </Stack>
    </Card>
  );
}

/** Password, MFA, sessions and login history. Also used by staff accounts. */
export function AccountSecurity() {
  const me = useMe();
  const refresh = useRefreshMe();
  const [pw, setPw] = useState({ current_password: "", new_password: "" });
  const [enrol, setEnrol] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [disableOpen, disable] = useDisclosure(false);
  const [disablePw, setDisablePw] = useState("");
  const sessions = useQuery({ queryKey: ["sessions"], queryFn: () => api.get<{ id: string; created_at: string; last_seen_at: string; ip_address: string | null; user_agent: string | null; current: boolean }[]>("/auth/sessions") });
  const history = useQuery({ queryKey: ["login-history"], queryFn: () => api.get<{ created_at: string; success: boolean; reason: string; ip_address: string | null; user_agent: string | null }[]>("/auth/login-history") });
  const change = useMutation({ mutationFn: () => api.post("/auth/password/change", pw), onSuccess: () => { setPw({ current_password: "", new_password: "" }); ok("Password changed. Other sessions were signed out."); sessions.refetch(); }, onError });
  const start = useMutation({ mutationFn: () => api.post<{ secret: string; otpauth_uri: string }>("/auth/mfa/enroll"), onSuccess: setEnrol, onError });
  const confirm = useMutation({ mutationFn: () => api.post<{ recovery_codes: string[] }>("/auth/mfa/enroll/confirm", { code }), onSuccess: (r) => { setCodes(r.recovery_codes); setEnrol(null); refresh(); }, onError });
  const off = useMutation({ mutationFn: () => api.post("/auth/mfa/disable", { password: disablePw }), onSuccess: () => { disable.close(); refresh(); ok("MFA disabled."); }, onError });
  const revoke = useMutation({ mutationFn: (id: string) => api.del(`/auth/sessions/${id}`), onSuccess: () => sessions.refetch(), onError });

  return (
    <Stack>
      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Section title="Multi-factor authentication" description="Protects your account with a code from an authenticator app.">
          {me.data?.mfa_enabled ? (
            <Stack>
              <Badge color="secure" leftSection={<IconShieldCheck size={12} />} size="lg">MFA enabled</Badge>
              {me.data.is_platform_staff ? <Text size="sm" c="dimmed">MFA is mandatory for Trust Data staff.</Text> : (
                <Button variant="subtle" color="threat" w="fit-content" onClick={disable.open}>Disable MFA</Button>
              )}
            </Stack>
          ) : enrol ? (
            <Stack>
              <Text size="sm">Add this account to your authenticator app using the setup key, then enter the 6-digit code.</Text>
              <Code block>{enrol.secret}</Code>
              <Text size="xs" c="dimmed" style={{ wordBreak: "break-all" }}>{enrol.otpauth_uri}</Text>
              <Center><PinInput length={6} type="number" value={code} onChange={setCode} aria-label="Verification code" oneTimeCode /></Center>
              <Button onClick={() => confirm.mutate()} loading={confirm.isPending} disabled={code.length !== 6}>Verify and enable</Button>
            </Stack>
          ) : (
            <Stack>
              {me.data?.platform_mfa_required && <Alert color="amber">Platform functions are unavailable until you enable MFA.</Alert>}
              <Button w="fit-content" onClick={() => start.mutate()} loading={start.isPending}>Set up MFA</Button>
            </Stack>
          )}
          {codes && (
            <Alert color="amber" mt="md" title="Save your recovery codes">
              <Text size="sm" mb="xs">Each code works once. They will not be shown again.</Text>
              <Code block>{codes.join("\n")}</Code>
              <CopyButton value={codes.join("\n")}>{({ copied, copy }) => <Button size="xs" mt="xs" variant="light" onClick={copy}>{copied ? "Copied" : "Copy codes"}</Button>}</CopyButton>
            </Alert>
          )}
        </Section>
        <Section title="Change password">
          <Stack>
            <PasswordInput label="Current password" value={pw.current_password} onChange={(e) => setPw({ ...pw, current_password: e.currentTarget.value })} autoComplete="current-password" />
            <PasswordInput label="New password" description="At least 12 characters." value={pw.new_password} onChange={(e) => setPw({ ...pw, new_password: e.currentTarget.value })} autoComplete="new-password" />
            <Button w="fit-content" onClick={() => change.mutate()} loading={change.isPending} disabled={!pw.current_password || pw.new_password.length < 12}>Change password</Button>
          </Stack>
        </Section>
      </SimpleGrid>
      <Section title="Active sessions" description="Sign out sessions you do not recognise.">
        <DataTable
          rows={sessions.data}
          loading={sessions.isLoading}
          rowKey={(s) => s.id}
          columns={[
            { key: "ua", header: "Device", render: (s) => <Text size="sm" lineClamp={1}>{s.user_agent ?? "Unknown"}{s.current ? " (this session)" : ""}</Text> },
            { key: "ip", header: "IP address", render: (s) => <Text size="sm">{s.ip_address ?? "—"}</Text> },
            { key: "seen", header: "Last active", render: (s) => <Text size="sm">{fmtRelative(s.last_seen_at)}</Text> },
            { key: "x", header: "", render: (s) => !s.current && <Button size="xs" variant="subtle" color="threat" onClick={() => revoke.mutate(s.id)}>Sign out</Button> },
          ]}
        />
      </Section>
      <Section title="Login history">
        <DataTable
          rows={history.data}
          loading={history.isLoading}
          rowKey={(h) => h.created_at}
          columns={[
            { key: "t", header: "Time", render: (h) => <Text size="sm">{fmtDateTime(h.created_at)}</Text> },
            { key: "r", header: "Result", render: (h) => <Badge color={h.success ? "secure" : "threat"}>{h.success ? "Success" : humanize(h.reason)}</Badge> },
            { key: "ip", header: "IP address", render: (h) => <Text size="sm">{h.ip_address ?? "—"}</Text> },
            { key: "ua", header: "Device", render: (h) => <Text size="xs" c="dimmed" lineClamp={1}>{h.user_agent}</Text>, visibleFrom: "md" },
          ]}
        />
      </Section>
      <Modal opened={disableOpen} onClose={disable.close} title="Disable MFA">
        <Stack>
          <Text size="sm">Disabling MFA makes your account easier to compromise. Confirm with your password.</Text>
          <PasswordInput label="Password" value={disablePw} onChange={(e) => setDisablePw(e.currentTarget.value)} />
          <Button color="threat" onClick={() => off.mutate()} loading={off.isPending}>Disable MFA</Button>
        </Stack>
      </Modal>
    </Stack>
  );
}

function OrganisationPanel() {
  const tid = useTenantId();
  const tenant = useTenant();
  const can = useCan();
  const [form, setForm] = useState<{ name?: string; industry?: string; contact_email?: string; contact_phone?: string; timezone?: string }>({});
  const groups = useQuery({ queryKey: ["groups", tid], queryFn: () => api.get<{ id: string; name: string; kind: string }[]>(`/tenants/${tid}/groups`) });
  const [groupName, setGroupName] = useState("");
  const [groupKind, setGroupKind] = useState("business_unit");
  const save = useMutation({ mutationFn: () => api.patch(`/tenants/${tid}`, form), onSuccess: () => { ok("Organisation updated."); tenant.refetch(); }, onError });
  const addGroup = useMutation({ mutationFn: () => api.post(`/tenants/${tid}/groups`, { name: groupName, kind: groupKind }), onSuccess: () => { setGroupName(""); groups.refetch(); }, onError });
  const t = tenant.data;
  if (!t) return null;
  const disabled = !can("tenant:manage");
  return (
    <SimpleGrid cols={{ base: 1, md: 2 }}>
      <Section title="Organisation profile">
        <Stack>
          <TextInput label="Name" defaultValue={t.name} disabled={disabled} onChange={(e) => setForm({ ...form, name: e.currentTarget.value })} />
          <TextInput label="Industry" defaultValue={t.industry ?? ""} disabled={disabled} onChange={(e) => setForm({ ...form, industry: e.currentTarget.value })} />
          <TextInput label="Security contact email" defaultValue={t.contact_email ?? ""} disabled={disabled} onChange={(e) => setForm({ ...form, contact_email: e.currentTarget.value })} />
          <TextInput label="Contact phone" defaultValue={t.contact_phone ?? ""} disabled={disabled} onChange={(e) => setForm({ ...form, contact_phone: e.currentTarget.value })} />
          <TextInput label="Timezone" defaultValue={t.timezone} disabled={disabled} onChange={(e) => setForm({ ...form, timezone: e.currentTarget.value })} />
          {!disabled && <Button w="fit-content" onClick={() => save.mutate()} loading={save.isPending}>Save</Button>}
        </Stack>
      </Section>
      <Section title="Website groups" description="Group websites by business unit, environment or client.">
        <Stack>
          {groups.data?.length === 0 && <Text size="sm" c="dimmed">No groups yet.</Text>}
          {groups.data?.map((g) => (
            <Group key={g.id} justify="space-between">
              <Text size="sm">{g.name} <Text span size="xs" c="dimmed">({humanize(g.kind)})</Text></Text>
              {can("websites:manage") && <Button size="xs" variant="subtle" color="gray" onClick={async () => { await api.del(`/tenants/${tid}/groups/${g.id}`); groups.refetch(); }}>Remove</Button>}
            </Group>
          ))}
          {can("websites:manage") && (
            <Group align="flex-end">
              <TextInput label="New group" value={groupName} onChange={(e) => setGroupName(e.currentTarget.value)} style={{ flex: 1 }} />
              <Select data={[{ value: "business_unit", label: "Business unit" }, { value: "environment", label: "Environment" }, { value: "client", label: "Client" }, { value: "other", label: "Other" }]} value={groupKind} onChange={(v) => setGroupKind(v ?? "business_unit")} w={150} aria-label="Group type" />
              <Button onClick={() => addGroup.mutate()} disabled={!groupName}>Add</Button>
            </Group>
          )}
        </Stack>
      </Section>
    </SimpleGrid>
  );
}

const TENANT_ROLES = [
  { value: "owner", label: "Owner" },
  { value: "admin", label: "Administrator" },
  { value: "security_lead", label: "Security lead" },
  { value: "analyst", label: "Analyst" },
  { value: "billing", label: "Billing contact" },
  { value: "viewer", label: "Viewer" },
];

function TeamPanel() {
  const tid = useTenantId();
  const can = useCan();
  const tenant = useTenant();
  const members = useQuery({ queryKey: ["members", tid], queryFn: () => api.get<{ membership_id: string; user_id: string; email: string; full_name: string; role: string; status: string; mfa_enabled: boolean; last_login_at: string | null }[]>(`/tenants/${tid}/members`) });
  const invites = useQuery({ queryKey: ["invites", tid], queryFn: () => api.get<{ id: string; email: string; role: string; expires_at: string; accepted_at: string | null; revoked_at: string | null }[]>(`/tenants/${tid}/invitations`) });
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("viewer");
  const invite = useMutation({ mutationFn: () => api.post(`/tenants/${tid}/invitations`, { email, role }), onSuccess: () => { setEmail(""); invites.refetch(); ok("Invitation sent."); }, onError });
  const update = useMutation({ mutationFn: ({ id, body }: { id: string; body: object }) => api.patch(`/tenants/${tid}/members/${id}`, body), onSuccess: () => members.refetch(), onError });
  const manage = can("members:manage");
  return (
    <Stack>
      {manage && (
        <Card>
          <Group align="flex-end" wrap="wrap">
            <TextInput label="Invite by email" value={email} onChange={(e) => setEmail(e.currentTarget.value)} style={{ flex: 1, minWidth: 220 }} />
            <Select label="Role" data={TENANT_ROLES} value={role} onChange={(v) => setRole(v ?? "viewer")} w={180} />
            <Button onClick={() => invite.mutate()} loading={invite.isPending} disabled={!email}>Send invitation</Button>
          </Group>
          <Text size="xs" c="dimmed" mt="xs">{tenant.data?.usage.users} of {String(tenant.data?.entitlements.max_users)} users in your plan.</Text>
        </Card>
      )}
      <Section title="Members">
        <DataTable
          rows={members.data}
          loading={members.isLoading}
          rowKey={(m) => m.membership_id}
          columns={[
            { key: "name", header: "Member", render: (m) => <Box><Text size="sm" fw={600}>{m.full_name || m.email}</Text><Text size="xs" c="dimmed">{m.email}</Text></Box> },
            { key: "role", header: "Role", render: (m) => manage ? <Select size="xs" w={160} data={TENANT_ROLES} value={m.role} onChange={(v) => v && update.mutate({ id: m.membership_id, body: { role: v } })} aria-label={`Role for ${m.email}`} /> : <Text size="sm">{humanize(m.role)}</Text> },
            { key: "mfa", header: "MFA", render: (m) => <Badge color={m.mfa_enabled ? "secure" : "gray"}>{m.mfa_enabled ? "On" : "Off"}</Badge>, visibleFrom: "sm" },
            { key: "login", header: "Last sign-in", render: (m) => <Text size="sm">{fmtRelative(m.last_login_at)}</Text>, visibleFrom: "md" },
            { key: "status", header: "Status", render: (m) => manage ? <Switch checked={m.status === "active"} onChange={(e) => update.mutate({ id: m.membership_id, body: { status: e.currentTarget.checked ? "active" : "disabled" } })} aria-label={`Active: ${m.email}`} /> : <Text size="sm">{humanize(m.status)}</Text> },
          ]}
        />
      </Section>
      <Section title="Invitations">
        <DataTable
          rows={invites.data}
          loading={invites.isLoading}
          rowKey={(i) => i.id}
          empty={<EmptyState title="No invitations" />}
          columns={[
            { key: "email", header: "Email", render: (i) => <Text size="sm">{i.email}</Text> },
            { key: "role", header: "Role", render: (i) => <Text size="sm">{humanize(i.role)}</Text> },
            { key: "state", header: "State", render: (i) => <Badge color={i.accepted_at ? "secure" : i.revoked_at ? "gray" : "info"}>{i.accepted_at ? "Accepted" : i.revoked_at ? "Revoked" : `Expires ${fmtRelative(i.expires_at)}`}</Badge> },
            { key: "x", header: "", render: (i) => manage && !i.accepted_at && !i.revoked_at && <Button size="xs" variant="subtle" color="threat" onClick={async () => { await api.del(`/tenants/${tid}/invitations/${i.id}`); invites.refetch(); }}>Revoke</Button> },
          ]}
        />
      </Section>
    </Stack>
  );
}

function GrantsPanel() {
  const tid = useTenantId();
  const can = useCan();
  const grants = useQuery({ queryKey: ["grants", tid], queryFn: () => api.get<{ id: string; grantee_email: string | null; grantee_name: string | null; permissions: string[]; reason: string; status: string; expires_at: string; approved_at: string | null; created_at: string }[]>(`/tenants/${tid}/grants`) });
  const decide = useMutation({ mutationFn: ({ id, approve }: { id: string; approve: boolean }) => api.post(`/tenants/${tid}/grants/${id}/decision`, { approve, duration_hours: 72 }), onSuccess: () => grants.refetch(), onError });
  const revoke = useMutation({ mutationFn: (id: string) => api.post(`/tenants/${tid}/grants/${id}/revoke`), onSuccess: () => grants.refetch(), onError });
  return (
    <Section title="Trust Data staff access" description="Trust Data personnel cannot see your monitoring data unless you approve a time-limited grant. Every action taken under a grant is audited.">
      <DataTable
        rows={grants.data}
        loading={grants.isLoading}
        rowKey={(g) => g.id}
        empty={<EmptyState title="No access requests" description="Requests from the Trust Data service team will appear here for approval." />}
        columns={[
          { key: "who", header: "Staff member", render: (g) => <Box><Text size="sm" fw={600}>{g.grantee_name}</Text><Text size="xs" c="dimmed">{g.grantee_email}</Text></Box> },
          { key: "reason", header: "Reason", render: (g) => <Text size="sm" lineClamp={2}>{g.reason}</Text> },
          { key: "perms", header: "Access", render: (g) => <Text size="xs">{g.permissions.map(humanize).join(", ")}</Text>, visibleFrom: "md" },
          { key: "status", header: "Status", render: (g) => <Badge color={g.status === "active" ? "secure" : g.status === "requested" ? "amber" : "gray"}>{humanize(g.status)}</Badge> },
          { key: "exp", header: "Expires", render: (g) => <Text size="sm">{fmtDateTime(g.expires_at)}</Text>, visibleFrom: "sm" },
          {
            key: "x",
            header: "",
            render: (g) =>
              can("managed_service:approve") && (g.status === "requested" ? (
                <Group gap={4}>
                  <ConfirmButton size="xs" title="Approve staff access?" message={`Grant ${g.grantee_name} the listed access for up to 72 hours. You can revoke it at any time.`} onConfirm={() => decide.mutateAsync({ id: g.id, approve: true })}>Approve</ConfirmButton>
                  <Button size="xs" variant="subtle" color="gray" onClick={() => decide.mutate({ id: g.id, approve: false })}>Reject</Button>
                </Group>
              ) : g.status === "active" ? <Button size="xs" variant="subtle" color="threat" onClick={() => revoke.mutate(g.id)}>Revoke</Button> : null),
          },
        ]}
      />
    </Section>
  );
}

function TokensPanel() {
  const tid = useTenantId();
  const tenant = useTenant();
  const tokens = useQuery({ queryKey: ["tokens", tid], queryFn: () => api.get<{ id: string; name: string; token_prefix: string; scopes: string[]; expires_at: string; revoked_at: string | null; last_used_at: string | null }[]>(`/tenants/${tid}/api-tokens`) });
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<string[]>(["websites:read", "incidents:read"]);
  const [days, setDays] = useState<number>(90);
  const [created, setCreated] = useState<string | null>(null);
  const create = useMutation({ mutationFn: () => api.post<{ token: string }>(`/tenants/${tid}/api-tokens`, { name, scopes, expires_in_days: days }), onSuccess: (r) => { setCreated(r.token); setName(""); tokens.refetch(); }, onError });
  const allowed = tenant.data?.entitlements.api_access;
  const options = ["tenant:read", "websites:read", "hosting:read", "monitoring:read", "inventory:read", "incidents:read", "notifications:read", "reports:read", "scans:run", "incidents:manage"].filter((s) => tenant.data?.permissions.includes(s));
  return (
    <Stack>
      {!allowed && <Alert color="amber">API access is not included in your current plan.</Alert>}
      {allowed && (
        <Card>
          <Group align="flex-end" wrap="wrap">
            <TextInput label="Token name" value={name} onChange={(e) => setName(e.currentTarget.value)} />
            <MultiSelect label="Scopes" data={options} value={scopes} onChange={setScopes} w={340} />
            <NumberInput label="Expires in (days)" min={1} max={365} value={days} onChange={(v) => setDays(Number(v) || 90)} w={150} />
            <Button onClick={() => create.mutate()} disabled={!name || !scopes.length} loading={create.isPending}>Create token</Button>
          </Group>
          {created && (
            <Alert color="amber" mt="md" title="Copy this token now — it will not be shown again">
              <Code block>{created}</Code>
              <CopyButton value={created}>{({ copied, copy }) => <Button size="xs" mt="xs" variant="light" onClick={copy}>{copied ? "Copied" : "Copy"}</Button>}</CopyButton>
            </Alert>
          )}
        </Card>
      )}
      <Section title="Your tokens">
        <Table>
          <Table.Tbody>
            {tokens.data?.map((t) => (
              <Table.Tr key={t.id}>
                <Table.Td><Text size="sm" fw={600}>{t.name}</Text><Text size="xs" c="dimmed" className="cw-mono">{t.token_prefix}…</Text></Table.Td>
                <Table.Td><Text size="xs">{t.scopes.join(", ")}</Text></Table.Td>
                <Table.Td><Text size="xs">{t.revoked_at ? "Revoked" : `Expires ${fmtDateTime(t.expires_at)}`}</Text></Table.Td>
                <Table.Td>{!t.revoked_at && <Button size="xs" variant="subtle" color="threat" onClick={async () => { await api.del(`/tenants/${tid}/api-tokens/${t.id}`); tokens.refetch(); }}>Revoke</Button>}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {tokens.data?.length === 0 && <EmptyState title="No API tokens" />}
      </Section>
    </Stack>
  );
}

function ActivityPanel() {
  const tid = useTenantId();
  const [page, setPage] = useState(1);
  const [category, setCategory] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["tenant-audit", tid, page, category], queryFn: () => api.get<Page<{ id: string; occurred_at: string; actor_email: string | null; actor_type: string; action: string; outcome: string; ip_address: string | null; target_type: string | null; via_grant_id: string | null; details: Record<string, unknown> }>>(`/tenants/${tid}/audit`, { page, page_size: 30, category: category ?? undefined }) });
  return (
    <Card>
      <Select mb="md" placeholder="Category" clearable w={200} value={category} onChange={setCategory} aria-label="Category"
        data={["auth", "tenant", "member", "website", "hosting", "monitoring", "scan", "incident", "baseline", "billing", "report", "grant", "support"].map((v) => ({ value: v, label: humanize(v) }))} />
      <DataTable
        rows={q.data?.items}
        loading={q.isLoading}
        error={q.error}
        rowKey={(e) => e.id}
        page={page}
        pageSize={30}
        total={q.data?.total}
        onPage={setPage}
        columns={[
          { key: "t", header: "Time", render: (e) => <Text size="sm">{fmtDateTime(e.occurred_at)}</Text> },
          { key: "who", header: "Actor", render: (e) => <Text size="sm">{e.actor_email ?? humanize(e.actor_type)}{e.via_grant_id ? <Badge ml={4} size="xs" color="amber">Trust Data grant</Badge> : null}</Text> },
          { key: "a", header: "Action", render: (e) => <Text size="sm" className="cw-mono">{e.action}</Text> },
          { key: "o", header: "Outcome", render: (e) => <Badge color={e.outcome === "success" ? "secure" : "threat"}>{humanize(e.outcome)}</Badge> },
          { key: "ip", header: "IP", render: (e) => <Text size="xs">{e.ip_address ?? "—"}</Text>, visibleFrom: "md" },
        ]}
      />
    </Card>
  );
}

