import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  Group,
  Modal,
  MultiSelect,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Tabs,
  Text,
  TextInput,
  Textarea,
  Tooltip,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconBell, IconBrandWhatsapp, IconMail, IconPlus, IconSend, IconTrash } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useCan, useTenantId } from "../../api/auth";
import { api, errorMessage } from "../../api/client";
import type { Page, Website } from "../../api/types";
import { fmtDateTime, fmtRelative, humanize } from "../../components/format";
import { ConfirmButton, DataTable, EmptyState, PageHeader, Section } from "../../components/ui";

interface Recipient {
  user_id?: string | null;
  role_key?: string | null;
  email?: string | null;
  whatsapp_number?: string | null;
  whatsapp_consent?: boolean;
}

interface Policy {
  id?: string;
  name: string;
  enabled: boolean;
  min_severity: string;
  categories: string[];
  website_ids: string[];
  group_ids: string[];
  channels: string[];
  escalation_stage: number;
  escalation_delay_minutes: number;
  quiet_hours: { start: string; end: string; timezone: string; bypass_severity: string } | null;
  email_fallback: boolean;
  recipients: Recipient[];
}

const EMPTY: Policy = {
  name: "",
  enabled: true,
  min_severity: "high",
  categories: [],
  website_ids: [],
  group_ids: [],
  channels: ["email"],
  escalation_stage: 0,
  escalation_delay_minutes: 0,
  quiet_hours: null,
  email_fallback: true,
  recipients: [{ role_key: "owner" }],
};

const ROLES = [
  { value: "owner", label: "Organisation owners" },
  { value: "admin", label: "Administrators" },
  { value: "security_lead", label: "Security leads" },
  { value: "analyst", label: "Analysts" },
  { value: "viewer", label: "Viewers" },
];
const CATEGORIES = ["file_integrity", "suspicious_file", "malware", "availability", "tls", "connection", "log_activity", "suspected_compromise"];

export function NotificationsPage() {
  const tid = useTenantId();
  const can = useCan();
  const [params] = useSearchParams();
  const [tab, setTab] = useState<string | null>(params.get("suppress") ? "suppressions" : "policies");
  const policies = useQuery({ queryKey: ["policies", tid], queryFn: () => api.get<(Policy & { id: string })[]>(`/tenants/${tid}/alert-policies`) });
  const channels = useQuery({ queryKey: ["channels", tid], queryFn: () => api.get<Record<string, { configured: boolean }>>(`/tenants/${tid}/notification-channels`) });
  const [editing, setEditing] = useState<Policy | null>(null);
  const [testOpen, test] = useDisclosure(false);

  return (
    <>
      <PageHeader
        title="Notifications and escalation"
        description="Decide who is alerted, through which channel, for which severities and websites. Alerts never include secrets or file contents."
        crumbs={[{ label: "Overview", to: `/app/${tid}/overview` }, { label: "Notifications" }]}
        actions={
          can("notifications:manage") && (
            <>
              <Button variant="default" leftSection={<IconSend size={16} />} onClick={test.open}>Send test</Button>
              <Button leftSection={<IconPlus size={16} />} onClick={() => setEditing({ ...EMPTY })}>New policy</Button>
            </>
          )
        }
      />
      <SimpleGrid cols={{ base: 1, sm: 2 }} mb="md">
        {(["email", "whatsapp"] as const).map((c) => (
          <Card key={c} p="md">
            <Group justify="space-between">
              <Group gap="xs">
                {c === "email" ? <IconMail size={18} /> : <IconBrandWhatsapp size={18} />}
                <Text fw={600}>{c === "email" ? "Email" : "WhatsApp Business"}</Text>
              </Group>
              <Badge color={channels.data?.[c]?.configured ? "secure" : "amber"}>
                {channels.data ? (channels.data[c]?.configured ? "Delivery configured" : "Not configured on platform") : "…"}
              </Badge>
            </Group>
            {channels.data && !channels.data[c]?.configured && (
              <Text size="xs" c="dimmed" mt={4}>Messages are recorded as “unconfigured” rather than reported as sent until the platform operator configures this channel.</Text>
            )}
          </Card>
        ))}
      </SimpleGrid>
      <Tabs value={tab} onChange={setTab}>
        <Tabs.List mb="md">
          <Tabs.Tab value="policies">Alert policies</Tabs.Tab>
          <Tabs.Tab value="history">Delivery history</Tabs.Tab>
          <Tabs.Tab value="suppressions">Suppression rules</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="policies">
          {policies.data?.length === 0 ? (
            <Card>
              <EmptyState icon={IconBell} title="No alert policies" description="Without a policy, incidents are visible in the console but nobody is notified." action={can("notifications:manage") && <Button onClick={() => setEditing({ ...EMPTY, name: "Critical and high incidents" })}>Create a policy</Button>} />
            </Card>
          ) : (
            <Stack>
              {policies.data?.map((p) => (
                <Card key={p.id}>
                  <Group justify="space-between" wrap="wrap">
                    <Stack gap={2}>
                      <Group gap="xs">
                        <Text fw={650}>{p.name}</Text>
                        {!p.enabled && <Badge color="gray">Disabled</Badge>}
                        {p.escalation_stage > 0 && <Badge color="amber">Escalation stage {p.escalation_stage} · after {p.escalation_delay_minutes} min if unacknowledged</Badge>}
                      </Group>
                      <Text size="sm" c="dimmed">
                        {humanize(p.min_severity)} and above · {p.categories.length ? p.categories.map(humanize).join(", ") : "all categories"} ·{" "}
                        {p.website_ids.length ? `${p.website_ids.length} website(s)` : "all websites"} · via {p.channels.map(humanize).join(" and ")}
                        {p.quiet_hours ? ` · quiet ${p.quiet_hours.start}–${p.quiet_hours.end}` : ""}
                      </Text>
                      <Text size="xs" c="dimmed">
                        Recipients: {p.recipients.map((r) => r.role_key ? ROLES.find((x) => x.value === r.role_key)?.label : r.email ?? r.whatsapp_number ?? "member").join(", ")}
                      </Text>
                    </Stack>
                    {can("notifications:manage") && (
                      <Group gap="xs">
                        <Button size="xs" variant="default" onClick={() => setEditing(p)}>Edit</Button>
                        <ConfirmButton size="xs" variant="subtle" danger title="Delete policy?" message="Recipients will no longer be alerted by this policy." onConfirm={async () => { await api.del(`/tenants/${tid}/alert-policies/${p.id}`); policies.refetch(); }}>
                          <IconTrash size={14} />
                        </ConfirmButton>
                      </Group>
                    )}
                  </Group>
                </Card>
              ))}
            </Stack>
          )}
        </Tabs.Panel>
        <Tabs.Panel value="history"><HistoryTable /></Tabs.Panel>
        <Tabs.Panel value="suppressions"><Suppressions /></Tabs.Panel>
      </Tabs>
      {editing && <PolicyModal policy={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); policies.refetch(); }} />}
      <TestModal opened={testOpen} onClose={test.close} />
    </>
  );
}

function PolicyModal({ policy, onClose, onSaved }: { policy: Policy; onClose: () => void; onSaved: () => void }) {
  const tid = useTenantId();
  const [p, setP] = useState<Policy>(policy);
  const [error, setError] = useState<string | null>(null);
  const sites = useQuery({ queryKey: ["website-options", tid], queryFn: () => api.get<Page<Website>>(`/tenants/${tid}/websites`, { page_size: 200 }) });
  const save = useMutation({
    mutationFn: () => (p.id ? api.put(`/tenants/${tid}/alert-policies/${p.id}`, p) : api.post(`/tenants/${tid}/alert-policies`, p)),
    onSuccess: onSaved,
    onError: (e) => setError(errorMessage(e)),
  });
  const setR = (i: number, r: Recipient) => setP({ ...p, recipients: p.recipients.map((x, j) => (j === i ? r : x)) });
  return (
    <Modal opened onClose={onClose} title={p.id ? "Edit alert policy" : "New alert policy"} size="lg">
      <Stack>
        <TextInput label="Policy name" required value={p.name} onChange={(e) => setP({ ...p, name: e.currentTarget.value })} />
        <SimpleGrid cols={{ base: 1, sm: 2 }}>
          <Select label="Minimum severity" data={["critical", "high", "medium", "low", "informational"].map((v) => ({ value: v, label: humanize(v) }))} value={p.min_severity} onChange={(v) => setP({ ...p, min_severity: v ?? "high" })} />
          <MultiSelect label="Channels" data={[{ value: "email", label: "Email" }, { value: "whatsapp", label: "WhatsApp" }]} value={p.channels} onChange={(v) => setP({ ...p, channels: v })} />
        </SimpleGrid>
        <MultiSelect label="Categories" description="Leave empty for all categories." data={CATEGORIES.map((c) => ({ value: c, label: humanize(c) }))} value={p.categories} onChange={(v) => setP({ ...p, categories: v })} />
        <MultiSelect label="Websites" description="Leave empty for all websites." data={(sites.data?.items ?? []).map((w) => ({ value: w.id, label: w.name }))} value={p.website_ids} onChange={(v) => setP({ ...p, website_ids: v })} searchable />
        <SimpleGrid cols={{ base: 1, sm: 2 }}>
          <NumberInput label="Escalation stage" description="0 = immediate. Higher stages only fire if still unacknowledged." min={0} max={5} value={p.escalation_stage} onChange={(v) => setP({ ...p, escalation_stage: Number(v) || 0 })} />
          <NumberInput label="Escalation delay (minutes)" min={0} value={p.escalation_delay_minutes} onChange={(v) => setP({ ...p, escalation_delay_minutes: Number(v) || 0 })} disabled={p.escalation_stage === 0} />
        </SimpleGrid>
        <Switch label="Quiet hours (non-critical alerts are deferred)" checked={!!p.quiet_hours} onChange={(e) => setP({ ...p, quiet_hours: e.currentTarget.checked ? { start: "22:00", end: "07:00", timezone: "Africa/Lagos", bypass_severity: "critical" } : null })} />
        {p.quiet_hours && (
          <Group grow>
            <TextInput label="From" value={p.quiet_hours.start} onChange={(e) => setP({ ...p, quiet_hours: { ...p.quiet_hours!, start: e.currentTarget.value } })} />
            <TextInput label="To" value={p.quiet_hours.end} onChange={(e) => setP({ ...p, quiet_hours: { ...p.quiet_hours!, end: e.currentTarget.value } })} />
          </Group>
        )}
        <Checkbox label="Fall back to email when WhatsApp delivery fails" checked={p.email_fallback} onChange={(e) => setP({ ...p, email_fallback: e.currentTarget.checked })} />
        <Text fw={600} size="sm">Recipients</Text>
        {p.recipients.map((r, i) => {
          const mode = r.role_key !== undefined && r.role_key !== null ? "role" : r.whatsapp_number !== undefined && r.whatsapp_number !== null ? "whatsapp" : "email";
          return (
            <Group key={i} align="flex-end" wrap="nowrap" gap="xs">
              <Select w={130} aria-label="Recipient type" data={[{ value: "role", label: "Role" }, { value: "email", label: "Email" }, { value: "whatsapp", label: "WhatsApp" }]} value={mode}
                onChange={(v) => setR(i, v === "role" ? { role_key: "owner" } : v === "whatsapp" ? { whatsapp_number: "+234", whatsapp_consent: false } : { email: "" })} />
              {mode === "role" && <Select style={{ flex: 1 }} aria-label="Role" data={ROLES} value={r.role_key} onChange={(v) => setR(i, { role_key: v })} />}
              {mode === "email" && <TextInput style={{ flex: 1 }} aria-label="Email" placeholder="security@example.com" value={r.email ?? ""} onChange={(e) => setR(i, { email: e.currentTarget.value })} />}
              {mode === "whatsapp" && (
                <>
                  <TextInput style={{ flex: 1 }} aria-label="WhatsApp number" placeholder="+2348012345678" value={r.whatsapp_number ?? ""} onChange={(e) => setR(i, { ...r, whatsapp_number: e.currentTarget.value })} />
                  <Tooltip label="WhatsApp policy requires the recipient's consent to receive messages.">
                    <Checkbox label="Consent given" checked={!!r.whatsapp_consent} onChange={(e) => setR(i, { ...r, whatsapp_consent: e.currentTarget.checked })} />
                  </Tooltip>
                </>
              )}
              <Button variant="subtle" color="gray" onClick={() => setP({ ...p, recipients: p.recipients.filter((_, j) => j !== i) })} aria-label="Remove recipient"><IconTrash size={14} /></Button>
            </Group>
          );
        })}
        <Button variant="light" size="xs" w="fit-content" onClick={() => setP({ ...p, recipients: [...p.recipients, { email: "" }] })}>Add recipient</Button>
        <Switch label="Policy enabled" checked={p.enabled} onChange={(e) => setP({ ...p, enabled: e.currentTarget.checked })} />
        {error && <Alert color="threat" role="alert">{error}</Alert>}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>Cancel</Button>
          <Button onClick={() => save.mutate()} loading={save.isPending} disabled={!p.name || !p.channels.length}>Save policy</Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function TestModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const tid = useTenantId();
  const [channel, setChannel] = useState("email");
  const [recipient, setRecipient] = useState("");
  const send = useMutation({
    mutationFn: () => api.post(`/tenants/${tid}/notifications/test`, { channel, recipient: recipient || null }),
    onSuccess: () => { notifications.show({ color: "cyber", title: "Test queued", message: "Check Delivery history for the outcome." }); onClose(); },
    onError: (e) => notifications.show({ color: "threat", title: "Not sent", message: errorMessage(e) }),
  });
  return (
    <Modal opened={opened} onClose={onClose} title="Send a test notification">
      <Stack>
        <Select label="Channel" data={[{ value: "email", label: "Email" }, { value: "whatsapp", label: "WhatsApp" }]} value={channel} onChange={(v) => setChannel(v ?? "email")} />
        <TextInput label="Recipient" description="Leave empty to send to yourself. Only you or configured recipients are allowed." value={recipient} onChange={(e) => setRecipient(e.currentTarget.value)} />
        <Button onClick={() => send.mutate()} loading={send.isPending}>Send test</Button>
      </Stack>
    </Modal>
  );
}

function HistoryTable() {
  const tid = useTenantId();
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState<string | null>(null);
  const q = useQuery({
    queryKey: ["notif-history", tid, page, status],
    queryFn: () => api.get<Page<{ id: string; channel: string; category: string; recipient: string; subject: string; status: string; attempts: number; max_attempts: number; last_error: string | null; sent_at: string | null; created_at: string; next_attempt_at: string; is_fallback: boolean }>>(`/tenants/${tid}/notifications`, { page, page_size: 25, status: status ?? undefined }),
  });
  return (
    <Card>
      <Select mb="md" placeholder="Status" clearable w={180} value={status} onChange={setStatus} aria-label="Status"
        data={["pending", "sent", "failed", "unconfigured", "suppressed"].map((v) => ({ value: v, label: humanize(v) }))} />
      <DataTable
        rows={q.data?.items}
        loading={q.isLoading}
        error={q.error}
        rowKey={(n) => n.id}
        page={page}
        pageSize={25}
        total={q.data?.total}
        onPage={setPage}
        empty={<EmptyState title="No notifications yet" />}
        columns={[
          { key: "created", header: "Created", render: (n) => <Text size="sm">{fmtDateTime(n.created_at)}</Text> },
          { key: "channel", header: "Channel", render: (n) => <Group gap={4}>{n.channel === "email" ? <IconMail size={14} /> : <IconBrandWhatsapp size={14} />}<Text size="sm">{humanize(n.channel)}</Text>{n.is_fallback && <Badge size="xs">fallback</Badge>}</Group> },
          { key: "recipient", header: "Recipient", render: (n) => <Text size="sm">{n.recipient}</Text> },
          { key: "subject", header: "Subject", render: (n) => <Text size="sm" lineClamp={1}>{n.subject}</Text>, visibleFrom: "lg" },
          { key: "status", header: "Status", render: (n) => <Tooltip label={n.last_error ?? (n.sent_at ? `Sent ${fmtDateTime(n.sent_at)}` : `Next attempt ${fmtRelative(n.next_attempt_at)}`)}><Badge color={n.status === "sent" ? "secure" : n.status === "pending" ? "info" : n.status === "failed" ? "threat" : "amber"}>{humanize(n.status)}</Badge></Tooltip> },
          { key: "attempts", header: "Attempts", render: (n) => <Text size="sm">{n.attempts}/{n.max_attempts}</Text>, visibleFrom: "md" },
        ]}
      />
    </Card>
  );
}

function Suppressions() {
  const tid = useTenantId();
  const can = useCan();
  const [params] = useSearchParams();
  const rules = useQuery({ queryKey: ["suppressions", tid], queryFn: () => api.get<{ id: string; rule_key: string; website_id: string | null; path_glob: string | null; reason: string; expires_at: string | null; is_active: boolean; created_at: string }[]>(`/tenants/${tid}/suppressions`) });
  const [form, setForm] = useState({ rule_key: params.get("rule") ?? "", path_glob: "", reason: "" });
  useEffect(() => { if (params.get("rule")) setForm((f) => ({ ...f, rule_key: params.get("rule") ?? "" })); }, [params]);
  const create = useMutation({
    mutationFn: () => api.post(`/tenants/${tid}/suppressions`, { ...form, path_glob: form.path_glob || null, from_incident_id: params.get("suppress") || null }),
    onSuccess: () => { setForm({ rule_key: "", path_glob: "", reason: "" }); rules.refetch(); },
    onError: (e) => notifications.show({ color: "threat", title: "Not created", message: errorMessage(e) }),
  });
  return (
    <SimpleGrid cols={{ base: 1, md: 2 }}>
      <Section title="Active rules" description="Documented exceptions that stop repeat incidents for known-benign detections.">
        {rules.data?.filter((r) => r.is_active).length === 0 && <EmptyState title="No suppression rules" />}
        <Stack gap="sm">
          {rules.data?.filter((r) => r.is_active).map((r) => (
            <Card key={r.id} p="sm" shadow="none">
              <Group justify="space-between" wrap="nowrap">
                <div>
                  <Text size="sm" fw={600}>{r.rule_key}{r.path_glob ? ` · ${r.path_glob}` : ""}</Text>
                  <Text size="xs" c="dimmed">{r.reason}</Text>
                  <Text size="xs" c="dimmed">Created {fmtDateTime(r.created_at)}{r.expires_at ? ` · expires ${fmtDateTime(r.expires_at)}` : ""}</Text>
                </div>
                {can("incidents:manage") && <Button size="xs" variant="subtle" color="threat" onClick={async () => { await api.del(`/tenants/${tid}/suppressions/${r.id}`); rules.refetch(); }}>Disable</Button>}
              </Group>
            </Card>
          ))}
        </Stack>
      </Section>
      {can("incidents:manage") && (
        <Section title="New suppression rule">
          <Stack>
            <TextInput label="Detection rule" description="e.g. script_changed, file_changes, tls:expiring" value={form.rule_key} onChange={(e) => setForm({ ...form, rule_key: e.currentTarget.value })} />
            <TextInput label="Path pattern (optional)" placeholder="wp-content/cache/**" value={form.path_glob} onChange={(e) => setForm({ ...form, path_glob: e.currentTarget.value })} />
            <Textarea label="Justification" required description="Recorded in the audit trail." value={form.reason} onChange={(e) => setForm({ ...form, reason: e.currentTarget.value })} />
            <Button w="fit-content" onClick={() => create.mutate()} loading={create.isPending} disabled={!form.rule_key || form.reason.length < 5}>Create rule</Button>
          </Stack>
        </Section>
      )}
    </SimpleGrid>
  );
}
