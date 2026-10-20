import {
  Alert,
  Anchor,
  Badge,
  Box,
  Button,
  Card,
  Group,
  Modal,
  Progress,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Text,
  TextInput,
  Textarea,
  Title,
} from "@mantine/core";
import { DatePickerInput } from "@mantine/dates";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconAlertTriangle, IconDownload, IconFileText, IconLifebuoy, IconPlus } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useCan, useTenantId } from "../../api/auth";
import { api, downloadUrl, errorMessage } from "../../api/client";
import type { Page, Website } from "../../api/types";
import { fmtBytes, fmtDate, fmtDateTime, fmtMoney, humanize, minCharsHint, shortHash } from "../../components/format";
import { SubscriptionBadge } from "../../components/status";
import { ConfirmButton, DataTable, EmptyState, ErrorState, KeyValue, LoadingBlock, PageHeader, Section } from "../../components/ui";

// ---------------------------------------------------------------- billing

interface Plan {
  key: string;
  name: string;
  description: string;
  currency: string;
  price_monthly_minor: number | null;
  price_annual_minor: number | null;
  contact_sales: boolean;
  entitlements: Record<string, number | boolean | string>;
}

interface BillingView {
  payments_configured: boolean;
  subscription: {
    plan_key: string | null;
    plan_name: string | null;
    status: string;
    interval: string;
    current_period_end: string | null;
    trial_ends_at: string | null;
    grace_until: string | null;
    cancel_at_period_end: boolean;
    payment_method: string | null;
  } | null;
  in_service: boolean;
  entitlements: Record<string, number | boolean | string>;
  usage: Record<string, number>;
  payments: { id: string; reference: string; plan: string; interval: string; amount_minor: number; currency: string; status: string; purpose: string; paid_at: string | null; created_at: string }[];
}

export function BillingPage() {
  const tid = useTenantId();
  const can = useCan();
  const [params, setParams] = useSearchParams();
  const [interval, setInterval] = useState("monthly");
  const view = useQuery({ queryKey: ["billing", tid], queryFn: () => api.get<BillingView>(`/tenants/${tid}/billing`) });
  const plans = useQuery({ queryKey: ["public-plans"], queryFn: () => api.get<Plan[]>("/plans") });
  const checkout = useMutation({
    mutationFn: (plan_key: string) => api.post<{ authorization_url: string }>(`/tenants/${tid}/billing/checkout`, { plan_key, interval }),
    onSuccess: (r) => { window.location.href = r.authorization_url; },
    onError: (e) => notifications.show({ color: "threat", title: "Checkout unavailable", message: errorMessage(e) }),
  });
  const reference = params.get("reference");
  const verify = useMutation({
    mutationFn: (ref: string) => api.post<{ status: string }>(`/tenants/${tid}/billing/verify`, { reference: ref }),
    onSuccess: (r) => {
      notifications.show({ color: r.status === "success" ? "secure" : "amber", title: "Payment status", message: r.status === "success" ? "Payment verified. Your subscription is active." : `Payment ${r.status}. Your plan has not changed.` });
      setParams({}, { replace: true });
      view.refetch();
    },
    onError: (e) => notifications.show({ color: "amber", title: "Verification pending", message: errorMessage(e) }),
  });
  useEffect(() => { if (reference && !verify.isPending && !verify.isSuccess) verify.mutate(reference); }, [reference]); // eslint-disable-line react-hooks/exhaustive-deps
  const cancel = useMutation({ mutationFn: () => api.post(`/tenants/${tid}/billing/cancel`), onSuccess: () => view.refetch() });

  if (view.error) return <ErrorState error={view.error} onRetry={() => view.refetch()} />;
  const v = view.data;
  const sub = v?.subscription;
  return (
    <>
      <PageHeader title="Subscription and billing" description="Payments are processed by Paystack hosted checkout. Card details never reach CyberWatch." crumbs={[{ label: "Overview", to: `/app/${tid}/overview` }, { label: "Billing" }]} />
      {reference && verify.isPending && <Alert mb="md" color="info">Verifying your payment with Paystack… Entitlements change only after server-side verification.</Alert>}
      {v && !v.in_service && <Alert mb="md" color="threat" icon={<IconAlertTriangle />} title="Service restricted">Your subscription is not active. Existing data is retained; new monitoring capacity and scheduled checks are paused until you subscribe.</Alert>}
      {sub?.status === "grace_period" && <Alert mb="md" color="amber" icon={<IconAlertTriangle />} title="Payment overdue">Renewal failed. Service continues until {fmtDate(sub.grace_until)}. Pay now to avoid interruption.</Alert>}
      <SimpleGrid cols={{ base: 1, md: 2 }} mb="md">
        <Section title="Current plan">
          {!v ? <LoadingBlock /> : (
            <Stack>
              <Group justify="space-between"><Title order={2}>{sub?.plan_name ?? "No plan"}</Title><SubscriptionBadge status={sub?.status} /></Group>
              <KeyValue items={[
                ["Billing interval", humanize(sub?.interval)],
                [sub?.status === "trialing" ? "Trial ends" : "Current period ends", fmtDate(sub?.status === "trialing" ? sub?.trial_ends_at : sub?.current_period_end)],
                ["Renewal", sub?.cancel_at_period_end ? "Ends at period end" : sub?.status === "active" ? "Automatic" : "—"],
                ["Payment method", sub?.payment_method ?? "None saved"],
              ]} />
              {can("billing:manage") && sub?.status === "active" && !sub.cancel_at_period_end && (
                <ConfirmButton variant="subtle" color="threat" w="fit-content" title="Cancel subscription?" message="Your plan stays active until the end of the current period, then monitoring is restricted. Data is retained." confirmLabel="Cancel at period end" onConfirm={() => cancel.mutateAsync()}>Cancel subscription</ConfirmButton>
              )}
            </Stack>
          )}
        </Section>
        <Section title="Usage against plan limits">
          {v && (
            <Stack gap="sm">
              {[["websites", "max_websites"], ["hosting_accounts", "max_hosting_accounts"], ["users", "max_users"]].map(([u, l]) => {
                const used = v.usage[u] ?? 0;
                const lim = Number(v.entitlements[l] ?? 0);
                const pct = lim ? Math.min(100, (used / lim) * 100) : 100;
                return (
                  <Box key={u}>
                    <Group justify="space-between"><Text size="sm">{humanize(u)}</Text><Text size="sm" fw={600}>{used} / {lim}</Text></Group>
                    <Progress value={pct} color={pct >= 90 ? "amber" : "cyber"} aria-label={`${humanize(u)} usage`} />
                  </Box>
                );
              })}
              <Text size="xs" c="dimmed">Fastest file-scan interval: {String(v.entitlements.min_file_scan_interval_minutes)} min · history retained {String(v.entitlements.retention_days)} days · reports {v.entitlements.reports ? "included" : "not included"} · WhatsApp {v.entitlements.whatsapp_notifications ? "included" : "not included"}</Text>
            </Stack>
          )}
        </Section>
      </SimpleGrid>

      <Section title="Change plan" actions={<SegmentedControl value={interval} onChange={setInterval} data={[{ value: "monthly", label: "Monthly" }, { value: "annual", label: "Annual" }]} aria-label="Billing interval" />}>
        {v && !v.payments_configured && <Alert color="amber" mb="md">Online payments are not configured for this platform yet. Contact Trust Data to change plans.</Alert>}
        <SimpleGrid cols={{ base: 1, sm: 2, lg: 5 }}>
          {plans.data?.map((p) => {
            const price = interval === "monthly" ? p.price_monthly_minor : p.price_annual_minor;
            const current = sub?.plan_key === p.key && sub?.status === "active";
            return (
              <Card key={p.key} shadow="none" style={{ borderColor: current ? "var(--cw-blue)" : undefined }}>
                <Text fw={650}>{p.name}</Text>
                <Text className="cw-metric" fz={20} mt={4}>{p.contact_sales ? "Contact us" : fmtMoney(price, p.currency)}</Text>
                {!p.contact_sales && <Text size="xs" c="dimmed">per {interval === "monthly" ? "month" : "year"}</Text>}
                <Text size="xs" c="dimmed" mt="xs">{String(p.entitlements.max_websites)} websites · {String(p.entitlements.max_users)} users</Text>
                {current ? <Badge mt="md">Current plan</Badge> : p.contact_sales ? (
                  <Button mt="md" size="xs" variant="light" component="a" href="mailto:team@trustdata.ng">Contact sales</Button>
                ) : can("billing:manage") ? (
                  <Button mt="md" size="xs" onClick={() => checkout.mutate(p.key)} loading={checkout.isPending && checkout.variables === p.key} disabled={!v?.payments_configured || !price}>Choose {p.name}</Button>
                ) : null}
              </Card>
            );
          })}
        </SimpleGrid>
      </Section>

      <Box mt="md">
        <Section title="Payment history" description="Only payments verified with Paystack are marked successful.">
          <DataTable
            rows={v?.payments}
            loading={!v}
            rowKey={(p) => p.id}
            empty={<EmptyState title="No payments yet" />}
            columns={[
              { key: "date", header: "Date", render: (p) => <Text size="sm">{fmtDateTime(p.paid_at ?? p.created_at)}</Text> },
              { key: "plan", header: "Plan", render: (p) => <Text size="sm">{p.plan} · {humanize(p.interval)}</Text> },
              { key: "amount", header: "Amount", render: (p) => <Text size="sm">{fmtMoney(p.amount_minor, p.currency)}</Text> },
              { key: "status", header: "Status", render: (p) => <Badge color={p.status === "success" ? "secure" : p.status === "initialized" ? "gray" : "threat"}>{humanize(p.status)}</Badge> },
              { key: "ref", header: "Reference", render: (p) => <Text size="xs" className="cw-mono">{p.reference}</Text>, visibleFrom: "md" },
              { key: "receipt", header: "", render: (p) => p.status === "success" ? <ReceiptLink paymentId={p.id} /> : null },
            ]}
          />
        </Section>
      </Box>
    </>
  );
}

function ReceiptLink({ paymentId }: { paymentId: string }) {
  const tid = useTenantId();
  const [opened, { open, close }] = useDisclosure(false);
  const r = useQuery({ queryKey: ["receipt", paymentId], queryFn: () => api.get<Record<string, string | number>>(`/tenants/${tid}/billing/payments/${paymentId}/receipt`), enabled: opened });
  return (
    <>
      <Anchor size="sm" component="button" onClick={open}>Receipt</Anchor>
      <Modal opened={opened} onClose={close} title="Payment receipt">
        {r.data ? (
          <Stack>
            <KeyValue items={[
              ["Receipt", String(r.data.receipt_number)], ["Organisation", String(r.data.organisation)], ["Plan", `${r.data.plan} (${r.data.interval})`],
              ["Amount", fmtMoney(Number(r.data.amount_minor), String(r.data.currency))], ["Paid", fmtDateTime(String(r.data.paid_at))],
              ["Verified", fmtDateTime(String(r.data.verified_at))], ["Reference", String(r.data.reference)], ["Issued by", String(r.data.issuer)],
            ]} />
            <Button variant="default" onClick={() => window.print()}>Print</Button>
          </Stack>
        ) : <LoadingBlock />}
      </Modal>
    </>
  );
}

// ---------------------------------------------------------------- reports

export function ReportsPage() {
  const tid = useTenantId();
  const can = useCan();
  const [type, setType] = useState<string | null>("security_summary");
  const [format, setFormat] = useState("pdf");
  const [website, setWebsite] = useState<string | null>(null);
  const [range, setRange] = useState<[Date | null, Date | null]>([new Date(Date.now() - 30 * 86400_000), new Date()]);
  const [page, setPage] = useState(1);
  const types = useQuery({ queryKey: ["report-types", tid], queryFn: () => api.get<Record<string, string>>(`/tenants/${tid}/report-types`) });
  const sites = useQuery({ queryKey: ["website-options", tid], queryFn: () => api.get<Page<Website>>(`/tenants/${tid}/websites`, { page_size: 200 }) });
  const list = useQuery({ queryKey: ["reports", tid, page], queryFn: () => api.get<Page<{ id: string; title: string; format: string; status: string; period_start: string; period_end: string; generated_at: string | null; content_sha256: string | null; size_bytes: number | null; error: string | null }>>(`/tenants/${tid}/reports`, { page, page_size: 20 }) });
  const gen = useMutation({
    mutationFn: () => api.post<{ status: string; error: string | null }>(`/tenants/${tid}/reports`, { report_type: type, format, website_id: website, period_start: range[0]?.toISOString(), period_end: range[1]?.toISOString() }),
    onSuccess: (r) => { notifications.show({ color: r.status === "ready" ? "secure" : "threat", title: r.status === "ready" ? "Report ready" : "Report failed", message: r.error ?? "Download it from the history below." }); list.refetch(); },
    onError: (e) => notifications.show({ color: "threat", title: "Not generated", message: errorMessage(e) }),
  });
  return (
    <>
      <PageHeader title="Reports and compliance evidence" description="Reports are generated from stored monitoring results, timestamped and hashed. They include the limits of what monitoring can show." crumbs={[{ label: "Overview", to: `/app/${tid}/overview` }, { label: "Reports" }]} />
      {can("reports:generate") && (
        <Card mb="md">
          <SimpleGrid cols={{ base: 1, sm: 2, lg: 5 }} style={{ alignItems: "end" }}>
            <Select label="Report" data={Object.entries(types.data ?? {}).map(([value, label]) => ({ value, label }))} value={type} onChange={setType} />
            <Select label="Website" placeholder="All websites" clearable data={(sites.data?.items ?? []).map((w) => ({ value: w.id, label: w.name }))} value={website} onChange={setWebsite} />
            <DatePickerInput type="range" label="Period" value={range} onChange={setRange} maxDate={new Date()} />
            <SegmentedControl value={format} onChange={setFormat} data={[{ value: "pdf", label: "PDF" }, { value: "csv", label: "CSV" }]} aria-label="Format" />
            <Button leftSection={<IconFileText size={16} />} onClick={() => gen.mutate()} loading={gen.isPending}>Generate</Button>
          </SimpleGrid>
        </Card>
      )}
      <Card>
        <DataTable
          rows={list.data?.items}
          loading={list.isLoading}
          error={list.error}
          rowKey={(r) => r.id}
          page={page}
          pageSize={20}
          total={list.data?.total}
          onPage={setPage}
          empty={<EmptyState title="No reports generated yet" />}
          columns={[
            { key: "title", header: "Report", render: (r) => <Text size="sm" fw={600}>{r.title}</Text> },
            { key: "period", header: "Period", render: (r) => <Text size="sm">{fmtDate(r.period_start)} – {fmtDate(r.period_end)}</Text> },
            { key: "generated", header: "Generated", render: (r) => <Text size="sm">{fmtDateTime(r.generated_at)}</Text>, visibleFrom: "md" },
            { key: "hash", header: "SHA-256", render: (r) => <Text size="xs" className="cw-mono" title={r.content_sha256 ?? ""}>{shortHash(r.content_sha256)}</Text>, visibleFrom: "lg" },
            { key: "size", header: "Size", render: (r) => <Text size="sm">{fmtBytes(r.size_bytes)}</Text>, visibleFrom: "lg" },
            { key: "dl", header: "", render: (r) => r.status === "ready" ? <Button size="xs" variant="light" component="a" href={downloadUrl(`/tenants/${tid}/reports/${r.id}/download`)} leftSection={<IconDownload size={14} />}>{r.format.toUpperCase()}</Button> : <Badge color="threat">{humanize(r.status)}</Badge> },
          ]}
        />
      </Card>
    </>
  );
}

// ---------------------------------------------------------------- support

interface Ticket {
  id: string;
  reference: string;
  subject: string;
  category: string;
  priority: string;
  status: string;
  created_at: string;
  updated_at: string;
  assigned_team_member?: string | null;
  remediation_approved_at: string | null;
  remediation_scope: string | null;
  messages?: { body: string; author: string; is_staff: boolean; created_at: string }[];
}

export function SupportPage() {
  const tid = useTenantId();
  const can = useCan();
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [opened, { open, close }] = useDisclosure(false);
  const [form, setForm] = useState({ subject: "", category: "general", priority: "normal", body: "" });
  const list = useQuery({ queryKey: ["tickets", tid, page], queryFn: () => api.get<Page<Ticket>>(`/tenants/${tid}/tickets`, { page, page_size: 20 }) });
  const create = useMutation({
    mutationFn: () => api.post<Ticket>(`/tenants/${tid}/tickets`, form),
    onSuccess: (t) => { close(); navigate(`/app/${tid}/support/${t.id}`); },
    onError: (e) => notifications.show({ color: "threat", title: "Not created", message: errorMessage(e) }),
  });
  return (
    <>
      <PageHeader title="Support and managed services" description="Request help or an investigation from the Trust Data service team. All staff access to your data is explicitly granted and audited." crumbs={[{ label: "Overview", to: `/app/${tid}/overview` }, { label: "Support" }]}
        actions={can("support:manage") && <Button leftSection={<IconPlus size={16} />} onClick={open}>New request</Button>} />
      <Card>
        <DataTable<Ticket>
          rows={list.data?.items}
          loading={list.isLoading}
          error={list.error}
          rowKey={(t) => t.id}
          onRowClick={(t) => navigate(`/app/${tid}/support/${t.id}`)}
          page={page}
          pageSize={20}
          total={list.data?.total}
          onPage={setPage}
          empty={<EmptyState icon={IconLifebuoy} title="No support requests" description="Raise a request for help, investigation or remediation." />}
          columns={[
            { key: "ref", header: "Request", render: (t) => <Box><Text size="sm" fw={600}>{t.subject}</Text><Text size="xs" c="dimmed">{t.reference} · {humanize(t.category)}</Text></Box> },
            { key: "priority", header: "Priority", render: (t) => <Badge variant="outline" color={t.priority === "urgent" ? "threat" : "gray"}>{humanize(t.priority)}</Badge> },
            { key: "status", header: "Status", render: (t) => <Badge color={t.status === "resolved" || t.status === "closed" ? "secure" : "cyber"}>{humanize(t.status)}</Badge> },
            { key: "team", header: "Service team", render: (t) => <Text size="sm">{t.assigned_team_member ?? "Unassigned"}</Text>, visibleFrom: "md" },
            { key: "updated", header: "Updated", render: (t) => <Text size="sm">{fmtDateTime(t.updated_at)}</Text>, visibleFrom: "sm" },
          ]}
        />
      </Card>
      <Modal opened={opened} onClose={close} title="New support request" size="lg">
        <Stack>
          <TextInput label="Subject" required value={form.subject} onChange={(e) => setForm({ ...form, subject: e.currentTarget.value })} />
          <Group grow>
            <Select label="Type" data={["general", "investigation", "remediation_request", "billing", "technical"].map((v) => ({ value: v, label: humanize(v) }))} value={form.category} onChange={(v) => setForm({ ...form, category: v ?? "general" })} />
            <Select label="Priority" data={["low", "normal", "high", "urgent"].map((v) => ({ value: v, label: humanize(v) }))} value={form.priority} onChange={(v) => setForm({ ...form, priority: v ?? "normal" })} />
          </Group>
          <Textarea label="Details" required autosize minRows={4} description="Do not include passwords or other secrets." value={form.body} onChange={(e) => setForm({ ...form, body: e.currentTarget.value })} />
          <Button onClick={() => create.mutate()} loading={create.isPending} disabled={form.subject.length < 3 || !form.body}>Submit</Button>
        </Stack>
      </Modal>
    </>
  );
}

export function TicketPage() {
  const tid = useTenantId();
  const { ticketId } = useParams();
  const can = useCan();
  const [reply, setReply] = useState("");
  const [scope, setScope] = useState("");
  const t = useQuery({ queryKey: ["ticket", tid, ticketId], queryFn: () => api.get<Ticket>(`/tenants/${tid}/tickets/${ticketId}`) });
  const send = useMutation({ mutationFn: () => api.post(`/tenants/${tid}/tickets/${ticketId}/messages`, { body: reply }), onSuccess: () => { setReply(""); t.refetch(); } });
  const approve = useMutation({
    mutationFn: () => api.post(`/tenants/${tid}/tickets/${ticketId}/remediation-approval`, { scope, confirm: true }),
    onSuccess: () => t.refetch(),
    onError: (e) => notifications.show({ color: "threat", title: "Not recorded", message: errorMessage(e) }),
  });
  if (t.error) return <ErrorState error={t.error} />;
  if (!t.data) return <LoadingBlock />;
  const d = t.data;
  return (
    <>
      <PageHeader title={d.subject} description={`${d.reference} · ${humanize(d.category)} · ${humanize(d.status)}`} crumbs={[{ label: "Support", to: `/app/${tid}/support` }, { label: d.reference }]} />
      <SimpleGrid cols={{ base: 1, md: 3 }} spacing="md">
        <Box style={{ gridColumn: "span 2" }}>
          <Section title="Conversation">
            <Stack>
              {d.messages?.map((m, i) => (
                <Card key={i} p="sm" shadow="none" style={{ background: m.is_staff ? "var(--cw-sidebar-active)" : "var(--cw-surface-alt)" }}>
                  <Group justify="space-between"><Text size="sm" fw={600}>{m.author}{m.is_staff ? " · Trust Data" : ""}</Text><Text size="xs" c="dimmed">{fmtDateTime(m.created_at)}</Text></Group>
                  <Text size="sm" mt={4} style={{ whiteSpace: "pre-wrap" }}>{m.body}</Text>
                </Card>
              ))}
              {can("support:manage") && (
                <>
                  <Textarea placeholder="Write a reply…" autosize minRows={3} value={reply} onChange={(e) => setReply(e.currentTarget.value)} aria-label="Reply" />
                  <Button w="fit-content" onClick={() => send.mutate()} loading={send.isPending} disabled={!reply.trim()}>Send</Button>
                </>
              )}
            </Stack>
          </Section>
        </Box>
        <Stack>
          <Section title="Service team"><Text size="sm">{d.assigned_team_member ?? "A Trust Data team member will be assigned."}</Text></Section>
          <Section title="Remediation approval" description="Trust Data staff may only change your systems within a scope you approve here.">
            {d.remediation_approved_at ? (
              <Alert color="secure" variant="light" title={`Approved ${fmtDateTime(d.remediation_approved_at)}`}>{d.remediation_scope}</Alert>
            ) : can("managed_service:approve") ? (
              <Stack>
                <Textarea label="Approved scope" description={minCharsHint(scope, 10, "Describe exactly what may be changed.")} autosize minRows={3} value={scope} onChange={(e) => setScope(e.currentTarget.value)} />
                <ConfirmButton title="Approve remediation?" message="This authorises Trust Data to perform the described actions. Your approval is permanently recorded in the audit trail." confirmLabel="Approve" disabled={scope.trim().length < 10} onConfirm={() => approve.mutateAsync()}>Record approval</ConfirmButton>
              </Stack>
            ) : <Text size="sm" c="dimmed">Only organisation owners can approve remediation.</Text>}
          </Section>
          <Anchor component={Link} to={`/app/${tid}/support`} size="sm">← All requests</Anchor>
        </Stack>
      </SimpleGrid>
    </>
  );
}
