import {
  Alert,
  Anchor,
  Badge,
  Box,
  Button,
  Card,
  Group,
  Modal,
  MultiSelect,
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
import { ApiError, api, downloadUrl, errorMessage } from "../../api/client";
import type { Page, Website } from "../../api/types";
import { fmtBytes, fmtDate, fmtDateTime, fmtMoney, humanize, minCharsHint, shortHash } from "../../components/format";
import { SlaBadge, SubscriptionBadge, TicketStatusBadge } from "../../components/status";
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

export interface Ticket {
  id: string;
  reference: string;
  subject: string;
  category: string;
  priority: string;
  status: string;
  created_at: string;
  updated_at: string;
  website_id: string | null;
  incident_ids: string[];
  is_service_request: boolean;
  assigned_team_member?: string | null;
  remediation_approved_at: string | null;
  remediation_scope: string | null;
  proposed_scope: string | null;
  authorisation_requested_at: string | null;
  access_granted: boolean;
  sla: { response_due: string | null; resolution_due: string | null; first_response_at: string | null; resolved_at: string | null; response: string; resolution: string };
  checklist: { key: string; label: string; done: boolean; done_at: string | null }[];
  time_spent_minutes: number;
  report: { findings?: string; actions_taken?: string; recommendations?: string; verification?: string; engineer?: string; updated_at?: string };
  billing_status: string;
  price_minor: number | null;
  messages?: { body: string; author: string; is_staff: boolean; internal?: boolean; kind: string; created_at: string }[];
}

interface DeskSummary {
  support_level: string;
  plan: string | null;
  response_hours: number;
  resolution_hours: number;
  tasks_per_month: number;
  used_this_month: number;
  remaining_this_month: number | null;
  service_types: { key: string; label: string }[];
}

const SERVICE_BLURB: Record<string, string> = {
  malware_cleanup: "Hacked site, malware warnings, spam pages or redirects. We clean it, find how they got in and harden it.",
  fix_site: "White screen, critical errors, broken contact forms or WooCommerce checkout.",
  migration: "Move your website to a new host or domain with minimal downtime.",
  maintenance: "Updates, configuration changes and other website tasks.",
  performance: "Make slow pages faster and measure the improvement.",
};
const OTHER_TYPES = ["general", "investigation", "technical", "billing"];

function hours(h: number): string {
  return h < 1 ? `${Math.round(h * 60)} min` : h < 48 ? `${+h.toFixed(1)} h` : `${+(h / 24).toFixed(1)} days`;
}

function TicketSla({ t }: { t: Ticket }) {
  if (["closed", "cancelled"].includes(t.status)) return null;
  return (
    <Group gap={4} wrap="nowrap">
      <SlaBadge state={t.sla.response} label="Reply" tooltip={t.sla.response_due ? `Due ${fmtDateTime(t.sla.response_due)}` : undefined} />
      <SlaBadge state={t.sla.resolution} label="Fix" tooltip={t.sla.resolution_due ? `Due ${fmtDateTime(t.sla.resolution_due)}` : undefined} />
    </Group>
  );
}

export function SupportPage() {
  const tid = useTenantId();
  const can = useCan();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [page, setPage] = useState(1);
  const [opened, { open, close }] = useDisclosure(false);
  const [form, setForm] = useState({ subject: "", category: "general", priority: "normal", body: "", website_id: "" as string | null, incident_ids: [] as string[] });
  const list = useQuery({ queryKey: ["tickets", tid, page], queryFn: () => api.get<Page<Ticket>>(`/tenants/${tid}/tickets`, { page, page_size: 20 }) });
  const desk = useQuery({ queryKey: ["service-desk", tid], queryFn: () => api.get<DeskSummary>(`/tenants/${tid}/service-desk`) });
  const sites = useQuery({ queryKey: ["websites-mini", tid], queryFn: () => api.get<Page<Website>>(`/tenants/${tid}/websites`, { page_size: 100 }), enabled: opened, retry: false });
  const incs = useQuery({
    queryKey: ["incidents-open-mini", tid, form.website_id],
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    queryFn: () => api.get<Page<any>>(`/tenants/${tid}/incidents`, { website_id: form.website_id || undefined, open_only: true, page_size: 50 }),
    enabled: opened && can("incidents:read"), retry: false,
  });
  const start = (category: string, extra: Partial<typeof form> = {}) => {
    setForm({ subject: "", category, priority: category === "malware_cleanup" ? "urgent" : "normal", body: "", website_id: null, incident_ids: [], ...extra });
    open();
  };
  // Opened from an incident: /support?new=malware_cleanup&website=…&incident=…
  useEffect(() => {
    const cat = params.get("new");
    if (cat && can("support:manage")) {
      start(cat, { website_id: params.get("website"), incident_ids: params.getAll("incident"), subject: params.get("subject") ?? "" });
      setParams({}, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);
  const create = useMutation({
    mutationFn: () => api.post<Ticket>(`/tenants/${tid}/tickets`, { ...form, website_id: form.website_id || null }),
    onSuccess: (t) => { close(); navigate(`/app/${tid}/support/${t.id}`); },
    onError: (e) => {
      const existing = e instanceof ApiError && e.status === 409 ? (e.details as { ticket_id?: string } | null)?.ticket_id : undefined;
      if (existing) {
        close();
        notifications.show({ color: "info", title: "Already being handled", message: errorMessage(e) });
        navigate(`/app/${tid}/support/${existing}`);
        return;
      }
      notifications.show({ color: "threat", title: "Not created", message: errorMessage(e) });
    },
  });
  const d = desk.data;
  const isService = !!d?.service_types.some((s) => s.key === form.category);
  const typeOptions = [...(d?.service_types ?? []).map((s) => ({ value: s.key, label: s.label })), ...OTHER_TYPES.map((v) => ({ value: v, label: humanize(v) + " question" }))];
  return (
    <>
      <PageHeader title="Support and services" description="Ask the Trust Data team for help, or order a service such as malware cleanup. Staff can see your website data only after you authorise the work, and only until the request is closed."
        crumbs={[{ label: "Overview", to: `/app/${tid}/overview` }, { label: "Support" }]}
        actions={can("support:manage") && <Button variant="default" leftSection={<IconPlus size={16} />} onClick={() => start("general")}>Ask a question</Button>} />
      {d && (
        <Alert color="info" variant="light" mb="md" title={`Your plan: ${d.plan ?? "none"} · ${humanize(d.support_level)} support`}>
          <Text size="sm">
            We reply within {hours(d.response_hours)} and aim to finish within {hours(d.resolution_hours)} (faster for urgent requests).{" "}
            {d.tasks_per_month < 0 ? "Service requests are unlimited on your plan."
              : d.tasks_per_month === 0 ? "Service requests are priced per request: we confirm the price before starting."
              : `Service requests this month: ${d.used_this_month} of ${d.tasks_per_month} included${d.remaining_this_month === 0 ? "; further requests are priced and confirmed before we start." : "."}`}
          </Text>
        </Alert>
      )}
      {can("support:manage") && d && (
        <SimpleGrid cols={{ base: 1, sm: 2, lg: 5 }} mb="md">
          {d.service_types.map((s) => (
            <Card key={s.key} p="md">
              <Stack gap={6} h="100%" justify="space-between">
                <Box>
                  <Text fw={700} size="sm">{s.label}</Text>
                  <Text size="xs" c="dimmed" mt={4}>{SERVICE_BLURB[s.key]}</Text>
                </Box>
                <Button size="xs" variant={s.key === "malware_cleanup" ? "filled" : "light"} onClick={() => start(s.key)}>Request</Button>
              </Stack>
            </Card>
          ))}
        </SimpleGrid>
      )}
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
          empty={<EmptyState icon={IconLifebuoy} title="No requests yet" description="Order a service above, or ask the team a question." />}
          columns={[
            { key: "ref", header: "Request", render: (t) => <Box><Text size="sm" fw={600}>{t.subject}</Text><Text size="xs" c="dimmed">{t.reference} · {humanize(t.category)}</Text></Box> },
            { key: "priority", header: "Priority", render: (t) => <Badge variant="outline" color={t.priority === "urgent" ? "threat" : "gray"}>{humanize(t.priority)}</Badge>, visibleFrom: "sm" },
            { key: "status", header: "Status", render: (t) => <TicketStatusBadge status={t.status} /> },
            { key: "sla", header: "Targets", render: (t) => <TicketSla t={t} />, visibleFrom: "md" },
            { key: "team", header: "Engineer", render: (t) => <Text size="sm">{t.assigned_team_member ?? "Unassigned"}</Text>, visibleFrom: "lg" },
            { key: "updated", header: "Updated", render: (t) => <Text size="sm">{fmtDateTime(t.updated_at)}</Text>, visibleFrom: "sm" },
          ]}
        />
      </Card>
      <Modal opened={opened} onClose={close} title={isService ? "Request a service" : "Ask the Trust Data team"} size="lg">
        <Stack>
          <Select label="What do you need?" data={typeOptions} value={form.category} onChange={(v) => setForm({ ...form, category: v ?? "general" })} allowDeselect={false} />
          <TextInput label="Subject" required value={form.subject} placeholder={form.category === "malware_cleanup" ? "e.g. Our site redirects to spam pages" : ""} onChange={(e) => setForm({ ...form, subject: e.currentTarget.value })} />
          <Group grow align="flex-start">
            <Select label="Website" clearable placeholder="Choose a website" data={(sites.data?.items ?? []).map((w) => ({ value: w.id, label: w.name }))} value={form.website_id} onChange={(v) => setForm({ ...form, website_id: v, incident_ids: [] })} />
            <Select label="Priority" data={["low", "normal", "high", "urgent"].map((v) => ({ value: v, label: humanize(v) }))} value={form.priority} onChange={(v) => setForm({ ...form, priority: v ?? "normal" })} allowDeselect={false} />
          </Group>
          {(incs.data?.items.length ?? 0) > 0 && (
            <MultiSelect label="Related incidents (optional)" data={incs.data!.items.map((i) => ({ value: i.id, label: `${i.reference} · ${i.title}`.slice(0, 120) }))} value={form.incident_ids} onChange={(v) => setForm({ ...form, incident_ids: v })} searchable />
          )}
          <Textarea label="Details" required autosize minRows={4} description="What you see, since when, anything that changed. Do not include passwords: we ask for access separately." value={form.body} onChange={(e) => setForm({ ...form, body: e.currentTarget.value })} />
          {isService && d && d.tasks_per_month >= 0 && (d.remaining_this_month ?? 0) <= 0 && (
            <Text size="xs" c="dimmed">This request is outside your plan's included services; we will confirm the price with you before starting.</Text>
          )}
          <Button onClick={() => create.mutate()} loading={create.isPending} disabled={form.subject.length < 3 || !form.body}>Submit</Button>
        </Stack>
      </Modal>
    </>
  );
}

function FileChangesSection({ ticketId }: { ticketId: string }) {
  const tid = useTenantId();
  const can = useCan();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const q = useQuery({ queryKey: ["ticket-remediation", tid, ticketId], queryFn: () => api.get<{ actions: any[] }>(`/tenants/${tid}/tickets/${ticketId}/remediation`) });
  const undo = useMutation({
    mutationFn: (id: string) => api.post(`/tenants/${tid}/tickets/${ticketId}/remediation/${id}/undo`, {}),
    onSuccess: () => { q.refetch(); notifications.show({ color: "secure", title: "Change undone", message: "The file is back as it was." }); },
    onError: (e) => notifications.show({ color: "threat", title: "Not undone", message: errorMessage(e) }),
  });
  if (!q.data?.actions.length) return null;
  return (
    <Section title="Changes made to your files" description="Every change Trust Data made for this request. A copy of each original file is kept, so you can put it back.">
      <Stack gap="xs">
        {q.data.actions.map((a) => (
          <Group key={a.id} justify="space-between" wrap="nowrap" align="flex-start">
            <Box miw={0}>
              <Text size="sm" style={{ wordBreak: "break-all" }}><b>{a.action === "restore_genuine" ? "Restored official version" : "Quarantined (removed)"}</b> · <span className="cw-mono">{a.path}</span></Text>
              <Text size="xs" c="dimmed">{a.performed_by} · {fmtDateTime(a.performed_at)}{a.status === "undone" ? ` · undone ${fmtDateTime(a.undone_at)} by ${a.undone_by}` : a.status === "failed" ? ` · failed: ${a.error}` : ""}</Text>
            </Box>
            {a.can_undo && can("managed_service:approve") && (
              <ConfirmButton size="xs" variant="default" title="Undo this change?" message={`${a.path} will be put back exactly as it was before this change.`} confirmLabel="Undo" onConfirm={() => undo.mutateAsync(a.id)}>Undo</ConfirmButton>
            )}
          </Group>
        ))}
      </Stack>
    </Section>
  );
}

export function TicketPage() {
  const tid = useTenantId();
  const { ticketId } = useParams();
  const can = useCan();
  const [reply, setReply] = useState("");
  const [scope, setScope] = useState("");
  const t = useQuery({ queryKey: ["ticket", tid, ticketId], queryFn: () => api.get<Ticket>(`/tenants/${tid}/tickets/${ticketId}`), refetchInterval: 60_000 });
  const onError = (e: unknown) => notifications.show({ color: "threat", title: "Not done", message: errorMessage(e) });
  const send = useMutation({ mutationFn: () => api.post(`/tenants/${tid}/tickets/${ticketId}/messages`, { body: reply }), onSuccess: () => { setReply(""); t.refetch(); }, onError });
  const approve = useMutation({
    mutationFn: () => api.post(`/tenants/${tid}/tickets/${ticketId}/remediation-approval`, { scope, confirm: true }),
    onSuccess: () => t.refetch(),
    onError,
  });
  const closeReq = useMutation({ mutationFn: () => api.post(`/tenants/${tid}/tickets/${ticketId}/close`, {}), onSuccess: () => t.refetch(), onError });
  const proposed = t.data?.proposed_scope;
  useEffect(() => { if (proposed && !scope) setScope(proposed); }, [proposed]); // eslint-disable-line react-hooks/exhaustive-deps
  if (t.error) return <ErrorState error={t.error} />;
  if (!t.data) return <LoadingBlock />;
  const d = t.data;
  const done = d.checklist.filter((c) => c.done).length;
  const authNeeded = d.is_service_request && !d.remediation_approved_at && !!d.proposed_scope && !["closed", "cancelled"].includes(d.status);
  const finished = ["closed", "cancelled"].includes(d.status);
  const r = d.report ?? {};
  return (
    <>
      <PageHeader title={d.subject} description={`${d.reference} · ${humanize(d.category)} · ${humanize(d.priority)} priority`} crumbs={[{ label: "Support", to: `/app/${tid}/support` }, { label: d.reference }]}
        actions={<Group gap="xs"><TicketStatusBadge status={d.status} />
          {can("support:manage") && !finished && (d.status === "resolved"
            ? <Button size="xs" onClick={() => closeReq.mutate()} loading={closeReq.isPending}>Confirm fixed and close</Button>
            : !d.sla.first_response_at && <ConfirmButton size="xs" variant="default" title="Withdraw this request?" message="The request is cancelled. You can open a new one at any time." confirmLabel="Withdraw" onConfirm={() => closeReq.mutateAsync()}>Withdraw</ConfirmButton>)}
        </Group>} />
      {d.billing_status === "quote" && !finished && (
        <Alert color="amber" variant="light" mb="md" title="Price to be confirmed">This request is outside your plan's included services. We will confirm the price with you before any work starts.</Alert>
      )}
      {authNeeded ? (
        <Alert color="amber" variant="light" mb="md" icon={<IconAlertTriangle />} title="Trust Data is asking for your authorisation" style={{ borderLeft: "4px solid var(--mantine-color-amber-6)" }}>
          <Text size="sm">Before changing anything on your website we need your permission for: <b>{d.proposed_scope}</b></Text>
          <Text size="sm" mt={4}>{can("managed_service:approve") ? "Review and authorise it under \u201cAuthorise the work\u201d on this page (you can adjust the scope first)." : "Ask an organisation owner to authorise it on this page."}</Text>
        </Alert>
      ) : d.status === "awaiting_customer" && <Alert color="amber" variant="light" mb="md" title="We need your input">Please reply below so we can continue.</Alert>}
      <SimpleGrid cols={{ base: 1, md: 3 }} spacing="md">
        <Stack style={{ gridColumn: "span 2" }}>
          {(r.actions_taken || r.findings) && (
            <Section title="Work report" description={r.engineer ? `Prepared by ${r.engineer}${r.updated_at ? ` · ${fmtDateTime(r.updated_at)}` : ""}` : undefined}
              actions={<Button size="xs" variant="default" onClick={() => window.print()}>Print</Button>}>
              <Stack gap="sm">
                {r.findings && <Box><Text size="sm" fw={700}>What we found</Text><Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{r.findings}</Text></Box>}
                {r.actions_taken && <Box><Text size="sm" fw={700}>What we did</Text><Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{r.actions_taken}</Text></Box>}
                {r.verification && <Box><Text size="sm" fw={700}>How we checked it</Text><Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{r.verification}</Text></Box>}
                {r.recommendations && <Box><Text size="sm" fw={700}>Our recommendations</Text><Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{r.recommendations}</Text></Box>}
              </Stack>
            </Section>
          )}
          {d.is_service_request && <FileChangesSection ticketId={d.id} />}
          <Section title="Conversation">
            <Stack>
              {d.messages?.map((m, i) => m.kind === "status" ? (
                <Text key={i} size="xs" c="dimmed" ta="center">{m.body} · {fmtDateTime(m.created_at)}</Text>
              ) : (
                <Card key={i} p="sm" shadow="none" style={{ background: m.is_staff ? "var(--cw-sidebar-active)" : "var(--cw-surface-alt)" }}>
                  <Group justify="space-between"><Text size="sm" fw={600}>{m.author}{m.is_staff ? " · Trust Data" : ""}</Text><Text size="xs" c="dimmed">{fmtDateTime(m.created_at)}</Text></Group>
                  <Text size="sm" mt={4} style={{ whiteSpace: "pre-wrap" }}>{m.body}</Text>
                </Card>
              ))}
              {can("support:manage") && d.status !== "cancelled" && (
                <>
                  <Textarea placeholder="Write a reply…" autosize minRows={3} value={reply} onChange={(e) => setReply(e.currentTarget.value)} aria-label="Reply" />
                  <Button w="fit-content" onClick={() => send.mutate()} loading={send.isPending} disabled={!reply.trim()}>Send</Button>
                </>
              )}
            </Stack>
          </Section>
        </Stack>
        <Stack>
          <Section title="Service team">
            <KeyValue items={[
              ["Engineer", d.assigned_team_member ?? "Being assigned"],
              ["First reply", d.sla.first_response_at ? fmtDateTime(d.sla.first_response_at) : `Due ${fmtDateTime(d.sla.response_due)}`],
              ["Target to finish", d.sla.resolved_at ? `Resolved ${fmtDateTime(d.sla.resolved_at)}` : fmtDateTime(d.sla.resolution_due)],
              ...(d.time_spent_minutes ? [["Time spent", `${Math.round(d.time_spent_minutes / 6) / 10} h`] as [string, string]] : []),
            ]} />
          </Section>
          {d.checklist.length > 0 && (
            <Section title="Progress" description={`${done} of ${d.checklist.length} steps done`}>
              <Progress value={(100 * done) / d.checklist.length} color="secure" mb="xs" aria-label="Progress" />
              <Stack gap={4}>
                {d.checklist.map((c) => <Text key={c.key} size="sm" c={c.done ? undefined : "dimmed"}>{c.done ? "✓" : "○"} {c.label}</Text>)}
              </Stack>
            </Section>
          )}
          {d.incident_ids.length > 0 && can("incidents:read") && (
            <Section title="Related incidents">
              <Stack gap={4}>{d.incident_ids.map((id, i) => <Anchor key={id} component={Link} to={`/app/${tid}/incidents/${id}`} size="sm">Incident {i + 1}</Anchor>)}</Stack>
            </Section>
          )}
          {d.is_service_request && (
            <Section title="Authorise the work" description="Trust Data may change your website only within the scope you approve here. The assigned engineer gets access to this organisation's monitoring data for 14 days or until you close this request.">
              {d.remediation_approved_at ? (
                <Alert color="secure" variant="light" title={`Authorised ${fmtDateTime(d.remediation_approved_at)}`}>
                  <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{d.remediation_scope}</Text>
                  <Text size="xs" mt={6}>{d.access_granted ? "The engineer has access while this request is open." : "Access starts when an engineer is assigned."}</Text>
                </Alert>
              ) : finished ? <Text size="sm" c="dimmed">Not authorised.</Text> : can("managed_service:approve") ? (
                <Stack>
                  <Textarea label="Approved scope" description={minCharsHint(scope, 10, d.proposed_scope ? "Proposed by Trust Data. You may narrow or adjust it before authorising." : "Describe exactly what may be changed, e.g. 'Remove malware and restore genuine files on www.example.com; update plugins'.")} autosize minRows={3} value={scope} onChange={(e) => setScope(e.currentTarget.value)} />
                  <ConfirmButton title="Authorise this work?" message="Trust Data may make the described changes, and the assigned engineer gets time-limited access to your monitoring data. Your authorisation is permanently recorded in the audit trail." confirmLabel="Authorise" disabled={scope.trim().length < 10} onConfirm={() => approve.mutateAsync()}>Authorise</ConfirmButton>
                </Stack>
              ) : <Text size="sm" c="dimmed">Only organisation owners can authorise work.</Text>}
            </Section>
          )}
          <Anchor component={Link} to={`/app/${tid}/support`} size="sm">← All requests</Anchor>
        </Stack>
      </SimpleGrid>
    </>
  );
}
