/**
 * Security operations portal (dark theme by default). Shows cross-tenant
 * operational metadata only; customer file paths, hashes and evidence are
 * visible solely through a customer-approved managed-service grant.
 */
import { Alert, Anchor, Badge, Box, Button, Card, Grid, Group, Modal, MultiSelect, Select, SimpleGrid, Stack, Table, Text, Textarea, TextInput, Tooltip } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconActivity,
  IconAlertTriangle,
  IconBug,
  IconClockPause,
  IconCpu,
  IconFileSearch,
  IconListDetails,
  IconLock,
  IconPlugConnectedX,
} from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { usePlatformCan } from "../../api/auth";
import { api, errorMessage } from "../../api/client";
import type { Job, Page } from "../../api/types";
import { fmtBytes, fmtDateTime, fmtRelative, humanize, minCharsHint } from "../../components/format";
import { HealthBadge, IncidentStatusBadge, ScanBadge, SeverityBadge } from "../../components/status";
import { DataTable, EmptyState, ErrorState, KeyValue, LoadingBlock, PageHeader, Section, StatCard } from "../../components/ui";

const onError = (e: unknown) => notifications.show({ color: "threat", title: "Action failed", message: errorMessage(e) });

/* eslint-disable @typescript-eslint/no-explicit-any */

export function OpsOverviewPage() {
  const q = useQuery({ queryKey: ["ops-overview"], queryFn: () => api.get<any>("/ops/overview"), refetchInterval: 15_000 });
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  const d = q.data;
  const alive = d?.workers.filter((w: any) => w.alive).length ?? 0;
  return (
    <>
      <PageHeader title="Security overview" description="Live operational view across all customers. Refreshes every 15 seconds." />
      {d?.alerts.length > 0 && (
        <Alert color="threat" icon={<IconAlertTriangle />} mb="md" title="Infrastructure alerts">
          {d.alerts.map((a: any) => <Text size="sm" key={a.message}>[{a.severity}] {a.message}</Text>)}
        </Alert>
      )}
      <SimpleGrid cols={{ base: 2, md: 3, xl: 6 }} mb="md">
        <StatCard label="Pending scans" icon={IconClockPause} loading={!d} value={d?.jobs.queued} to="/ops/jobs?status=queued" />
        <StatCard label="Running" icon={IconActivity} loading={!d} value={d?.jobs.running} to="/ops/jobs?status=running" />
        <StatCard label="Failed (24h)" icon={IconAlertTriangle} tone={d?.jobs.failed_24h ? "threat" : "secure"} loading={!d} value={d?.jobs.failed_24h} to="/ops/jobs?status=failed" />
        <StatCard label="Stale jobs" icon={IconClockPause} tone={d?.jobs.stale_running ? "amber" : "secure"} loading={!d} value={d?.jobs.stale_running} />
        <StatCard label="Failing connections" icon={IconPlugConnectedX} tone={d?.failing_connections ? "amber" : "secure"} loading={!d} value={d?.failing_connections} to="/ops/diagnostics" />
        <StatCard label="Workers alive" icon={IconCpu} tone={alive ? "secure" : "threat"} loading={!d} value={d ? `${alive}/${d.workers.length}` : "—"} to="/ops/workers" />
      </SimpleGrid>
      <Grid>
        <Grid.Col span={{ base: 12, lg: 8 }}>
          <Section title="High-priority open incidents" actions={<Anchor component={Link} to="/ops/incidents" size="sm">All incidents</Anchor>}>
            {!d ? <LoadingBlock /> : d.high_priority_incidents.length === 0 ? <EmptyState title="No critical or high incidents open" /> : (
              <div className="cw-table-scroll">
                <Table miw={560}>
                  <Table.Tbody>
                    {d.high_priority_incidents.map((i: any) => (
                      <Table.Tr key={i.id}>
                        <Table.Td><SeverityBadge severity={i.severity} /></Table.Td>
                        <Table.Td><Text size="sm" fw={600}>{i.tenant}</Text><Text size="xs" c="dimmed">{i.reference} · {humanize(i.category)}{i.is_demo ? " · demo" : ""}</Text></Table.Td>
                        <Table.Td><IncidentStatusBadge status={i.status} /></Table.Td>
                        <Table.Td><Text size="sm">{fmtRelative(i.last_observed_at)}</Text></Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </div>
            )}
          </Section>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 4 }}>
          <Stack>
            <Section title="New findings (24h)">
              {d && <Stack gap={6}>{Object.entries(d.new_findings_24h).map(([s, n]) => <Group key={s} justify="space-between"><SeverityBadge severity={s} /><Text fw={600}>{n as number}</Text></Group>)}</Stack>}
            </Section>
            <Section title="Queues">
              {d && (Object.keys(d.queues).length ? <KeyValue items={Object.entries(d.queues).map(([q, n]) => [q, `${n} waiting`])} /> : <Text size="sm" c="threat.4">Queue depth unavailable (Redis unreachable).</Text>)}
              {d && <Text size="xs" c="dimmed" mt="xs">Notification failures (24h): {d.notification_failures_24h}</Text>}
            </Section>
          </Stack>
        </Grid.Col>
      </Grid>
    </>
  );
}

export function ScanQueuePage() {
  const can = usePlatformCan();
  const params = new URLSearchParams(window.location.search);
  const [status, setStatus] = useState<string | null>(params.get("status"));
  const [type, setType] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: ["ops-jobs", status, type, page], queryFn: () => api.get<Page<Job>>("/ops/jobs", { status: status ?? undefined, job_type: type ?? undefined, page, page_size: 30 }), refetchInterval: 10_000 });
  const retry = useMutation({ mutationFn: (id: string) => api.post(`/ops/jobs/${id}/retry`), onSuccess: () => q.refetch(), onError });
  const cancel = useMutation({ mutationFn: (id: string) => api.post(`/ops/jobs/${id}/cancel`), onSuccess: () => q.refetch(), onError });
  return (
    <>
      <PageHeader title="Scheduler and job queue" description="Scheduled, queued, running and completed monitoring jobs. Overlapping jobs for the same website are prevented by the database." />
      <Card>
        <Group mb="md">
          <Select placeholder="Status" clearable w={150} value={status} onChange={setStatus} aria-label="Status" data={["queued", "running", "succeeded", "partial", "failed", "cancelled"].map((v) => ({ value: v, label: humanize(v) }))} />
          <Select placeholder="Type" clearable w={190} value={type} onChange={setType} aria-label="Type" data={["file_scan", "availability", "tls", "connection_test"].map((v) => ({ value: v, label: humanize(v) }))} />
        </Group>
        <DataTable<Job>
          rows={q.data?.items}
          loading={q.isLoading}
          error={q.error}
          rowKey={(j) => j.id}
          page={page}
          pageSize={30}
          total={q.data?.total}
          onPage={setPage}
          empty={<EmptyState title="No jobs match" />}
          columns={[
            { key: "type", header: "Job", render: (j) => <Box><Text size="sm" fw={600}>{humanize(j.job_type)}</Text><Text size="xs" c="dimmed">{j.tenant}</Text></Box> },
            { key: "status", header: "Status", render: (j) => <ScanBadge status={j.status} /> },
            { key: "q", header: "Queued", render: (j) => <Text size="sm">{fmtRelative(j.queued_at)}</Text> },
            { key: "hb", header: "Heartbeat", render: (j) => <Text size="sm">{j.status === "running" ? fmtRelative(j.heartbeat_at) : "—"}</Text>, visibleFrom: "md" },
            { key: "att", header: "Attempts", render: (j) => <Text size="sm">{j.attempts}/{j.max_attempts}</Text> },
            { key: "err", header: "Error", render: (j) => <Tooltip label={j.error_message ?? ""} disabled={!j.error_message}><Text size="xs" c="dimmed" lineClamp={1}>{j.error_class ? humanize(j.error_class) : ""}</Text></Tooltip>, visibleFrom: "sm" },
            { key: "x", header: "", render: (j) => can("ops:jobs:manage") && (j.status === "failed" || j.status === "partial" || j.status === "cancelled" ? <Button size="xs" variant="subtle" onClick={() => retry.mutate(j.id)}>Retry</Button> : j.status === "queued" || j.status === "running" ? <Button size="xs" variant="subtle" color="threat" onClick={() => cancel.mutate(j.id)}>Cancel</Button> : null) },
          ]}
        />
      </Card>
    </>
  );
}

export function DiagnosticsPage() {
  const [failingOnly, setFailingOnly] = useState("failing");
  const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: ["ops-connections", failingOnly, page], queryFn: () => api.get<Page<any>>("/ops/connections", { failing_only: failingOnly === "failing", page, page_size: 30 }), retry: false });
  if (q.error) return <ErrorState error={q.error} />;
  return (
    <>
      <PageHeader title="Hosting diagnostics" description="Sanitised connection health across customers: permission failures, expired credentials and unreachable services. Running a live test requires a customer grant." />
      <Card>
        <Select mb="md" w={200} value={failingOnly} onChange={(v) => setFailingOnly(v ?? "failing")} data={[{ value: "failing", label: "Failing or untested" }, { value: "all", label: "All connections" }]} aria-label="Filter" />
        <DataTable
          rows={q.data?.items}
          loading={q.isLoading}
          rowKey={(a) => a.id}
          page={page}
          pageSize={30}
          total={q.data?.total}
          onPage={setPage}
          empty={<EmptyState title="All connections healthy" />}
          columns={[
            { key: "c", header: "Customer / connection", render: (a) => <Box><Text size="sm" fw={600}>{a.tenant}</Text><Text size="xs" c="dimmed">{a.name} · {humanize(a.connector_type)} · {a.hostname}:{a.port}</Text></Box> },
            { key: "s", header: "Status", render: (a) => <HealthBadge state={a.status === "connected" ? "healthy" : a.status === "untested" ? "pending" : "failed"} /> },
            { key: "e", header: "Diagnosis", render: (a) => <Box><Text size="xs" fw={600}>{humanize(a.last_error_code)}</Text><Text size="xs" c="dimmed" lineClamp={2}>{a.last_error_message}</Text></Box> },
            { key: "t", header: "Last tested", render: (a) => <Text size="sm">{fmtRelative(a.last_tested_at)}</Text>, visibleFrom: "md" },
            { key: "ok", header: "Last success", render: (a) => <Text size="sm">{fmtRelative(a.last_success_at)}</Text>, visibleFrom: "lg" },
          ]}
        />
      </Card>
    </>
  );
}

export function OpsIncidentsPage() {
  const can = usePlatformCan();
  const [severity, setSeverity] = useState<string[]>([]);
  const [category, setCategory] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [action, setAction] = useState<{ id: string; ref: string } | null>(null);
  const [form, setForm] = useState({ action: "", note: "" });
  const q = useQuery({ queryKey: ["ops-incidents", severity, category, page], queryFn: () => api.get<Page<any>>("/ops/incidents", { severity, category: category ?? undefined, page, page_size: 30 }), retry: false });
  const record = useMutation({ mutationFn: () => api.post(`/ops/incidents/${action?.id}/actions`, form), onSuccess: () => { setAction(null); setForm({ action: "", note: "" }); notifications.show({ color: "secure", title: "Recorded", message: "Response action added to the incident history." }); }, onError });
  if (q.error) return <ErrorState error={q.error} />;
  return (
    <>
      <PageHeader title="Global incident oversight" description="Open incidents across customers. Titles and evidence are shown only for customers who granted your team access." />
      <Card>
        <Group mb="md">
          <MultiSelect placeholder="Severity" w={240} data={["critical", "high", "medium", "low"].map((v) => ({ value: v, label: humanize(v) }))} value={severity} onChange={setSeverity} aria-label="Severity" />
          <Select placeholder="Category" clearable w={200} data={["file_integrity", "suspicious_file", "availability", "tls", "connection"].map((v) => ({ value: v, label: humanize(v) }))} value={category} onChange={setCategory} aria-label="Category" />
        </Group>
        <DataTable
          rows={q.data?.items}
          loading={q.isLoading}
          rowKey={(i) => i.id}
          page={page}
          pageSize={30}
          total={q.data?.total}
          onPage={setPage}
          empty={<EmptyState title="No open incidents" />}
          columns={[
            { key: "s", header: "Severity", render: (i) => <SeverityBadge severity={i.severity} /> },
            { key: "c", header: "Customer", render: (i) => <Box><Text size="sm" fw={600}>{i.tenant}</Text><Text size="xs" c="dimmed">{i.reference} · {humanize(i.category)}</Text></Box> },
            { key: "t", header: "Detail", render: (i) => i.has_grant ? <Anchor component={Link} to={`/app/${i.tenant_id}/incidents/${i.id}`} size="sm">{i.title}</Anchor> : <Group gap={4}><IconLock size={14} /><Text size="xs" c="dimmed">Requires customer grant</Text></Group> },
            { key: "st", header: "Status", render: (i) => <IncidentStatusBadge status={i.status} /> },
            { key: "o", header: "Last observed", render: (i) => <Text size="sm">{fmtRelative(i.last_observed_at)}</Text>, visibleFrom: "md" },
            { key: "x", header: "", render: (i) => can("ops:incidents:manage") && <Button size="xs" variant="subtle" onClick={() => setAction({ id: i.id, ref: i.reference })}>Record action</Button> },
          ]}
        />
      </Card>
      <Modal opened={!!action} onClose={() => setAction(null)} title={`Record response action · ${action?.ref}`}>
        <Stack>
          <TextInput label="Action" description={minCharsHint(form.action, 3)} placeholder="e.g. Contacted customer security lead" value={form.action} onChange={(e) => setForm({ ...form, action: e.currentTarget.value })} />
          <Textarea label="Notes" description={minCharsHint(form.note, 3)} autosize minRows={3} value={form.note} onChange={(e) => setForm({ ...form, note: e.currentTarget.value })} />
          <Text size="xs" c="dimmed">Recorded as a manual action in the tamper-evident incident history. Actions that change customer systems require recorded customer approval.</Text>
          <Button onClick={() => record.mutate()} loading={record.isPending} disabled={form.action.trim().length < 3 || form.note.trim().length < 3}>Record</Button>
        </Stack>
      </Modal>
    </>
  );
}

export function OpsNotificationsPage() {
  const [status, setStatus] = useState("failed");
  const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: ["ops-notifications", status, page], queryFn: () => api.get<Page<any>>("/ops/notifications", { status, page, page_size: 30 }) });
  return (
    <>
      <PageHeader title="Notification dispatcher" description="Delivery failures, retries and unconfigured channels across customers." />
      <Card>
        <Select mb="md" w={180} value={status} onChange={(v) => setStatus(v ?? "failed")} data={["failed", "pending", "unconfigured"].map((v) => ({ value: v, label: humanize(v) }))} aria-label="Status" />
        <DataTable rows={q.data?.items} loading={q.isLoading} error={q.error} rowKey={(n) => n.id} page={page} pageSize={30} total={q.data?.total} onPage={setPage}
          empty={<EmptyState title={`No ${status} notifications`} />}
          columns={[
            { key: "t", header: "Created", render: (n) => <Text size="sm">{fmtDateTime(n.created_at)}</Text> },
            { key: "c", header: "Customer", render: (n) => <Text size="sm">{n.tenant ?? "Platform"}</Text> },
            { key: "ch", header: "Channel", render: (n) => <Text size="sm">{humanize(n.channel)} · {humanize(n.category)}</Text> },
            { key: "a", header: "Attempts", render: (n) => <Text size="sm">{n.attempts}</Text> },
            { key: "e", header: "Last error", render: (n) => <Text size="xs" c="dimmed">{n.last_error}</Text> },
          ]} />
      </Card>
    </>
  );
}

export function WorkerHealthPage() {
  const q = useQuery({ queryKey: ["ops-health"], queryFn: () => api.get<any>("/ops/health"), refetchInterval: 15_000, retry: false });
  if (q.error) return <ErrorState error={q.error} />;
  const d = q.data;
  if (!d) return <LoadingBlock rows={8} />;
  return (
    <>
      <PageHeader title="Worker and infrastructure health" description={`Checked ${fmtRelative(d.checked_at)}.`} />
      {d.alerts.length > 0 && <Alert color="threat" mb="md" icon={<IconAlertTriangle />} title="Alerts">{d.alerts.map((a: any) => <Text key={a.message} size="sm">[{a.severity}] {a.message}</Text>)}</Alert>}
      <SimpleGrid cols={{ base: 1, md: 3 }} mb="md">
        <Section title="Database"><HealthBadge state={d.database.ok ? "healthy" : "failed"} /></Section>
        <Section title="Redis and queues">
          <HealthBadge state={d.redis.ok ? "healthy" : "failed"} />
          <KeyValue items={Object.entries(d.redis.queues ?? {}).map(([k, v]) => [k, `${v} waiting`])} />
        </Section>
        <Section title="Scheduler">
          <HealthBadge state={d.scheduler.ok ? "healthy" : "degraded"} />
          <KeyValue items={Object.entries(d.scheduler.tasks).map(([k, v]: [string, any]) => [humanize(k), fmtRelative(v.last_run_at)])} />
        </Section>
        <Section title="Disk">
          {d.disk.used_pct !== undefined ? <KeyValue items={[["Used", `${d.disk.used_pct}%`], ["Free", fmtBytes(d.disk.free_bytes)]]} /> : <Text size="sm">Unavailable</Text>}
        </Section>
        <Section title="Backups">
          {d.backup ? <KeyValue items={[["Status", <HealthBadge key="b" state={d.backup.status === "ok" ? "healthy" : "failed"} />], ["Reported", fmtDateTime(d.backup.reported_at)], ["Location", d.backup.location]]} /> : <Text size="sm" c="amber.5">No backup has been reported.</Text>}
        </Section>
        <Section title="Job latency and durations (24h)">
          <KeyValue items={[["Avg queue wait", d.avg_queue_latency_seconds === null ? "—" : `${d.avg_queue_latency_seconds}s`], ...Object.entries(d.avg_duration_seconds_by_type).map(([k, v]: [string, any]) => [humanize(k), `${v.avg}s avg · ${v.count} jobs`] as [string, string])]} />
          {d.resource_usage?.load_avg && <Text size="xs" c="dimmed" mt="xs">API host load: {d.resource_usage.load_avg.join(" / ")}</Text>}
        </Section>
      </SimpleGrid>
      <Section title="Workers" description="Each worker reports a heartbeat every 20 seconds.">
        <DataTable rows={d.workers} rowKey={(w: any) => w.name} empty={<EmptyState title="No worker has reported a heartbeat" description="Start the monitoring and notification workers." />}
          columns={[
            { key: "n", header: "Worker", render: (w: any) => <Text size="sm" className="cw-mono">{w.name}</Text> },
            { key: "q", header: "Queues", render: (w: any) => <Group gap={4}>{w.queues.map((q: string) => <Badge key={q} size="xs" variant="outline">{q}</Badge>)}</Group> },
            { key: "s", header: "State", render: (w: any) => <HealthBadge state={w.alive ? "healthy" : "failed"} /> },
            { key: "l", header: "Last heartbeat", render: (w: any) => <Text size="sm">{fmtRelative(w.last_seen_at)}</Text> },
            { key: "st", header: "Started", render: (w: any) => <Text size="sm">{fmtDateTime(w.started_at)}</Text>, visibleFrom: "md" },
          ]} />
      </Section>
    </>
  );
}

/** Honest placeholder views for capabilities that are not active in this release. */
export function CapabilityNoticePage({ kind }: { kind: "files" | "malware" | "logs" | "evidence" }) {
  const content = {
    files: { title: "File inventory and integrity", icon: IconFileSearch, body: "Customer file inventories, baselines and change history are customer data. Open a customer workspace through an approved managed-service grant to investigate.", link: "/admin/grants", linkLabel: "Request or use a grant" },
    malware: { title: "Malware findings", icon: IconBug, body: "Signature-based malware scanning (ClamAV/YARA) is not enabled in this release. Heuristic suspicious-file findings appear as incidents under the 'Suspicious file' category and are never presented as confirmed malware.", link: "/ops/incidents", linkLabel: "View suspicious-file incidents" },
    logs: { title: "Log and attack analysis", icon: IconListDetails, body: "Log analysis is not active. No connection has a verified, implemented log-access capability in this release; CyberWatch does not claim log analysis where logs are unavailable.", link: "/ops/diagnostics", linkLabel: "Review connection capabilities" },
    evidence: { title: "Evidence store", icon: IconLock, body: "Incident evidence is hashed at collection and stored per customer. Access it from the incident page inside a customer workspace, under an approved grant. Integrity is verified on every view.", link: "/admin/grants", linkLabel: "Managed-service grants" },
  }[kind];
  const IconCmp = content.icon;
  return (
    <>
      <PageHeader title={content.title} />
      <Card>
        <EmptyState icon={IconCmp} title={kind === "malware" || kind === "logs" ? "Not available in this release" : "Customer data requires a grant"} description={content.body}
          action={<Button component={Link} to={content.link} variant="light">{content.linkLabel}</Button>} />
      </Card>
    </>
  );
}
