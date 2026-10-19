import { Anchor, Badge, Box, Button, Card, Group, Select, Tabs, Text, Tooltip } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconDownload, IconFileDiff } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useCan, useTenantId } from "../../api/auth";
import { api, downloadUrl, errorMessage } from "../../api/client";
import type { FileChange, Job, Page, Website } from "../../api/types";
import { fmtBytes, fmtDateTime, fmtRelative, humanize, shortHash } from "../../components/format";
import { HealthBadge, ScanBadge, SeverityBadge } from "../../components/status";
import { DataTable, EmptyState, PageHeader, SearchInput } from "../../components/ui";

function useSiteOptions() {
  const tid = useTenantId();
  return useQuery({
    queryKey: ["website-options", tid],
    queryFn: () => api.get<Page<Website>>(`/tenants/${tid}/websites`, { page_size: 200 }),
    select: (d) => d.items.map((w) => ({ value: w.id, label: w.name })),
  });
}

interface InventoryItem {
  path: string;
  entry_type: string;
  size: number | null;
  mtime: string | null;
  sha256: string | null;
  hash_status: string;
  file_type: string | null;
  state: string;
  first_seen_at: string;
  last_seen_at: string;
}

export function FilesPage() {
  const tid = useTenantId();
  const [params, setParams] = useSearchParams();
  const sites = useSiteOptions();
  const website = params.get("website");
  const setWebsite = (v: string | null) => {
    const p = new URLSearchParams(params);
    if (v) p.set("website", v);
    else p.delete("website");
    setParams(p, { replace: true });
  };
  const [tab, setTab] = useState<string | null>("changes");
  return (
    <>
      <PageHeader
        title="File integrity"
        description="SHA-256 change history and current inventory. Observed deletions are only recorded when the parent directory was fully listed."
        crumbs={[{ label: "Overview", to: `/app/${tid}/overview` }, { label: "File integrity" }]}
        actions={
          <Select placeholder="All websites" clearable data={sites.data ?? []} value={website} onChange={setWebsite} w={240} aria-label="Website" />
        }
      />
      <Tabs value={tab} onChange={setTab}>
        <Tabs.List mb="md">
          <Tabs.Tab value="changes">Change history</Tabs.Tab>
          <Tabs.Tab value="inventory" disabled={!website}>
            <Tooltip label="Select a website first" disabled={!!website}>
              <span>File inventory</span>
            </Tooltip>
          </Tabs.Tab>
          <Tabs.Tab value="compare" disabled={!website}>Compare with baseline</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="changes">
          <ChangesTable websiteId={website} />
        </Tabs.Panel>
        <Tabs.Panel value="inventory">{website && <InventoryTable websiteId={website} />}</Tabs.Panel>
        <Tabs.Panel value="compare">{website && <ComparePanel websiteId={website} />}</Tabs.Panel>
      </Tabs>
    </>
  );
}

function ChangesTable({ websiteId }: { websiteId: string | null }) {
  const tid = useTenantId();
  const [changeType, setChangeType] = useState<string | null>(null);
  const [severity, setSeverity] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const list = useQuery({
    queryKey: ["changes", tid, websiteId, changeType, severity, q, page],
    queryFn: () =>
      api.get<Page<FileChange>>(`/tenants/${tid}/changes`, { website_id: websiteId ?? undefined, change_type: changeType ?? undefined, severity: severity ?? undefined, q, page, page_size: 50 }),
  });
  return (
    <Card>
      <Group mb="md" gap="sm" justify="space-between" wrap="wrap">
        <Group gap="sm" wrap="wrap">
          <SearchInput value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Filter by path" />
          <Select placeholder="Change" clearable w={160} value={changeType} onChange={setChangeType} aria-label="Change type"
            data={["added", "modified", "deleted", "renamed", "metadata_changed", "type_changed"].map((v) => ({ value: v, label: humanize(v) }))} />
          <Select placeholder="Severity" clearable w={150} value={severity} onChange={setSeverity} aria-label="Severity"
            data={["critical", "high", "medium", "low"].map((v) => ({ value: v, label: humanize(v) }))} />
        </Group>
        <Button component="a" variant="default" leftSection={<IconDownload size={16} />}
          href={downloadUrl(`/tenants/${tid}/changes/export.csv`, { website_id: websiteId ?? undefined, change_type: changeType ?? undefined, severity: severity ?? undefined })}>
          Export CSV
        </Button>
      </Group>
      <DataTable<FileChange>
        rows={list.data?.items}
        loading={list.isLoading}
        error={list.error}
        rowKey={(c) => c.id}
        page={page}
        pageSize={50}
        total={list.data?.total}
        onPage={setPage}
        empty={<EmptyState icon={IconFileDiff} title="No file changes recorded" description="Changes appear after at least two successful scans of a website." />}
        columns={[
          { key: "severity", header: "Severity", render: (c) => <SeverityBadge severity={c.severity} />, width: 110 },
          {
            key: "path",
            header: "Path",
            render: (c) => (
              <Box maw={460}>
                <Text className="cw-mono">{c.path}</Text>
                {c.old_path && <Text size="xs" c="dimmed">from {c.old_path}</Text>}
                {c.flags.filter((f) => f !== "file_changed").length > 0 && (
                  <Group gap={4} mt={2}>
                    {c.flags.filter((f) => f !== "file_changed").map((f) => <Badge key={f} size="xs" variant="outline" color="gray">{humanize(f)}</Badge>)}
                  </Group>
                )}
              </Box>
            ),
          },
          { key: "change", header: "Change", render: (c) => <Text size="sm">{humanize(c.change_type)}{c.confidence === "low" ? <Text span size="xs" c="amber.8"> (low confidence)</Text> : null}</Text> },
          { key: "website", header: "Website", render: (c) => <Text size="sm">{c.website_name}</Text>, visibleFrom: "md" },
          { key: "hash", header: "Hash", render: (c) => <Tooltip label={`${c.old_sha256 ?? "—"} → ${c.new_sha256 ?? "—"}`}><Text size="xs" className="cw-mono">{shortHash(c.new_sha256 ?? c.old_sha256)}</Text></Tooltip>, visibleFrom: "lg" },
          { key: "detected", header: "Detected", render: (c) => <Tooltip label={fmtDateTime(c.detected_at)}><Text size="sm">{fmtRelative(c.detected_at)}</Text></Tooltip> },
        ]}
      />
    </Card>
  );
}

function InventoryTable({ websiteId }: { websiteId: string }) {
  const tid = useTenantId();
  const [q, setQ] = useState("");
  const [state, setState] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [sort, setSort] = useState("path");
  const list = useQuery({
    queryKey: ["inventory", tid, websiteId, q, state, page, sort],
    queryFn: () => api.get<Page<InventoryItem>>(`/tenants/${tid}/websites/${websiteId}/inventory`, { q, state: state ?? undefined, page, page_size: 50, sort }),
  });
  return (
    <Card>
      <Group mb="md" gap="sm">
        <SearchInput value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Filter by path" />
        <Select placeholder="State" clearable w={170} value={state} onChange={setState} aria-label="State"
          data={[{ value: "present", label: "Present" }, { value: "deleted", label: "Deleted (observed)" }, { value: "unverified", label: "Not observed (incomplete scan)" }]} />
      </Group>
      <DataTable<InventoryItem>
        rows={list.data?.items}
        loading={list.isLoading}
        error={list.error}
        rowKey={(i) => i.path}
        page={page}
        pageSize={50}
        total={list.data?.total}
        onPage={setPage}
        sort={sort}
        onSort={setSort}
        empty={<EmptyState title="No inventory yet" description="Run a file scan to build the inventory." />}
        columns={[
          { key: "path", header: "Path", sortable: true, render: (i) => <Text className="cw-mono">{i.path}{i.entry_type === "dir" ? "/" : ""}</Text> },
          { key: "state", header: "State", render: (i) => <HealthBadge state={i.state === "present" ? "active" : i.state === "deleted" ? "failed" : "unknown"} tooltip={i.state === "unverified" ? "Not observed in the last scan because part of the scan was incomplete. Not reported as deleted." : undefined} /> },
          { key: "size", header: "Size", sortable: true, render: (i) => <Text size="sm">{fmtBytes(i.size)}</Text>, visibleFrom: "sm" },
          { key: "sha256", header: "SHA-256", render: (i) => <Tooltip label={i.sha256 ?? humanize(i.hash_status)}><Text size="xs" className="cw-mono">{i.sha256 ? shortHash(i.sha256) : humanize(i.hash_status)}</Text></Tooltip>, visibleFrom: "md" },
          { key: "mtime", header: "Modified", sortable: true, render: (i) => <Text size="sm">{fmtDateTime(i.mtime)}</Text>, visibleFrom: "lg" },
          { key: "first_seen_at", header: "First seen", sortable: true, render: (i) => <Text size="sm">{fmtDateTime(i.first_seen_at)}</Text>, visibleFrom: "lg" },
          { key: "last_seen_at", header: "Last seen", sortable: true, render: (i) => <Text size="sm">{fmtRelative(i.last_seen_at)}</Text> },
        ]}
      />
    </Card>
  );
}

function ComparePanel({ websiteId }: { websiteId: string }) {
  const tid = useTenantId();
  const q = useQuery({
    queryKey: ["compare", tid, websiteId],
    queryFn: () =>
      api.get<{ total_changes: number; unverified_missing: number; withheld_reason: string | null; base: { started_at: string; status: string }; target: { started_at: string; status: string }; changes: { path: string; old_path: string | null; change_type: string; severity: string; flags: string[] }[] }>(
        `/tenants/${tid}/websites/${websiteId}/compare`,
      ),
    retry: false,
  });
  if (q.error) return <Card><EmptyState title="Comparison unavailable" description={errorMessage(q.error)} /></Card>;
  return (
    <Card>
      {q.data && (
        <Text size="sm" c="dimmed" mb="md">
          Baseline from {fmtDateTime(q.data.base.started_at)} compared with the latest scan from {fmtDateTime(q.data.target.started_at)} (<ScanBadge status={q.data.target.status} />).
          {" "}{q.data.total_changes} difference(s){q.data.unverified_missing ? `, ${q.data.unverified_missing} path(s) not observed due to incomplete scanning` : ""}.
        </Text>
      )}
      <DataTable
        rows={q.data?.changes}
        loading={q.isLoading}
        rowKey={(c) => c.path + c.change_type}
        empty={<EmptyState title="No differences from the baseline" />}
        columns={[
          { key: "sev", header: "Severity", render: (c) => <SeverityBadge severity={c.severity} /> },
          { key: "path", header: "Path", render: (c) => <Text className="cw-mono">{c.path}</Text> },
          { key: "change", header: "Change", render: (c) => <Text size="sm">{humanize(c.change_type)}</Text> },
          { key: "flags", header: "Flags", render: (c) => <Text size="xs" c="dimmed">{c.flags.map(humanize).join(", ")}</Text>, visibleFrom: "md" },
        ]}
      />
    </Card>
  );
}

// ---------------------------------------------------------------- monitoring / jobs

export function MonitoringPage() {
  const tid = useTenantId();
  const can = useCan();
  const [status, setStatus] = useState<string | null>(null);
  const [type, setType] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const jobs = useQuery({
    queryKey: ["jobs", tid, status, type, page],
    queryFn: () => api.get<Page<Job>>(`/tenants/${tid}/jobs`, { status: status ?? undefined, job_type: type ?? undefined, page, page_size: 25 }),
    refetchInterval: 10_000,
  });
  const cancel = useMutation({
    mutationFn: (id: string) => api.post(`/tenants/${tid}/jobs/${id}/cancel`),
    onSuccess: () => jobs.refetch(),
    onError: (e) => notifications.show({ color: "threat", title: "Could not cancel", message: errorMessage(e) }),
  });
  return (
    <>
      <PageHeader
        title="Monitoring activity"
        description="Every scan and check is recorded with its actual outcome. Configure frequency and checks per website."
        crumbs={[{ label: "Overview", to: `/app/${tid}/overview` }, { label: "Monitoring" }]}
        actions={<Button component={Link} to={`/app/${tid}/websites`} variant="default">Configure websites</Button>}
      />
      <Card>
        <Group mb="md" gap="sm">
          <Select placeholder="Status" clearable w={150} value={status} onChange={setStatus} aria-label="Status"
            data={["queued", "running", "succeeded", "partial", "failed", "cancelled"].map((v) => ({ value: v, label: humanize(v) }))} />
          <Select placeholder="Type" clearable w={190} value={type} onChange={setType} aria-label="Job type"
            data={["file_scan", "availability", "tls", "connection_test"].map((v) => ({ value: v, label: humanize(v) }))} />
        </Group>
        <DataTable<Job>
          rows={jobs.data?.items}
          loading={jobs.isLoading}
          error={jobs.error}
          rowKey={(j) => j.id}
          page={page}
          pageSize={25}
          total={jobs.data?.total}
          onPage={setPage}
          empty={<EmptyState title="No monitoring activity yet" />}
          columns={[
            { key: "type", header: "Check", render: (j) => <Box><Text size="sm" fw={600}>{humanize(j.job_type)}</Text><Text size="xs" c="dimmed">{j.website_name ?? (j.hosting_account_id ? "Hosting connection" : "—")}</Text></Box> },
            { key: "status", header: "Outcome", render: (j) => <Tooltip label={j.error_message ?? ""} disabled={!j.error_message}><span><ScanBadge status={j.status} /></span></Tooltip> },
            { key: "trigger", header: "Trigger", render: (j) => <Text size="sm">{humanize(j.trigger)}</Text>, visibleFrom: "md" },
            { key: "queued", header: "Queued", render: (j) => <Text size="sm">{fmtRelative(j.queued_at)}</Text> },
            { key: "duration", header: "Duration", render: (j) => <Text size="sm">{j.duration_seconds !== null ? `${j.duration_seconds}s` : "—"}</Text>, visibleFrom: "sm" },
            { key: "attempts", header: "Attempts", render: (j) => <Text size="sm">{j.attempts}/{j.max_attempts}</Text>, visibleFrom: "lg" },
            { key: "error", header: "Detail", render: (j) => <Text size="xs" c="dimmed" lineClamp={2}>{j.error_message ?? (j.result_summary?.files_seen !== undefined ? `${j.result_summary.files_seen} files · ${j.result_summary.changes ?? 0} changes` : "")}</Text>, visibleFrom: "md" },
            { key: "actions", header: "", render: (j) => can("scans:run") && (j.status === "queued" || j.status === "running") ? <Anchor component="button" size="sm" onClick={() => cancel.mutate(j.id)}>Cancel</Anchor> : null },
          ]}
        />
      </Card>
    </>
  );
}
