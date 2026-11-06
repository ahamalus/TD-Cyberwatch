import {
  Alert,
  Anchor,
  Badge,
  Box,
  Button,
  Card,
  Code,
  Grid,
  Group,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Stepper,
  Switch,
  Table,
  Tabs,
  TagsInput,
  Text,
  TextInput,
  Textarea,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconAlertTriangle,
  IconCertificate,
  IconFileDiff,
  IconInfoCircle,
  IconPlayerPause,
  IconPlayerPlay,
  IconPlus,
  IconRefresh,
  IconTrash,
  IconWorld,
} from "@tabler/icons-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useCan, useTenant, useTenantId } from "../../api/auth";
import { api, errorMessage } from "../../api/client";
import type { HostingAccount, MonitoringConfig, Page, Snapshot, Website } from "../../api/types";
import { fmtBytes, fmtDateTime, fmtNumber, fmtRelative, humanize } from "../../components/format";
import { HealthBadge, ScanBadge } from "../../components/status";
import {
  ConfirmButton,
  DataTable,
  EmptyState,
  ErrorState,
  KeyValue,
  LoadingBlock,
  PageHeader,
  SearchInput,
  Section,
} from "../../components/ui";

function useWebsites(params: Record<string, string | number | undefined>) {
  const tid = useTenantId();
  return useQuery({
    queryKey: ["websites", tid, params],
    queryFn: () => api.get<Page<Website>>(`/tenants/${tid}/websites`, params),
  });
}

export function WebsitesPage() {
  const tid = useTenantId();
  const can = useCan();
  const tenant = useTenant();
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [env, setEnv] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [sort, setSort] = useState("name");
  const list = useWebsites({ q, status: status ?? undefined, environment: env ?? undefined, page, page_size: 25, sort });
  const limit = Number(tenant.data?.entitlements.max_websites ?? 0);
  const used = tenant.data?.usage.websites ?? 0;
  const atLimit = tenant.data && used >= limit;

  return (
    <>
      <PageHeader
        title="Websites"
        description="Websites and domains monitored for your organisation. Coverage shows which checks are actually running."
        crumbs={[{ label: "Overview", to: `/app/${tid}/overview` }, { label: "Websites" }]}
        actions={
          can("websites:manage") && (
            <Tooltip label={atLimit ? `Plan limit reached (${used}/${limit}). Upgrade to add more.` : `${used} of ${limit} websites used`}>
              <Button component={Link} to={`/app/${tid}/websites/new`} leftSection={<IconPlus size={16} />} disabled={!!atLimit}>
                Add website
              </Button>
            </Tooltip>
          )
        }
      />
      {tenant.data && limit > 0 && used / limit >= 0.8 && !atLimit && (
        <Alert color="amber" variant="light" mb="md" icon={<IconInfoCircle />}>
          You are using {used} of {limit} websites in your {tenant.data.plan.name} plan.
        </Alert>
      )}
      <Card>
        <Group mb="md" gap="sm" wrap="wrap">
          <SearchInput value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Search name or hostname" />
          <Select placeholder="Status" clearable data={[{ value: "active", label: "Active" }, { value: "paused", label: "Paused" }]} value={status} onChange={setStatus} w={140} aria-label="Filter by status" />
          <Select
            placeholder="Environment"
            clearable
            data={["production", "staging", "development", "other"].map((v) => ({ value: v, label: humanize(v) }))}
            value={env}
            onChange={setEnv}
            w={170}
            aria-label="Filter by environment"
          />
        </Group>
        <DataTable<Website>
          rows={list.data?.items}
          loading={list.isLoading}
          error={list.error}
          onRetry={() => list.refetch()}
          rowKey={(w) => w.id}
          onRowClick={(w) => navigate(`/app/${tid}/websites/${w.id}`)}
          page={page}
          pageSize={25}
          total={list.data?.total}
          onPage={setPage}
          sort={sort}
          onSort={setSort}
          empty={
            <EmptyState
              icon={IconWorld}
              title="No websites yet"
              description="Add a website to start availability and TLS monitoring, then connect its hosting for file integrity."
              action={can("websites:manage") && <Button component={Link} to={`/app/${tid}/websites/new`}>Add your first website</Button>}
            />
          }
          columns={[
            {
              key: "name",
              header: "Website",
              sortable: true,
              render: (w) => (
                <Box>
                  <Text fw={600} size="sm">
                    {w.name}
                  </Text>
                  <Text size="xs" c="dimmed">
                    {w.url}
                  </Text>
                </Box>
              ),
            },
            { key: "coverage", header: "Coverage", render: (w) => <HealthBadge state={w.status === "paused" ? "paused" : w.coverage?.overall} tooltip={w.coverage?.reasons.join(" ") || undefined} /> },
            {
              key: "last_scan_at",
              header: "Last file scan",
              sortable: true,
              render: (w) => (
                <Box>
                  <ScanBadge status={w.last_scan_status} />
                  <Text size="xs" c="dimmed">
                    {fmtRelative(w.last_scan_at)}
                  </Text>
                </Box>
              ),
            },
            { key: "availability", header: "Availability", render: (w) => <HealthBadge state={w.last_availability_status ?? "unknown"} />, visibleFrom: "md" },
            { key: "tls", header: "TLS", render: (w) => <HealthBadge state={w.last_tls_status ?? (w.url.startsWith("https") ? "unknown" : "not_applicable")} />, visibleFrom: "md" },
            { key: "hosting", header: "Hosting", render: (w) => <Text size="sm">{w.hosting_account_name ?? "—"}</Text>, visibleFrom: "lg" },
            { key: "environment", header: "Env", render: (w) => <Badge variant="outline" color="gray">{humanize(w.environment)}</Badge>, visibleFrom: "lg" },
          ]}
        />
      </Card>
    </>
  );
}

// ---------------------------------------------------------------- onboarding wizard

export function NewWebsitePage() {
  const tid = useTenantId();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [step, setStep] = useState(0);
  const [form, setForm] = useState({ name: "", url: "https://", environment: "production", hosting_account_id: "", document_root: "", technology: "", group_id: "" });
  const [error, setError] = useState<string | null>(null);
  const hosting = useQuery({ queryKey: ["hosting", tid], queryFn: () => api.get<HostingAccount[]>(`/tenants/${tid}/hosting-accounts`) });
  const groups = useQuery({ queryKey: ["groups", tid], queryFn: () => api.get<{ id: string; name: string }[]>(`/tenants/${tid}/groups`) });
  const create = useMutation({
    mutationFn: () =>
      api.post<Website>(`/tenants/${tid}/websites`, {
        name: form.name,
        url: form.url,
        environment: form.environment,
        hosting_account_id: form.hosting_account_id || null,
        document_root: form.document_root || null,
        technology: form.technology || null,
        group_id: form.group_id || null,
      }),
    onSuccess: (w) => {
      qc.invalidateQueries({ queryKey: ["websites", tid] });
      qc.invalidateQueries({ queryKey: ["tenant", tid] });
      notifications.show({ color: "secure", title: "Website added", message: "Configure monitoring to start checks." });
      navigate(`/app/${tid}/websites/${w.id}?tab=monitoring`);
    },
    onError: (e) => setError(errorMessage(e)),
  });
  const selected = hosting.data?.find((h) => h.id === form.hosting_account_id);
  const fileCap = selected?.capabilities.find((c) => c.capability === "file_listing");

  return (
    <>
      <PageHeader
        title="Add a website"
        description="Register the website, optionally associate the hosting account that serves its files, then choose checks."
        crumbs={[{ label: "Websites", to: `/app/${tid}/websites` }, { label: "Add website" }]}
      />
      <Card maw={820}>
        <Stepper active={step} onStepClick={setStep} allowNextStepsSelect={false} size="sm">
          <Stepper.Step label="Website" description="Name and URL">
            <Stack mt="md">
              <TextInput label="Display name" required value={form.name} onChange={(e) => setForm({ ...form, name: e.currentTarget.value })} />
              <TextInput
                label="Website URL"
                description="Public http(s) address. Internal and private network addresses are not allowed."
                required
                value={form.url}
                onChange={(e) => setForm({ ...form, url: e.currentTarget.value })}
              />
              <Group grow>
                <Select
                  label="Environment"
                  data={["production", "staging", "development", "other"].map((v) => ({ value: v, label: humanize(v) }))}
                  value={form.environment}
                  onChange={(v) => setForm({ ...form, environment: v ?? "production" })}
                />
                <Select
                  label="Group (optional)"
                  clearable
                  data={(groups.data ?? []).map((g) => ({ value: g.id, label: g.name }))}
                  value={form.group_id || null}
                  onChange={(v) => setForm({ ...form, group_id: v ?? "" })}
                />
              </Group>
              <TextInput label="Technology (optional)" placeholder="e.g. WordPress, Laravel, static HTML" value={form.technology} onChange={(e) => setForm({ ...form, technology: e.currentTarget.value })} />
            </Stack>
          </Stepper.Step>
          <Stepper.Step label="Hosting" description="Where the files live">
            <Stack mt="md">
              <Text size="sm" c="dimmed">
                File-integrity monitoring requires a hosting connection with verified file listing. You can skip this and add it later; availability
                and TLS checks still work.
              </Text>
              {hosting.data && hosting.data.length === 0 && (
                <Alert icon={<IconInfoCircle />} variant="light">
                  No hosting connections yet. <Anchor component={Link} to={`/app/${tid}/hosting/new`}>Connect a hosting account</Anchor> first if you
                  want file monitoring.
                </Alert>
              )}
              <Select
                label="Hosting connection"
                clearable
                data={(hosting.data ?? []).map((h) => ({ value: h.id, label: `${h.name} — ${h.connector_name} (${h.hostname})` }))}
                value={form.hosting_account_id || null}
                onChange={(v) => setForm({ ...form, hosting_account_id: v ?? "" })}
              />
              {selected && (
                <Alert
                  color={fileCap?.status === "available" ? "secure" : "amber"}
                  variant="light"
                  icon={fileCap?.status === "available" ? <IconFileDiff /> : <IconAlertTriangle />}
                >
                  {fileCap?.status === "available"
                    ? `File listing verified on ${selected.root_path}. Hashing: ${selected.capabilities.find((c) => c.capability === "file_hashing")?.status}.`
                    : "File listing has not been verified for this connection. Test the connection before enabling file scans."}
                </Alert>
              )}
              <TextInput
                label="Document root (relative to the connection root)"
                description={selected ? `Leave empty to monitor ${selected.root_path} itself.` : "Leave empty to use the connection root."}
                placeholder="e.g. blog or subdomain/shop"
                value={form.document_root}
                onChange={(e) => setForm({ ...form, document_root: e.currentTarget.value })}
                disabled={!selected}
              />
            </Stack>
          </Stepper.Step>
          <Stepper.Step label="Review" description="Confirm">
            <Stack mt="md">
              <KeyValue
                items={[
                  ["Name", form.name || "—"],
                  ["URL", form.url],
                  ["Environment", humanize(form.environment)],
                  ["Hosting", selected ? selected.name : "Not associated (availability and TLS only)"],
                  ["Document root", form.document_root || "Connection root"],
                ]}
              />
              <Text size="xs" c="dimmed">
                Monitoring is read-only. CyberWatch never modifies, deletes or quarantines your files.
              </Text>
              {error && (
                <Alert color="threat" variant="light" role="alert">
                  {error}
                </Alert>
              )}
            </Stack>
          </Stepper.Step>
        </Stepper>
        <Group justify="space-between" mt="xl">
          <Button variant="default" onClick={() => (step === 0 ? navigate(-1) : setStep(step - 1))}>
            {step === 0 ? "Cancel" : "Back"}
          </Button>
          {step < 2 ? (
            <Button onClick={() => setStep(step + 1)} disabled={step === 0 && (!form.name || form.url.length < 10)}>
              Continue
            </Button>
          ) : (
            <Button onClick={() => create.mutate()} loading={create.isPending}>
              Add website
            </Button>
          )}
        </Group>
      </Card>
    </>
  );
}

// ---------------------------------------------------------------- website detail

export function WebsiteDetailPage() {
  const tid = useTenantId();
  const { websiteId } = useParams();
  const can = useCan();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const params = new URLSearchParams(window.location.search);
  const [tab, setTab] = useState<string | null>(params.get("tab") ?? "overview");
  const site = useQuery({ queryKey: ["website", tid, websiteId], queryFn: () => api.get<Website>(`/tenants/${tid}/websites/${websiteId}`) });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["website", tid, websiteId] });
    qc.invalidateQueries({ queryKey: ["websites", tid] });
  };
  const runCheck = useMutation({
    mutationFn: (check: string) => api.post<{ message: string }>(`/tenants/${tid}/websites/${websiteId}/checks`, { check }),
    onSuccess: (r) => {
      notifications.show({ color: "cyber", title: "Check requested", message: r.message });
      setTimeout(refresh, 4000);
    },
    onError: (e) => notifications.show({ color: "threat", title: "Could not start check", message: errorMessage(e) }),
  });
  const toggle = useMutation({
    mutationFn: (action: "pause" | "resume") => api.post(`/tenants/${tid}/websites/${websiteId}/${action}`),
    onSuccess: refresh,
  });
  const remove = useMutation({
    mutationFn: () => api.del(`/tenants/${tid}/websites/${websiteId}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["websites", tid] });
      navigate(`/app/${tid}/websites`);
    },
  });

  if (site.error) return <ErrorState error={site.error} onRetry={() => site.refetch()} />;
  if (!site.data) return <LoadingBlock rows={8} />;
  const w = site.data;
  const cov = w.coverage;

  return (
    <>
      <PageHeader
        title={w.name}
        description={
          <Group gap="xs">
            <Anchor href={w.url} target="_blank" rel="noopener noreferrer" size="sm">
              {w.url}
            </Anchor>
            <HealthBadge state={w.status === "paused" ? "paused" : cov?.overall} />
          </Group>
        }
        crumbs={[{ label: "Websites", to: `/app/${tid}/websites` }, { label: w.name }]}
        actions={
          <>
            {can("scans:run") && (
              <Button.Group>
                <Button variant="default" leftSection={<IconRefresh size={16} />} loading={runCheck.isPending} onClick={() => runCheck.mutate("availability")}>
                  Check availability
                </Button>
                <Button variant="default" disabled={!w.hosting_account_id} onClick={() => runCheck.mutate("file_scan")}>
                  Scan files
                </Button>
                {w.url.startsWith("https") && (
                  <Button variant="default" onClick={() => runCheck.mutate("tls")}>
                    Check TLS
                  </Button>
                )}
              </Button.Group>
            )}
            {can("websites:manage") &&
              (w.status === "active" ? (
                <Button variant="subtle" color="gray" leftSection={<IconPlayerPause size={16} />} onClick={() => toggle.mutate("pause")}>
                  Pause
                </Button>
              ) : (
                <Button variant="subtle" leftSection={<IconPlayerPlay size={16} />} onClick={() => toggle.mutate("resume")}>
                  Resume
                </Button>
              ))}
          </>
        }
      />

      <Tabs value={tab} onChange={setTab} keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="overview">Overview</Tabs.Tab>
          <Tabs.Tab value="monitoring">Monitoring settings</Tabs.Tab>
          <Tabs.Tab value="scans">File scans</Tabs.Tab>
          <Tabs.Tab value="availability">Availability & TLS</Tabs.Tab>
          <Tabs.Tab value="settings">Details</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="overview">
          <Grid>
            <Grid.Col span={{ base: 12, md: 7 }}>
              <Section title="Monitoring coverage" description="Only verified, enabled checks count as active.">
                <Stack gap="sm">
                  {cov?.checks.map((c) => (
                    <Group key={c.key} justify="space-between" wrap="nowrap" align="flex-start">
                      <Box>
                        <Text size="sm" fw={600}>
                          {c.label}
                        </Text>
                        <Text size="xs" c="dimmed">
                          {c.detail}
                          {c.last_success ? ` Last success ${fmtRelative(c.last_success)}.` : ""}
                        </Text>
                      </Box>
                      <HealthBadge state={c.state} />
                    </Group>
                  ))}
                </Stack>
                {cov && cov.reasons.length > 0 && (
                  <Alert mt="md" color="amber" variant="light" icon={<IconInfoCircle />} title="Why monitoring is partial">
                    <Stack gap={2}>
                      {cov.reasons.map((r) => (
                        <Text key={r} size="sm">
                          {r}
                        </Text>
                      ))}
                    </Stack>
                  </Alert>
                )}
              </Section>
            </Grid.Col>
            <Grid.Col span={{ base: 12, md: 5 }}>
              <Section title="Status">
                <KeyValue
                  items={[
                    ["Last file scan", <Group gap={6} justify="flex-end" key="s"><ScanBadge status={w.last_scan_status} /><Text size="xs" c="dimmed">{fmtRelative(w.last_scan_at)}</Text></Group>],
                    ["Last successful scan", fmtDateTime(w.last_successful_scan_at)],
                    ["Baseline", w.baseline_snapshot_id ? `Approved ${fmtDateTime(w.baseline_approved_at)}` : "Not yet established"],
                    ["Availability", <HealthBadge key="a" state={w.last_availability_status ?? "unknown"} />],
                    ["Last availability check", fmtRelative(w.last_availability_at)],
                    ["TLS certificate", <HealthBadge key="t" state={w.last_tls_status ?? "unknown"} />],
                    ["Certificate expires", fmtDateTime(w.tls_expires_at)],
                    ["Hosting", w.hosting_account_id ? <Anchor key="h" component={Link} to={`/app/${tid}/hosting/${w.hosting_account_id}`} size="sm">{w.hosting_account_name}</Anchor> : "Not associated"],
                    ["Ownership", <Badge key="v" color={w.verification_status === "verified" ? "secure" : "gray"}>{humanize(w.verification_status)}</Badge>],
                  ]}
                />
              </Section>
            </Grid.Col>
          </Grid>
          <Box mt="md">
            <Anchor component={Link} to={`/app/${tid}/files?website=${w.id}`} size="sm">
              View change history and inventory for this website →
            </Anchor>
          </Box>
        </Tabs.Panel>

        <Tabs.Panel value="monitoring">
          <MonitoringForm site={w} onSaved={refresh} />
        </Tabs.Panel>

        <Tabs.Panel value="scans">
          <SnapshotsPanel site={w} onBaseline={refresh} />
        </Tabs.Panel>

        <Tabs.Panel value="availability">
          <AvailabilityPanel websiteId={w.id} />
        </Tabs.Panel>

        <Tabs.Panel value="settings">
          <WebsiteDetailsForm site={w} onSaved={refresh} />
          {can("websites:manage") && (
            <Card mt="md" style={{ borderColor: "var(--cw-red)" }}>
              <Group justify="space-between">
                <Box>
                  <Text fw={600}>Remove website</Text>
                  <Text size="sm" c="dimmed">
                    Deletes this website and its monitoring history from CyberWatch. Nothing on your server is changed.
                  </Text>
                </Box>
                <ConfirmButton
                  danger
                  variant="light"
                  leftSection={<IconTrash size={16} />}
                  title="Remove this website?"
                  message={`${w.name} and all of its scans, change history and checks will be permanently deleted from CyberWatch.`}
                  confirmLabel="Remove website"
                  onConfirm={() => remove.mutateAsync()}
                >
                  Remove
                </ConfirmButton>
              </Group>
            </Card>
          )}
        </Tabs.Panel>
      </Tabs>
    </>
  );
}

function MonitoringForm({ site, onSaved }: { site: Website; onSaved: () => void }) {
  const tid = useTenantId();
  const can = useCan();
  const tenant = useTenant();
  const [cfg, setCfg] = useState<MonitoringConfig>(
    site.monitoring ?? {
      file_scan_enabled: false,
      file_scan_interval_minutes: 1440,
      availability_enabled: true,
      availability_interval_minutes: 15,
      tls_enabled: true,
      tls_expiry_warning_days: 21,
      availability_failure_threshold: 2,
      slow_response_ms: 5000,
      incident_min_severity: "medium",
      exclusions: [],
      critical_paths: [],
      max_file_bytes: null,
      max_total_mb: null,
      max_files: null,
      maintenance_windows: [],
    },
  );
  const save = useMutation({
    mutationFn: () => api.put(`/tenants/${tid}/websites/${site.id}/monitoring`, cfg),
    onSuccess: () => {
      notifications.show({ color: "secure", title: "Monitoring updated", message: "New settings apply from the next scheduled run." });
      onSaved();
    },
    onError: (e) => notifications.show({ color: "threat", title: "Not saved", message: errorMessage(e) }),
  });
  const fileCheck = site.coverage?.checks.find((c) => c.key === "file_integrity");
  const fileAvailable = fileCheck && fileCheck.state !== "unavailable";
  const minFs = Number(tenant.data?.entitlements.min_file_scan_interval_minutes ?? 1440);
  const minAv = Number(tenant.data?.entitlements.min_availability_interval_minutes ?? 15);
  const disabled = !can("monitoring:manage");

  return (
    <Stack gap="md">
      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Section title="File integrity" description="SHA-256 inventory compared with the previous scan and the approved baseline.">
          {!fileAvailable && (
            <Alert color="gray" variant="light" mb="sm" icon={<IconInfoCircle />}>
              {fileCheck?.detail ?? "Unavailable."} File scanning cannot be enabled until a hosting connection verifies file listing.
            </Alert>
          )}
          <Stack>
            <Switch
              label="Enable scheduled file-integrity scans"
              checked={cfg.file_scan_enabled}
              disabled={disabled || !fileAvailable}
              onChange={(e) => setCfg({ ...cfg, file_scan_enabled: e.currentTarget.checked })}
            />
            <NumberInput
              label="Scan interval (minutes)"
              description={`Your plan allows every ${minFs} minutes or longer.`}
              min={minFs}
              step={60}
              value={cfg.file_scan_interval_minutes}
              disabled={disabled}
              onChange={(v) => setCfg({ ...cfg, file_scan_interval_minutes: Number(v) || minFs })}
            />
            <Select
              label="Open an incident for changes rated at least"
              data={["critical", "high", "medium", "low"].map((v) => ({ value: v, label: humanize(v) }))}
              value={cfg.incident_min_severity}
              disabled={disabled}
              onChange={(v) => setCfg({ ...cfg, incident_min_severity: v ?? "medium" })}
            />
            <TagsInput
              label="Exclusions"
              description="Glob patterns relative to the document root, e.g. wp-content/cache/**"
              value={cfg.exclusions}
              disabled={disabled}
              onChange={(v) => setCfg({ ...cfg, exclusions: v })}
            />
            <TagsInput
              label="Critical paths"
              description="Changes here are rated high severity, e.g. wp-config.php, admin/**"
              value={cfg.critical_paths}
              disabled={disabled}
              onChange={(v) => setCfg({ ...cfg, critical_paths: v })}
            />
            <Group grow>
              <NumberInput label="Max file size (bytes)" placeholder="Platform default" value={cfg.max_file_bytes ?? ""} disabled={disabled} onChange={(v) => setCfg({ ...cfg, max_file_bytes: v === "" ? null : Number(v) })} />
              <NumberInput label="Scan budget (MB)" placeholder="Platform default" value={cfg.max_total_mb ?? ""} disabled={disabled} onChange={(v) => setCfg({ ...cfg, max_total_mb: v === "" ? null : Number(v) })} />
              <NumberInput label="Max files" placeholder="Platform default" value={cfg.max_files ?? ""} disabled={disabled} onChange={(v) => setCfg({ ...cfg, max_files: v === "" ? null : Number(v) })} />
            </Group>
          </Stack>
        </Section>
        <Stack gap="md">
          <Section title="Availability and TLS" description="Checks run from the CyberWatch platform over the public internet.">
            <Stack>
              <Switch label="Enable availability checks" checked={cfg.availability_enabled} disabled={disabled} onChange={(e) => setCfg({ ...cfg, availability_enabled: e.currentTarget.checked })} />
              <NumberInput
                label="Check interval (minutes)"
                description={`Plan minimum: ${minAv} minutes.`}
                min={minAv}
                value={cfg.availability_interval_minutes}
                disabled={disabled}
                onChange={(v) => setCfg({ ...cfg, availability_interval_minutes: Number(v) || minAv })}
              />
              <Group grow>
                <NumberInput label="Failures before incident" min={1} max={10} value={cfg.availability_failure_threshold} disabled={disabled} onChange={(v) => setCfg({ ...cfg, availability_failure_threshold: Number(v) || 2 })} />
                <NumberInput label="Slow response (ms)" min={500} step={500} value={cfg.slow_response_ms} disabled={disabled} onChange={(v) => setCfg({ ...cfg, slow_response_ms: Number(v) || 5000 })} />
              </Group>
              <Switch label="Check TLS certificate" checked={cfg.tls_enabled} disabled={disabled || !site.url.startsWith("https")} onChange={(e) => setCfg({ ...cfg, tls_enabled: e.currentTarget.checked })} />
              <NumberInput label="Warn when certificate expires within (days)" min={1} max={90} value={cfg.tls_expiry_warning_days} disabled={disabled} onChange={(v) => setCfg({ ...cfg, tls_expiry_warning_days: Number(v) || 21 })} />
            </Stack>
          </Section>
          <Section title="Maintenance windows" description="Scheduled checks are deferred during these windows.">
            <Stack gap="xs">
              {cfg.maintenance_windows.map((mw, i) => (
                <Group key={i} gap="xs" wrap="nowrap">
                  <Select
                    aria-label="Day"
                    w={130}
                    data={[{ value: "", label: "Every day" }, ...["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map((d, idx) => ({ value: String(idx), label: d }))]}
                    value={mw.weekday === null ? "" : String(mw.weekday)}
                    disabled={disabled}
                    onChange={(v) => {
                      const next = [...cfg.maintenance_windows];
                      next[i] = { ...mw, weekday: v === "" || v === null ? null : Number(v) };
                      setCfg({ ...cfg, maintenance_windows: next });
                    }}
                  />
                  <TextInput aria-label="Start time" w={90} value={mw.start} disabled={disabled} onChange={(e) => { const next = [...cfg.maintenance_windows]; next[i] = { ...mw, start: e.currentTarget.value }; setCfg({ ...cfg, maintenance_windows: next }); }} />
                  <Text size="sm">to</Text>
                  <TextInput aria-label="End time" w={90} value={mw.end} disabled={disabled} onChange={(e) => { const next = [...cfg.maintenance_windows]; next[i] = { ...mw, end: e.currentTarget.value }; setCfg({ ...cfg, maintenance_windows: next }); }} />
                  <Button variant="subtle" color="gray" size="xs" disabled={disabled} onClick={() => setCfg({ ...cfg, maintenance_windows: cfg.maintenance_windows.filter((_, j) => j !== i) })} aria-label="Remove window">
                    <IconTrash size={14} />
                  </Button>
                </Group>
              ))}
              <Button variant="light" size="xs" w="fit-content" disabled={disabled} onClick={() => setCfg({ ...cfg, maintenance_windows: [...cfg.maintenance_windows, { start: "01:00", end: "03:00", weekday: null, timezone: tenant.data?.timezone ?? "Africa/Lagos" }] })}>
                Add window
              </Button>
              <Text size="xs" c="dimmed">
                Times use the {tenant.data?.timezone ?? "Africa/Lagos"} timezone.
              </Text>
            </Stack>
          </Section>
        </Stack>
      </SimpleGrid>
      <Alert variant="light" color="info" icon={<IconInfoCircle />}>
        Polling-based monitoring detects changes that exist at scan time. It cannot guarantee detection of short-lived changes between scans.
      </Alert>
      {can("monitoring:manage") && (
        <Group justify="flex-end">
          <Button onClick={() => save.mutate()} loading={save.isPending}>
            Save monitoring settings
          </Button>
        </Group>
      )}
    </Stack>
  );
}

function SnapshotsPanel({ site, onBaseline }: { site: Website; onBaseline: () => void }) {
  const tid = useTenantId();
  const can = useCan();
  const [page, setPage] = useState(1);
  const snaps = useQuery({
    queryKey: ["snapshots", tid, site.id, page],
    queryFn: () => api.get<Page<Snapshot>>(`/tenants/${tid}/websites/${site.id}/snapshots`, { page, page_size: 15 }),
  });
  const approve = useMutation({
    mutationFn: (s: Snapshot) => api.post(`/tenants/${tid}/websites/${site.id}/baseline`, { snapshot_id: s.id, reason: "Approved from scan history" }),
    onSuccess: () => {
      notifications.show({ color: "secure", title: "Baseline approved", message: "Future comparisons use this snapshot." });
      snaps.refetch();
      onBaseline();
    },
    onError: (e) => notifications.show({ color: "threat", title: "Not approved", message: errorMessage(e) }),
  });
  return (
    <Card>
      <Text size="sm" c="dimmed" mb="md">
        Each scan records an inventory snapshot. Failed scans never produce deletion findings; partial scans mark unreachable paths as
        unverified rather than deleted.
      </Text>
      <DataTable<Snapshot>
        rows={snaps.data?.items}
        loading={snaps.isLoading}
        error={snaps.error}
        rowKey={(s) => s.id}
        page={page}
        pageSize={15}
        total={snaps.data?.total}
        onPage={setPage}
        empty={<EmptyState title="No scans yet" description="Enable file scans in Monitoring settings or run a scan now." />}
        columns={[
          {
            key: "started",
            header: "Started",
            render: (s) => (
              <Box>
                <Text size="sm">{fmtDateTime(s.started_at)}</Text>
                {s.is_baseline && <Badge size="xs" color="cyber">Baseline</Badge>}
              </Box>
            ),
          },
          { key: "status", header: "Result", render: (s) => <Tooltip label={s.failure_reason ?? (s.limits_hit.length ? `Limits hit: ${s.limits_hit.join(", ")}` : "Completed")}><span><ScanBadge status={s.status} /></span></Tooltip> },
          { key: "files", header: "Files", render: (s) => <Text size="sm">{fmtNumber(s.files_seen)} <Text span size="xs" c="dimmed">({fmtNumber(s.files_hashed)} hashed)</Text></Text> },
          {
            key: "changes",
            header: "Changes",
            render: (s) => (
              <Text size="sm">
                +{s.changes_added} ~{s.changes_modified} −{s.changes_deleted}
                {s.changes_renamed ? ` ↻${s.changes_renamed}` : ""}
                {s.deletions_unverified ? <Text span size="xs" c="amber.8"> · {s.deletions_unverified} unverified</Text> : null}
              </Text>
            ),
          },
          { key: "errors", header: "Errors", render: (s) => <Text size="sm" c={s.error_count ? "amber.8" : undefined}>{s.error_count}</Text>, visibleFrom: "md" },
          { key: "bytes", header: "Hashed", render: (s) => <Text size="sm">{fmtBytes(s.bytes_hashed)}</Text>, visibleFrom: "lg" },
          {
            key: "actions",
            header: "",
            render: (s) =>
              can("baseline:approve") && !s.is_baseline && s.status !== "failed" && s.status !== "running" ? (
                <ConfirmButton
                  size="xs"
                  variant="subtle"
                  title="Approve as trusted baseline?"
                  message="Approve this snapshot only if you have confirmed every change since the previous baseline was authorised. This action is recorded in the audit trail."
                  confirmLabel="Approve baseline"
                  onConfirm={() => approve.mutateAsync(s)}
                >
                  Set as baseline
                </ConfirmButton>
              ) : null,
          },
        ]}
      />
    </Card>
  );
}

function AvailabilityPanel({ websiteId }: { websiteId: string }) {
  const tid = useTenantId();
  const av = useQuery({
    queryKey: ["availability", tid, websiteId],
    queryFn: () => api.get<{ checked_at: string; outcome: string; http_status: number | null; response_ms: number | null; error_message: string | null }[]>(`/tenants/${tid}/websites/${websiteId}/availability`, { limit: 50 }),
  });
  const tls = useQuery({
    queryKey: ["tls", tid, websiteId],
    queryFn: () => api.get<{ checked_at: string; outcome: string; valid_to: string | null; days_remaining: number | null; issuer: string | null; error_message: string | null; protocol: string | null }[]>(`/tenants/${tid}/websites/${websiteId}/tls`, { limit: 10 }),
  });
  const latestTls = tls.data?.[0];
  const up = av.data?.filter((a) => a.outcome === "up" || a.outcome === "degraded").length ?? 0;
  const pct = av.data?.length ? Math.round((up / av.data.length) * 1000) / 10 : null;
  return (
    <Grid>
      <Grid.Col span={{ base: 12, md: 8 }}>
        <Section title="Recent availability checks" description={pct !== null ? `${pct}% reachable over the last ${av.data?.length} checks.` : undefined}>
          {av.isLoading ? (
            <LoadingBlock />
          ) : !av.data?.length ? (
            <EmptyState title="No checks recorded" description="Availability checks run on the configured interval." />
          ) : (
            <div className="cw-table-scroll">
              <Table miw={480}>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Checked</Table.Th>
                    <Table.Th>Result</Table.Th>
                    <Table.Th>HTTP</Table.Th>
                    <Table.Th>Response</Table.Th>
                    <Table.Th>Detail</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {av.data.map((a) => (
                    <Table.Tr key={a.checked_at}>
                      <Table.Td>{fmtDateTime(a.checked_at)}</Table.Td>
                      <Table.Td><HealthBadge state={a.outcome} /></Table.Td>
                      <Table.Td>{a.http_status ?? "—"}</Table.Td>
                      <Table.Td>{a.response_ms ? `${a.response_ms} ms` : "—"}</Table.Td>
                      <Table.Td><Text size="xs" c="dimmed">{a.error_message ?? ""}</Text></Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </div>
          )}
        </Section>
      </Grid.Col>
      <Grid.Col span={{ base: 12, md: 4 }}>
        <Section title="TLS certificate">
          {!latestTls ? (
            <EmptyState icon={IconCertificate} title="Not checked yet" />
          ) : (
            <KeyValue
              items={[
                ["Status", <HealthBadge key="s" state={latestTls.outcome} />],
                ["Expires", fmtDateTime(latestTls.valid_to)],
                ["Days remaining", latestTls.days_remaining ?? "—"],
                ["Issuer", latestTls.issuer ?? "—"],
                ["Protocol", latestTls.protocol ?? "—"],
                ["Checked", fmtRelative(latestTls.checked_at)],
              ]}
            />
          )}
          {latestTls?.error_message && (
            <Alert mt="sm" color="amber" variant="light">
              {latestTls.error_message}
            </Alert>
          )}
        </Section>
      </Grid.Col>
    </Grid>
  );
}

function WebsiteDetailsForm({ site, onSaved }: { site: Website; onSaved: () => void }) {
  const tid = useTenantId();
  const can = useCan();
  const [name, setName] = useState(site.name);
  const [technology, setTechnology] = useState(site.technology ?? "");
  const [notes, setNotes] = useState(site.notes ?? "");
  const verification = useQuery({
    queryKey: ["verification", tid, site.id],
    queryFn: () => api.get<{ status: string; path: string; token: string | null; message: string }>(`/tenants/${tid}/websites/${site.id}/verification`),
  });
  const save = useMutation({
    mutationFn: () => api.patch(`/tenants/${tid}/websites/${site.id}`, { name, technology: technology || null, notes: notes || null }),
    onSuccess: () => {
      notifications.show({ color: "secure", title: "Saved", message: "Website details updated." });
      onSaved();
    },
    onError: (e) => notifications.show({ color: "threat", title: "Not saved", message: errorMessage(e) }),
  });
  const verify = useMutation({
    mutationFn: () => api.post<{ status: string; message: string }>(`/tenants/${tid}/websites/${site.id}/verify`),
    onSuccess: (r) => {
      notifications.show({ color: r.status === "verified" ? "secure" : "amber", title: "Verification", message: r.message });
      verification.refetch();
      onSaved();
    },
  });
  return (
    <SimpleGrid cols={{ base: 1, md: 2 }}>
      <Section title="Details">
        <Stack>
          <TextInput label="Name" value={name} onChange={(e) => setName(e.currentTarget.value)} disabled={!can("websites:manage")} />
          <TextInput label="Technology" value={technology} onChange={(e) => setTechnology(e.currentTarget.value)} disabled={!can("websites:manage")} />
          <Textarea label="Notes" autosize minRows={3} value={notes} onChange={(e) => setNotes(e.currentTarget.value)} disabled={!can("websites:manage")} />
          <KeyValue items={[["Hostname", site.hostname], ["Environment", humanize(site.environment)], ["Document root", site.document_root ?? "Connection root"], ["Added", fmtDateTime(site.created_at)]]} />
          {can("websites:manage") && (
            <Button w="fit-content" onClick={() => save.mutate()} loading={save.isPending}>
              Save
            </Button>
          )}
        </Stack>
      </Section>
      <Section title="Ownership verification" description="Optional. Proves control of the website by publishing a token file.">
        {verification.data && (
          <Stack>
            <HealthBadge state={verification.data.status === "verified" ? "valid" : "pending"} />
            <Text size="sm">Publish a text file at:</Text>
            <Code block>{`${site.url.replace(/\/$/, "")}${verification.data.path}`}</Code>
            <Text size="sm">containing exactly:</Text>
            <Code block>{verification.data.token}</Code>
            {can("websites:manage") && (
              <Button variant="light" w="fit-content" onClick={() => verify.mutate()} loading={verify.isPending}>
                Verify now
              </Button>
            )}
          </Stack>
        )}
      </Section>
    </SimpleGrid>
  );
}

