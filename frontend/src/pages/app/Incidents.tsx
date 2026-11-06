import {
  Accordion,
  Alert,
  Anchor,
  Badge,
  Box,
  Button,
  Card,
  Checkbox,
  Code,
  Grid,
  Group,
  MultiSelect,
  Progress,
  ScrollArea,
  Select,
  Stack,
  Switch,
  Text,
  Textarea,
  Timeline,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconCircleCheck,
  IconFingerprint,
  IconLock,
  IconMessage,
  IconShieldExclamation,
  IconUser,
} from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useCan, useTenantId } from "../../api/auth";
import { api, errorMessage } from "../../api/client";
import type { Incident, IncidentDetail, Page } from "../../api/types";
import { fmtDateTime, fmtRelative, humanize, shortHash } from "../../components/format";
import { IncidentStatusBadge, SeverityBadge, VerificationBadge } from "../../components/status";
import { DataTable, EmptyState, ErrorState, KeyValue, LoadingBlock, PageHeader, SearchInput, Section } from "../../components/ui";

const SEVERITIES = ["critical", "high", "medium", "low", "informational"];
const CATEGORIES = ["file_integrity", "suspicious_file", "malware", "availability", "tls", "connection", "log_activity", "suspected_compromise", "other"];

export function IncidentsPage() {
  const tid = useTenantId();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [openOnly, setOpenOnly] = useState(params.get("open") === "1" || !params.has("open"));
  const [severity, setSeverity] = useState<string[]>([]);
  const [category, setCategory] = useState<string | null>(null);
  const [mine, setMine] = useState(false);
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [sort, setSort] = useState("-last_observed_at");
  const list = useQuery({
    queryKey: ["incidents", tid, openOnly, severity, category, mine, q, page, sort],
    queryFn: () =>
      api.get<Page<Incident>>(`/tenants/${tid}/incidents`, {
        open_only: openOnly,
        severity,
        category: category ?? undefined,
        assigned_to_me: mine,
        q,
        page,
        page_size: 25,
        sort,
      }),
  });
  return (
    <>
      <PageHeader
        title="Incident centre"
        description="Detections from file-integrity, availability, TLS and connection monitoring. Heuristic findings require human verification."
        crumbs={[{ label: "Overview", to: `/app/${tid}/overview` }, { label: "Incidents" }]}
      />
      <Card>
        <Group mb="md" gap="sm" wrap="wrap">
          <SearchInput value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Search title or reference" />
          <MultiSelect placeholder="Severity" data={SEVERITIES.map((s) => ({ value: s, label: humanize(s) }))} value={severity} onChange={setSeverity} clearable w={220} aria-label="Filter by severity" />
          <Select placeholder="Category" data={CATEGORIES.map((c) => ({ value: c, label: humanize(c) }))} value={category} onChange={setCategory} clearable w={190} aria-label="Filter by category" />
          <Switch label="Open only" checked={openOnly} onChange={(e) => setOpenOnly(e.currentTarget.checked)} />
          <Switch label="Assigned to me" checked={mine} onChange={(e) => setMine(e.currentTarget.checked)} />
        </Group>
        <DataTable<Incident>
          rows={list.data?.items}
          loading={list.isLoading}
          error={list.error}
          onRetry={() => list.refetch()}
          rowKey={(i) => i.id}
          onRowClick={(i) => navigate(`/app/${tid}/incidents/${i.id}`)}
          page={page}
          pageSize={25}
          total={list.data?.total}
          onPage={setPage}
          sort={sort}
          onSort={setSort}
          empty={<EmptyState icon={IconCircleCheck} title={openOnly ? "No open incidents" : "No incidents"} description="When monitoring detects something that needs attention, it appears here." />}
          columns={[
            { key: "severity", header: "Severity", sortable: true, render: (i) => <SeverityBadge severity={i.severity} />, width: 110 },
            {
              key: "reference",
              header: "Incident",
              sortable: true,
              render: (i) => (
                <Box>
                  <Text size="sm" fw={600} lineClamp={1}>
                    {i.title}
                  </Text>
                  <Text size="xs" c="dimmed">
                    {i.reference} · {humanize(i.category)}
                    {i.is_demo ? " · DEMO" : ""}
                  </Text>
                </Box>
              ),
            },
            { key: "status", header: "Status", render: (i) => <IncidentStatusBadge status={i.status} /> },
            { key: "website", header: "Website", render: (i) => <Text size="sm">{i.website_name ?? "—"}</Text>, visibleFrom: "md" },
            { key: "last_observed_at", header: "Last observed", sortable: true, render: (i) => <Tooltip label={fmtDateTime(i.last_observed_at)}><Text size="sm">{fmtRelative(i.last_observed_at)}</Text></Tooltip> },
            { key: "owner", header: "Owner", render: (i) => <Text size="sm">{i.assigned_to_name ?? "Unassigned"}</Text>, visibleFrom: "lg" },
          ]}
        />
      </Card>
    </>
  );
}

export function IncidentDetailPage() {
  const tid = useTenantId();
  const { incidentId } = useParams();
  const can = useCan();
  const [note, setNote] = useState("");
  const [resolution, setResolution] = useState("");
  const [falsePositive, setFalsePositive] = useState(false);
  const q = useQuery({ queryKey: ["incident", tid, incidentId], queryFn: () => api.get<IncidentDetail>(`/tenants/${tid}/incidents/${incidentId}`) });
  const members = useQuery({ queryKey: ["members", tid], queryFn: () => api.get<{ user_id: string; full_name: string; email: string; status: string }[]>(`/tenants/${tid}/members`), enabled: can("members:read") });
  const onErr = (e: unknown) => notifications.show({ color: "threat", title: "Action failed", message: errorMessage(e) });
  const status = useMutation({
    mutationFn: (body: { status: string; note?: string; false_positive?: boolean }) => api.post(`/tenants/${tid}/incidents/${incidentId}/status`, body),
    onSuccess: () => { setResolution(""); q.refetch(); },
    onError: onErr,
  });
  const addNote = useMutation({ mutationFn: () => api.post(`/tenants/${tid}/incidents/${incidentId}/notes`, { body: note }), onSuccess: () => { setNote(""); q.refetch(); }, onError: onErr });
  const assign = useMutation({ mutationFn: (user_id: string | null) => api.post(`/tenants/${tid}/incidents/${incidentId}/assign`, { user_id }), onSuccess: () => q.refetch(), onError: onErr });

  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  if (!q.data) return <LoadingBlock rows={10} />;
  const i = q.data;
  const closing = i.allowed_transitions.filter((t) => t === "resolved" || t === "closed");
  const progressing = i.allowed_transitions.filter((t) => !(closing as string[]).includes(t));

  return (
    <>
      <PageHeader
        title={i.title}
        crumbs={[{ label: "Incidents", to: `/app/${tid}/incidents` }, { label: i.reference }]}
        description={
          <Group gap="xs" component="span">
            <SeverityBadge severity={i.severity} size="md" />
            <IncidentStatusBadge status={i.status} />
            <VerificationBadge requiresHuman={i.requires_human_verification} confidence={i.confidence} />
            {i.is_false_positive && <Badge color="gray">False positive</Badge>}
            {i.is_demo && <Badge color="amber">Demo data</Badge>}
          </Group>
        }
      />
      <Grid>
        <Grid.Col span={{ base: 12, lg: 8 }}>
          <Stack>
            <Section title="Summary">
              <Text size="sm">{i.summary}</Text>
              <Grid mt="md">
                <Grid.Col span={{ base: 12, sm: 6 }}>
                  <KeyValue
                    items={[
                      ["Website", i.website_id ? <Anchor key="w" component={Link} to={`/app/${tid}/websites/${i.website_id}`} size="sm">{i.website_name}</Anchor> : "—"],
                      ["Category", humanize(i.category)],
                      ["Finding type", humanize(i.finding_class)],
                      ["Detection source", humanize(i.detection_source)],
                    ]}
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, sm: 6 }}>
                  <KeyValue
                    items={[
                      ["First detected", fmtDateTime(i.first_detected_at)],
                      ["Last observed", fmtDateTime(i.last_observed_at)],
                      ["Occurrences", i.occurrence_count],
                      ["Rule", <Code key="r">{i.rule_key}</Code>],
                    ]}
                  />
                </Grid.Col>
              </Grid>
            </Section>

            {i.affected_resources.length > 0 && (
              <Section title="Affected resources" description={`${i.affected_resources.length} item(s)`}>
                <ScrollArea.Autosize mah={240}>
                  <Stack gap={4}>
                    {i.affected_resources.map((r, idx) => (
                      <Group key={idx} gap="xs" wrap="nowrap">
                        {"change" in r && <Badge size="xs" variant="outline">{String(r.change)}</Badge>}
                        <Text className="cw-mono">{String(r.path ?? JSON.stringify(r))}</Text>
                      </Group>
                    ))}
                  </Stack>
                </ScrollArea.Autosize>
              </Section>
            )}

            <Section
              title="Evidence"
              description="Collected automatically at detection time. Each record carries a SHA-256 of its content for integrity verification."
            >
              {i.evidence.length === 0 ? (
                <Text size="sm" c="dimmed">No evidence records.</Text>
              ) : (
                <Accordion variant="separated">
                  {i.evidence.map((e) => (
                    <Accordion.Item key={e.id} value={e.id}>
                      <Accordion.Control icon={<IconFingerprint size={16} />}>
                        <Group gap="xs" wrap="nowrap">
                          <Text size="sm" fw={600}>{humanize(e.kind)}</Text>
                          <Text size="xs" c="dimmed">{fmtDateTime(e.collected_at)} · {humanize(e.collection_method)}</Text>
                          <Badge size="xs" color={e.integrity_ok ? "secure" : "threat"} leftSection={<IconLock size={10} />}>
                            {e.integrity_ok ? "Integrity verified" : "Integrity mismatch"}
                          </Badge>
                        </Group>
                      </Accordion.Control>
                      <Accordion.Panel>
                        <Text size="xs" c="dimmed" mb={4}>SHA-256 {e.content_sha256}</Text>
                        <Code block style={{ maxHeight: 280, overflow: "auto" }}>{JSON.stringify(e.content, null, 2)}</Code>
                      </Accordion.Panel>
                    </Accordion.Item>
                  ))}
                </Accordion>
              )}
            </Section>

            <Section
              title="Investigation history"
              description={i.history_verified ? "Tamper-evident history: hash chain verified." : "Warning: history hash chain could not be verified."}
            >
              <Timeline bulletSize={24} lineWidth={2}>
                {i.events.map((e) => (
                  <Timeline.Item
                    key={e.seq}
                    bullet={e.is_manual ? <IconUser size={13} /> : <IconShieldExclamation size={13} />}
                    title={
                      <Group gap={6}>
                        <Text size="sm" fw={600}>
                          {e.event_type === "status_changed" ? `Status: ${humanize(e.from_status)} → ${humanize(e.to_status)}` : humanize(e.event_type)}
                        </Text>
                        <Badge size="xs" variant="outline" color={e.is_manual ? "cyber" : "gray"}>
                          {e.is_manual ? "Manual action" : "Automated detection"}
                        </Badge>
                      </Group>
                    }
                  >
                    {e.body && <Text size="sm" mt={2} style={{ whiteSpace: "pre-wrap" }}>{e.body}</Text>}
                    <Text size="xs" c="dimmed" mt={2}>
                      {fmtDateTime(e.created_at)} · {e.actor_name ?? humanize(e.actor_type)} · <Tooltip label={e.hash}><span>{shortHash(e.hash)}</span></Tooltip>
                    </Text>
                  </Timeline.Item>
                ))}
              </Timeline>
              {can("incidents:manage") && (
                <Stack mt="md" gap="xs">
                  <Textarea placeholder="Add an investigation note…" autosize minRows={2} value={note} onChange={(e) => setNote(e.currentTarget.value)} aria-label="Investigation note" />
                  <Button size="xs" w="fit-content" leftSection={<IconMessage size={14} />} disabled={!note.trim()} onClick={() => addNote.mutate()} loading={addNote.isPending}>
                    Add note
                  </Button>
                </Stack>
              )}
            </Section>
          </Stack>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 4 }}>
          <Stack>
            <Card style={{ borderColor: "var(--cw-blue)" }}>
              <Title order={3}>Recommended next action</Title>
              <Text size="sm" mt="xs">{i.recommended_action}</Text>
              <Text size="xs" c="dimmed" mt="sm">
                CyberWatch does not change files on your server. Any remediation must be performed by you or authorised separately.
              </Text>
            </Card>

            {can("incidents:manage") && (
              <Section title="Response">
                <Stack>
                  <Select
                    label="Owner"
                    placeholder="Unassigned"
                    clearable
                    data={(members.data ?? []).filter((m) => m.status === "active").map((m) => ({ value: m.user_id, label: m.full_name || m.email }))}
                    value={i.assigned_to}
                    onChange={(v) => assign.mutate(v)}
                  />
                  {progressing.length > 0 && (
                    <Group gap="xs">
                      {progressing.map((t) => (
                        <Button key={t} size="xs" variant="light" onClick={() => status.mutate({ status: t })} loading={status.isPending}>
                          {t === "investigating" && (i.status === "resolved" || i.status === "closed") ? "Reopen" : `Mark ${humanize(t).toLowerCase()}`}
                        </Button>
                      ))}
                    </Group>
                  )}
                  {closing.length > 0 && (
                    <>
                      <Textarea label="Resolution notes" description="Required to resolve or close." autosize minRows={3} value={resolution} onChange={(e) => setResolution(e.currentTarget.value)} />
                      <Checkbox label="Classify as false positive" checked={falsePositive} onChange={(e) => setFalsePositive(e.currentTarget.checked)} />
                      <Group gap="xs">
                        {closing.map((t) => (
                          <Button key={t} size="xs" color={t === "closed" ? "gray" : "secure"} disabled={!resolution.trim()} onClick={() => status.mutate({ status: t, note: resolution, false_positive: falsePositive })}>
                            {humanize(t) === "Resolved" ? "Resolve" : "Close"}
                          </Button>
                        ))}
                      </Group>
                      {falsePositive && (
                        <Anchor component={Link} to={`/app/${tid}/notifications?suppress=${i.id}&rule=${encodeURIComponent(i.rule_key)}`} size="xs">
                          Create a documented suppression rule →
                        </Anchor>
                      )}
                    </>
                  )}
                  {i.resolution_notes && (
                    <Alert variant="light" color="secure" title="Resolution">
                      {i.resolution_notes}
                    </Alert>
                  )}
                </Stack>
              </Section>
            )}

            {i.risk_score !== null && (
              <Section title="Risk score" description="Explainable heuristic. Not proof of compromise.">
                <Group justify="space-between" mb={6}>
                  <Text className="cw-metric" fz={26}>{i.risk_score}<Text span size="sm" c="dimmed">/100</Text></Text>
                </Group>
                <Progress value={i.risk_score} color={i.risk_score >= 60 ? "threat" : i.risk_score >= 30 ? "amber" : "info"} aria-label={`Risk score ${i.risk_score} of 100`} />
                <Stack gap={4} mt="sm">
                  {i.risk_explanation.map((r, idx) => (
                    <Group key={idx} justify="space-between" wrap="nowrap">
                      <Text size="xs">{r.detail}</Text>
                      <Text size="xs" fw={600}>{r.points > 0 ? `+${r.points}` : "—"}</Text>
                    </Group>
                  ))}
                </Stack>
              </Section>
            )}

            <Section title="Notifications sent">
              {i.notifications.length === 0 ? (
                <Text size="sm" c="dimmed">No notifications were routed for this incident. Configure alert policies under Notifications.</Text>
              ) : (
                <Stack gap={6}>
                  {i.notifications.map((n, idx) => (
                    <Group key={idx} justify="space-between" wrap="nowrap">
                      <Text size="xs">{humanize(n.channel)} · {n.recipient}</Text>
                      <Tooltip label={n.last_error ?? fmtDateTime(n.sent_at)}>
                        <Badge size="xs" color={n.status === "sent" ? "secure" : n.status === "pending" ? "info" : "amber"}>{humanize(n.status)}</Badge>
                      </Tooltip>
                    </Group>
                  ))}
                </Stack>
              )}
            </Section>
          </Stack>
        </Grid.Col>
      </Grid>
    </>
  );
}
