/**
 * Service desk (staff): every organisation's support and service requests, with SLA targets, assignment,
 * checklist, internal notes, time and the customer report. Site data (incidents, files) is reached only
 * through the access grant created when the customer authorises the work.
 */
import { Alert, Anchor, Badge, Box, Button, Card, Checkbox, Grid, Group, NumberInput, SegmentedControl, Select, Stack, Switch, Text, Textarea, TextInput } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMe } from "../../api/auth";
import { api, errorMessage } from "../../api/client";
import type { Page } from "../../api/types";
import { fmtDateTime, fmtMoney, fmtRelative, humanize } from "../../components/format";
import { SeverityBadge, SlaBadge, TicketStatusBadge } from "../../components/status";
import { DataTable, EmptyState, ErrorState, KeyValue, LoadingBlock, PageHeader, Section } from "../../components/ui";

/* eslint-disable @typescript-eslint/no-explicit-any */

const onError = (e: unknown) => notifications.show({ color: "threat", title: "Action failed", message: errorMessage(e) });

function Sla({ r }: { r: any }) {
  if (["closed", "cancelled"].includes(r.status)) return <Text size="xs" c="dimmed">—</Text>;
  return (
    <Group gap={4} wrap="nowrap">
      <SlaBadge state={r.sla.response} label="Reply" tooltip={r.sla.response_due ? `Due ${fmtDateTime(r.sla.response_due)} (${fmtRelative(r.sla.response_due)})` : undefined} />
      <SlaBadge state={r.sla.resolution} label="Fix" tooltip={r.sla.resolution_due ? `Due ${fmtDateTime(r.sla.resolution_due)} (${fmtRelative(r.sla.resolution_due)})` : undefined} />
    </Group>
  );
}

export function ServiceDeskPage() {
  const navigate = useNavigate();
  const [view, setView] = useState("open");
  const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: ["desk", view, page], queryFn: () => api.get<Page<any> & { counts: any }>("/ops/service-desk", { view, page, page_size: 30 }), refetchInterval: 30_000 });
  const c = q.data?.counts;
  return (
    <>
      <PageHeader title="Service desk" description="Support and service requests from every organisation, most urgent deadline first. Refreshes every 30 seconds." />
      {c && c.overdue > 0 && <Alert color="threat" mb="md" title={`${c.overdue} request(s) past their SLA target`}>Open the Overdue view and reply or escalate.</Alert>}
      <SegmentedControl mb="md" value={view} onChange={(v) => { setView(v); setPage(1); }} aria-label="View"
        data={[
          { value: "open", label: `Open${c ? ` (${c.open})` : ""}` },
          { value: "mine", label: `Mine${c ? ` (${c.mine})` : ""}` },
          { value: "unassigned", label: `Unassigned${c ? ` (${c.unassigned})` : ""}` },
          { value: "overdue", label: `Overdue${c ? ` (${c.overdue})` : ""}` },
          { value: "resolved", label: "Resolved" },
          { value: "all", label: "All" },
        ]} />
      <Card>
        <DataTable
          rows={q.data?.items}
          loading={q.isLoading}
          error={q.error}
          rowKey={(r: any) => r.id}
          onRowClick={(r: any) => navigate(`/ops/service-desk/${r.id}`)}
          page={page}
          pageSize={30}
          total={q.data?.total}
          onPage={setPage}
          empty={<EmptyState title="Nothing here" description="No requests match this view." />}
          columns={[
            { key: "s", header: "Request", render: (r: any) => <Box><Text size="sm" fw={600}>{r.subject}</Text><Text size="xs" c="dimmed">{r.tenant} · {r.reference} · {humanize(r.category)}</Text></Box> },
            { key: "p", header: "Priority", render: (r: any) => <Badge variant={r.priority === "urgent" ? "filled" : "outline"} color={["urgent", "high"].includes(r.priority) ? "threat" : "gray"}>{humanize(r.priority)}</Badge> },
            { key: "st", header: "Status", render: (r: any) => <TicketStatusBadge status={r.status} staffView /> },
            { key: "sla", header: "SLA", render: (r: any) => <Sla r={r} />, visibleFrom: "md" },
            { key: "a", header: "Engineer", render: (r: any) => <Text size="sm" c={r.assignee ? undefined : "dimmed"}>{r.assignee ?? "Unassigned"}</Text>, visibleFrom: "sm" },
            { key: "w", header: "Work", render: (r: any) => (
              <Group gap={4} wrap="nowrap">
                {r.is_service_request && <Badge size="xs" variant="light" color={r.authorised ? "secure" : "amber"}>{r.authorised ? "Authorised" : "Not authorised"}</Badge>}
                {r.checklist_total > 0 && <Text size="xs" c="dimmed">{r.checklist_done}/{r.checklist_total}</Text>}
                {r.billing_status === "quote" && <Badge size="xs" variant="outline" color="amber">Quote</Badge>}
              </Group>
            ), visibleFrom: "lg" },
          ]}
        />
      </Card>
    </>
  );
}

function FixFilesSection({ ticketId }: { ticketId: string }) {
  const q = useQuery({ queryKey: ["desk-remediation", ticketId], queryFn: () => api.get<any>(`/ops/service-desk/${ticketId}/remediation`) });
  const act = useMutation({
    mutationFn: (b: { action: string; path: string; expected_sha256: string }) => api.post<any>(`/ops/service-desk/${ticketId}/remediation/actions`, b),
    onSuccess: (a: any) => { q.refetch(); notifications.show({ color: "secure", title: a.action === "restore_genuine" ? "Official file restored" : "File quarantined", message: `${a.path}. A rescan has been queued.` }); },
    onError: (e) => { q.refetch(); onError(e); },
  });
  const undo = useMutation({
    mutationFn: (id: string) => api.post(`/ops/service-desk/${ticketId}/remediation/actions/${id}/undo`, {}),
    onSuccess: () => { q.refetch(); notifications.show({ color: "secure", title: "Change undone", message: "The previous content is back." }); },
    onError,
  });
  const d = q.data;
  if (!d) return null;
  return (
    <Section title="Fix files" description="Restore official WordPress files (downloaded from wordpress.org and checksum-verified) or quarantine files that should not be there. A copy of every original is kept for undo; each change starts a rescan.">
      {d.blocked ? <Alert color="gray" variant="light">{d.blocked}</Alert>
        : !d.access.configured ? <Alert color="amber" variant="light" title="No remediation access">Ask the customer to set up remediation access on the website's hosting connection (Hosting → connection → Remediation access).</Alert>
        : d.access.status !== "ok" ? <Alert color="threat" variant="light" title="Remediation access is not working">{d.access.last_result ?? "Ask the customer to test it again."}</Alert>
        : d.candidates.length === 0 ? <Text size="sm" c="dimmed">No files need fixing according to the last scan.</Text> : (
          <Stack gap="xs">
            {d.candidates.map((c: any) => (
              <Card key={c.path} p="xs" shadow="none" withBorder>
                <Group justify="space-between" wrap="nowrap" align="flex-start">
                  <Box miw={0}>
                    <Text size="sm" className="cw-mono" style={{ wordBreak: "break-all" }}>{c.path}</Text>
                    <Text size="xs" c="dimmed">{c.reasons.join(" · ")}</Text>
                    {c.last_action && <Text size="xs" c="var(--mantine-color-secure-text)">{humanize(c.last_action.action)} {fmtRelative(c.last_action.at)}</Text>}
                  </Box>
                  <Group gap={4} wrap="nowrap">
                    {c.actions.includes("restore_genuine") && (
                      <Button size="compact-xs" loading={act.isPending && act.variables?.path === c.path}
                        onClick={() => window.confirm(`Replace ${c.path} with the official ${c.vendor_ref} version? A copy of the current file is kept.`) && act.mutate({ action: "restore_genuine", path: c.path, expected_sha256: c.sha256 })}>Restore official</Button>
                    )}
                    {c.actions.includes("quarantine") && (
                      <Button size="compact-xs" color="threat" loading={act.isPending && act.variables?.path === c.path}
                        onClick={() => window.confirm(`Remove ${c.path} from the server? An encrypted copy is kept so it can be undone.`) && act.mutate({ action: "quarantine", path: c.path, expected_sha256: c.sha256 })}>Quarantine</Button>
                    )}
                  </Group>
                </Group>
              </Card>
            ))}
          </Stack>
        )}
      {d.actions.length > 0 && (
        <Stack gap={4} mt="md">
          <Text size="sm" fw={700}>Changes made</Text>
          {d.actions.map((a: any) => (
            <Group key={a.id} justify="space-between" wrap="nowrap" gap="xs">
              <Text size="xs" style={{ wordBreak: "break-all" }}>
                <Badge size="xs" color={a.status === "done" ? "secure" : a.status === "undone" ? "gray" : "threat"} mr={6}>{humanize(a.status)}</Badge>
                {humanize(a.action)} <span className="cw-mono">{a.path}</span> · {a.performed_by} · {fmtRelative(a.performed_at)}{a.error ? ` · ${a.error}` : ""}
              </Text>
              {a.can_undo && !d.blocked && <Button size="compact-xs" variant="subtle" onClick={() => window.confirm(`Put ${a.path} back as it was before?`) && undo.mutate(a.id)}>Undo</Button>}
            </Group>
          ))}
        </Stack>
      )}
    </Section>
  );
}

const DEFAULT_SCOPE: Record<string, string> = {
  malware_cleanup: "Find and remove malware and unauthorised files; restore genuine WordPress core and plugin files; update or remove vulnerable plugins and themes; reset WordPress security keys; apply basic hardening.",
  remediation_request: "Find and remove malware and unauthorised files; restore genuine WordPress core and plugin files; apply basic hardening.",
  fix_site: "Diagnose the reported problem and fix or roll back its cause (files, plugins, theme or configuration).",
  migration: "Copy the website files and database to the new host, update its configuration, and test before the DNS switch.",
  maintenance: "Make the requested change, with a backup first.",
  performance: "Change caching, plugin and media settings to improve page speed.",
};

function RequestAuthorisation({ d, onDone }: { d: any; onDone: () => void }) {
  const [scope, setScope] = useState(d.proposed_scope ?? `${DEFAULT_SCOPE[d.category] ?? "Carry out the requested work."}${d.website ? ` Website: ${d.website.url}` : ""}`);
  const [message, setMessage] = useState("");
  const send = useMutation({
    mutationFn: () => api.post(`/ops/service-desk/${d.id}/request-authorisation`, { scope, message }),
    onSuccess: () => { onDone(); notifications.show({ color: "secure", title: "Authorisation requested", message: "The customer and their owners were emailed." }); },
    onError,
  });
  const finished = ["resolved", "closed", "cancelled"].includes(d.status);
  return (
    <Stack gap="xs">
      <Alert color="amber" variant="light" title="Not authorised yet">Do not change the customer's site until they authorise the work. Once they do, the assigned engineer gets time-limited access automatically.</Alert>
      {d.authorisation_requested_at && <Text size="sm">Requested {fmtRelative(d.authorisation_requested_at)}; waiting for an owner to authorise.</Text>}
      {!finished && (
        <>
          <Textarea label="Proposed scope" description="Exactly what you will change. The customer sees this and can adjust it before authorising." autosize minRows={3} value={scope} onChange={(e) => setScope(e.currentTarget.value)} />
          <Textarea label="Note to the customer (optional)" autosize minRows={1} value={message} onChange={(e) => setMessage(e.currentTarget.value)} />
          <Button w="fit-content" onClick={() => send.mutate()} loading={send.isPending} disabled={scope.trim().length < 10}>
            {d.authorisation_requested_at ? "Send the request again" : "Request authorisation"}
          </Button>
        </>
      )}
    </Stack>
  );
}

export function DeskTicketPage() {
  const { ticketId } = useParams();
  const me = useMe();
  const q = useQuery({ queryKey: ["desk-ticket", ticketId], queryFn: () => api.get<any>(`/ops/service-desk/${ticketId}`), refetchInterval: 60_000 });
  const staff = useQuery({ queryKey: ["desk-staff"], queryFn: () => api.get<{ id: string; name: string }[]>("/ops/service-desk-staff") });
  const [reply, setReply] = useState("");
  const [internal, setInternal] = useState(false);
  const [minutes, setMinutes] = useState<number | string>(30);
  const [timeNote, setTimeNote] = useState("");
  const [report, setReport] = useState({ findings: "", actions_taken: "", recommendations: "", verification: "" });
  const [billing, setBilling] = useState<{ billing_status: string; price: number | string }>({ billing_status: "included", price: "" });
  const d = q.data;
  useEffect(() => {
    if (!d) return;
    setReport({ findings: d.report?.findings ?? "", actions_taken: d.report?.actions_taken ?? "", recommendations: d.report?.recommendations ?? "", verification: d.report?.verification ?? "" });
    setBilling({ billing_status: d.billing_status, price: d.price_minor != null ? d.price_minor / 100 : "" });
  }, [d?.id, d?.report?.updated_at, d?.billing_status, d?.price_minor]); // eslint-disable-line react-hooks/exhaustive-deps
  const post = (path: string, body: object, method: "post" | "put" = "post") => (method === "post" ? api.post : api.put)(`/ops/service-desk/${ticketId}${path}`, body);
  const act = useMutation({ mutationFn: ({ path, body, method }: { path: string; body: object; method?: "post" | "put" }) => post(path, body, method), onSuccess: () => q.refetch(), onError });

  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  if (!d) return <LoadingBlock rows={8} />;
  const myId = me.data?.id;
  const grantMine = d.grant?.status === "active" && d.grant.grantee_user_id === myId;
  const finished = ["closed", "cancelled"].includes(d.status);
  return (
    <>
      <PageHeader title={d.subject} crumbs={[{ label: "Service desk", to: "/ops/service-desk" }, { label: d.reference }]}
        description={`${d.tenant} · ${d.reference} · ${humanize(d.category)} · ${humanize(d.priority)} priority · opened ${fmtDateTime(d.created_at)}${d.requested_by ? ` by ${d.requested_by.name || d.requested_by.email}` : ""}`}
        actions={<Group gap="xs"><TicketStatusBadge status={d.status} staffView /><Sla r={d} /></Group>} />
      <Grid>
        <Grid.Col span={{ base: 12, lg: 7 }}>
          <Stack>
            <Section title="Conversation" description="Internal notes (amber) are never shown to the customer.">
              <Stack>
                {d.messages.map((m: any, i: number) => m.kind === "status" ? (
                  <Text key={i} size="xs" c="dimmed" ta="center">{m.body} · {fmtDateTime(m.created_at)}</Text>
                ) : (
                  <Card key={i} p="sm" shadow="none" style={{ background: m.internal ? "var(--mantine-color-amber-light)" : m.is_staff ? "var(--cw-sidebar-active)" : "var(--cw-surface-alt)" }}>
                    <Group justify="space-between"><Text size="sm" fw={600}>{m.author}{m.internal ? " · internal note" : m.is_staff ? " · Trust Data" : " · customer"}</Text><Text size="xs" c="dimmed">{fmtDateTime(m.created_at)}</Text></Group>
                    <Text size="sm" mt={4} style={{ whiteSpace: "pre-wrap" }}>{m.body}</Text>
                  </Card>
                ))}
                {!finished && (
                  <>
                    <Textarea placeholder={internal ? "Internal note (staff only)…" : "Reply to the customer…"} autosize minRows={3} value={reply} onChange={(e) => setReply(e.currentTarget.value)} aria-label="Message" />
                    <Group>
                      <Button onClick={() => act.mutate({ path: "/messages", body: { body: reply, internal } }, { onSuccess: () => setReply("") })} loading={act.isPending} disabled={!reply.trim()} color={internal ? "amber" : undefined}>
                        {internal ? "Add internal note" : "Send to customer"}
                      </Button>
                      <Switch label="Internal note" checked={internal} onChange={(e) => setInternal(e.currentTarget.checked)} />
                    </Group>
                  </>
                )}
              </Stack>
            </Section>
            {d.is_service_request && <FixFilesSection ticketId={d.id} />}
            {d.is_service_request && (
              <Section title="Report for the customer" description="Shown on the customer's request page. Required before resolving a service request.">
                <Stack>
                  <Textarea label="What we found" autosize minRows={2} value={report.findings} onChange={(e) => setReport({ ...report, findings: e.currentTarget.value })} />
                  <Textarea label="What we did" autosize minRows={2} value={report.actions_taken} onChange={(e) => setReport({ ...report, actions_taken: e.currentTarget.value })} />
                  <Textarea label="How we checked it" autosize minRows={1} value={report.verification} onChange={(e) => setReport({ ...report, verification: e.currentTarget.value })} />
                  <Textarea label="Recommendations" autosize minRows={2} value={report.recommendations} onChange={(e) => setReport({ ...report, recommendations: e.currentTarget.value })} />
                  <Group><Button variant="default" onClick={() => act.mutate({ path: "/report", body: report, method: "put" }, { onSuccess: () => notifications.show({ color: "secure", title: "Report saved", message: "The customer can see it now." }) })} loading={act.isPending}>Save report</Button>
                    {d.report?.updated_at && <Text size="xs" c="dimmed">Saved {fmtRelative(d.report.updated_at)} by {d.report.engineer}</Text>}</Group>
                </Stack>
              </Section>
            )}
          </Stack>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 5 }}>
          <Stack>
            <Section title="Handling">
              <Stack gap="sm">
                <Group align="flex-end" gap="xs">
                  <Select label="Engineer" placeholder="Unassigned" w={220} data={(staff.data ?? []).map((s) => ({ value: s.id, label: s.name }))} value={d.assigned_to}
                    onChange={(v) => v && act.mutate({ path: "/assign", body: { user_id: v } })} disabled={finished} />
                  {!finished && d.assigned_to !== myId && <Button variant="light" onClick={() => act.mutate({ path: "/assign", body: {} })}>Assign to me</Button>}
                </Group>
                <Select label="Status" w={220} value={d.status} disabled={finished && d.status === "cancelled"}
                  data={["open", "in_progress", "awaiting_customer", "resolved", "closed", "cancelled"].map((s) => ({ value: s, label: humanize(s) }))}
                  onChange={(v) => v && v !== d.status && act.mutate({ path: "/status", body: { status: v } })} />
                <KeyValue items={[
                  ["Reply due", d.sla.response_due ? `${fmtDateTime(d.sla.response_due)}${d.sla.first_response_at ? " (replied)" : ""}` : "—"],
                  ["Fix due", d.sla.resolution_due ? fmtDateTime(d.sla.resolution_due) : "—"],
                  ["Time logged", `${Math.round(d.time_spent_minutes / 6) / 10} h`],
                ]} />
              </Stack>
            </Section>
            {d.is_service_request && (
              <Section title="Customer authorisation and access">
                {d.remediation_approved_at ? (
                  <Stack gap="xs">
                    <Alert color="secure" variant="light" title={`Authorised ${fmtDateTime(d.remediation_approved_at)}`}><Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{d.remediation_scope}</Text></Alert>
                    {d.grant ? (
                      <Text size="sm">Access grant: <b>{humanize(d.grant.status)}</b>{d.grant.status === "active" ? `, until ${fmtDateTime(d.grant.expires_at)}` : ""}.{" "}
                        {grantMine && <Anchor component={Link} to={`/app/${d.tenant_id}/overview`}>Open the customer's portal</Anchor>}</Text>
                    ) : <Text size="sm" c="dimmed">Access starts when an engineer is assigned.</Text>}
                  </Stack>
                ) : <RequestAuthorisation d={d} onDone={() => q.refetch()} />}
              </Section>
            )}
            {(d.website || d.incidents.length > 0) && (
              <Section title="Site and incidents" description="Details, evidence and files are in the customer's portal (needs the access grant).">
                <Stack gap={6}>
                  {d.website && <Text size="sm"><b>{d.website.name}</b> · {d.website.url}</Text>}
                  {d.incidents.map((i: any) => (
                    <Group key={i.id} gap="xs"><SeverityBadge severity={i.severity} /><Text size="sm">{i.reference} · {humanize(i.category)} · {humanize(i.status)}</Text>
                      {grantMine && <Anchor component={Link} to={`/app/${d.tenant_id}/incidents/${i.id}`} size="sm">Open</Anchor>}</Group>
                  ))}
                </Stack>
              </Section>
            )}
            {d.checklist.length > 0 && (
              <Section title="Checklist" description="The customer sees progress, not who ticked each step.">
                <Stack gap={6}>
                  {d.checklist.map((c: any) => (
                    <Checkbox key={c.key} label={c.label} checked={c.done} disabled={finished}
                      description={c.done && c.done_at ? `Done ${fmtRelative(c.done_at)}` : undefined}
                      onChange={(e) => act.mutate({ path: "/checklist", body: { key: c.key, done: e.currentTarget.checked } })} />
                  ))}
                </Stack>
              </Section>
            )}
            <Section title="Log time">
              <Group align="flex-end" gap="xs">
                <NumberInput label="Minutes" w={110} min={1} max={1440} value={minutes} onChange={setMinutes} />
                <TextInput label="What for" style={{ flex: 1 }} value={timeNote} onChange={(e) => setTimeNote(e.currentTarget.value)} />
                <Button variant="default" disabled={!Number(minutes)} onClick={() => act.mutate({ path: "/time", body: { minutes: Number(minutes), note: timeNote } }, { onSuccess: () => setTimeNote("") })}>Log</Button>
              </Group>
            </Section>
            <Section title="Billing" description="Included in the plan's allowance, to be quoted, agreed price, or waived.">
              <Group align="flex-end" gap="xs">
                <Select label="Status" w={150} value={billing.billing_status} data={["included", "quote", "billable", "waived"].map((s) => ({ value: s, label: humanize(s) }))} onChange={(v) => setBilling({ ...billing, billing_status: v ?? "included" })} />
                <NumberInput label="Price (₦)" w={150} min={0} thousandSeparator="," value={billing.price} onChange={(v) => setBilling({ ...billing, price: v })} />
                <Button variant="default" onClick={() => act.mutate({ path: "/billing", method: "put", body: { billing_status: billing.billing_status, price_minor: billing.price === "" ? null : Math.round(Number(billing.price) * 100) } })}>Save</Button>
              </Group>
              {d.price_minor != null && <Text size="xs" c="dimmed" mt={4}>Recorded: {fmtMoney(d.price_minor, "NGN")}</Text>}
            </Section>
          </Stack>
        </Grid.Col>
      </Grid>
    </>
  );
}
