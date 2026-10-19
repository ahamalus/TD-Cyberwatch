import {
  Alert,
  Badge,
  Box,
  Button,
  Card,
  Code,
  Grid,
  Group,
  Loader,
  Modal,
  NumberInput,
  PasswordInput,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  TagsInput,
  Text,
  Textarea,
  TextInput,
  ThemeIcon,
  Timeline,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import {
  IconCheck,
  IconInfoCircle,
  IconKey,
  IconPlugConnected,
  IconPlus,
  IconRefresh,
  IconServer,
  IconTrash,
  IconX,
} from "@tabler/icons-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useCan, useTenant, useTenantId } from "../../api/auth";
import { api, errorMessage } from "../../api/client";
import type { ConnectorInfo, HostingAccount } from "../../api/types";
import { fmtDateTime, fmtRelative } from "../../components/format";
import { CapabilityBadge, ConnectionBadge } from "../../components/status";
import { ConfirmButton, EmptyState, ErrorState, KeyValue, LoadingBlock, PageHeader, Section } from "../../components/ui";

export function HostingListPage() {
  const tid = useTenantId();
  const can = useCan();
  const tenant = useTenant();
  const q = useQuery({ queryKey: ["hosting", tid], queryFn: () => api.get<HostingAccount[]>(`/tenants/${tid}/hosting-accounts`) });
  const limit = Number(tenant.data?.entitlements.max_hosting_accounts ?? 0);
  const used = tenant.data?.usage.hosting_accounts ?? 0;
  return (
    <>
      <PageHeader
        title="Hosting connections"
        description="Accounts CyberWatch uses for read-only file monitoring. Each connection shows the capabilities it has actually verified."
        crumbs={[{ label: "Overview", to: `/app/${tid}/overview` }, { label: "Hosting connections" }]}
        actions={
          can("hosting:manage") && (
            <Button component={Link} to={`/app/${tid}/hosting/new`} leftSection={<IconPlus size={16} />} disabled={!!tenant.data && used >= limit}>
              Connect hosting
            </Button>
          )
        }
      />
      {q.error && <ErrorState error={q.error} onRetry={() => q.refetch()} />}
      {q.isLoading && <LoadingBlock />}
      {q.data && q.data.length === 0 && (
        <Card>
          <EmptyState
            icon={IconServer}
            title="No hosting connections"
            description="Connect an SFTP account or a cPanel account (API token) to enable file-integrity monitoring."
            action={can("hosting:manage") && <Button component={Link} to={`/app/${tid}/hosting/new`}>Connect hosting</Button>}
          />
        </Card>
      )}
      <SimpleGrid cols={{ base: 1, md: 2, xl: 3 }}>
        {q.data?.map((h) => {
          const avail = h.capabilities.filter((c) => c.status === "available").length;
          return (
            <Card key={h.id} component={Link} to={`/app/${tid}/hosting/${h.id}`} style={{ textDecoration: "none", color: "inherit" }}>
              <Group justify="space-between" align="flex-start" wrap="nowrap">
                <Group wrap="nowrap">
                  <ThemeIcon variant="light" size={40}>
                    <IconServer size={22} />
                  </ThemeIcon>
                  <Box style={{ minWidth: 0 }}>
                    <Text fw={650} truncate>
                      {h.name}
                    </Text>
                    <Text size="xs" c="dimmed" truncate>
                      {h.connector_name} · {h.username}@{h.hostname}:{h.port}
                    </Text>
                  </Box>
                </Group>
                <ConnectionBadge status={h.status} />
              </Group>
              <Group mt="md" gap="xs">
                <Badge variant="outline" color="gray">
                  {avail} of {h.capabilities.length} capabilities available
                </Badge>
                <Badge variant="outline" color="gray">
                  {h.website_count} website{h.website_count === 1 ? "" : "s"}
                </Badge>
              </Group>
              <Text size="xs" c="dimmed" mt="sm">
                Last successful connection: {fmtRelative(h.last_success_at)}
              </Text>
              {h.last_error_message && h.status !== "connected" && (
                <Text size="xs" c="threat.6" mt={4} lineClamp={2}>
                  {h.last_error_message}
                </Text>
              )}
            </Card>
          );
        })}
      </SimpleGrid>
    </>
  );
}

export function NewHostingPage() {
  const tid = useTenantId();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const connectors = useQuery({ queryKey: ["connectors"], queryFn: () => api.get<ConnectorInfo[]>("/connectors") });
  const [type, setType] = useState("sftp");
  const [form, setForm] = useState({ name: "", provider_name: "", hostname: "", port: 22, username: "", root_path: "/public_html", log_paths: [] as string[] });
  const [kind, setKind] = useState("password");
  const [secret, setSecret] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const implemented = connectors.data?.filter((c) => c.status === "implemented" && c.credential_kinds.length) ?? [];
  const planned = connectors.data?.filter((c) => c.status === "planned") ?? [];
  const current = implemented.find((c) => c.key === type);

  const create = useMutation({
    mutationFn: () =>
      api.post<HostingAccount>(`/tenants/${tid}/hosting-accounts`, {
        ...form,
        connector_type: type,
        provider_name: form.provider_name || null,
        credential: { kind, value: secret, passphrase: passphrase || null },
      }),
    onSuccess: (a) => {
      setSecret("");
      setPassphrase("");
      qc.invalidateQueries({ queryKey: ["hosting", tid] });
      qc.invalidateQueries({ queryKey: ["tenant", tid] });
      navigate(`/app/${tid}/hosting/${a.id}?testing=1`);
    },
    onError: (e) => setError(errorMessage(e)),
  });

  return (
    <>
      <PageHeader
        title="Connect a hosting account"
        description="Credentials are encrypted immediately and are never shown again. CyberWatch uses them for read-only listing and reading of files."
        crumbs={[{ label: "Hosting connections", to: `/app/${tid}/hosting` }, { label: "Connect" }]}
      />
      <Grid>
        <Grid.Col span={{ base: 12, lg: 8 }}>
          <Card>
            <Stack>
              <SegmentedControl
                fullWidth
                value={type}
                onChange={(v) => {
                  setType(v);
                  const c = implemented.find((x) => x.key === v);
                  setKind(c?.credential_kinds[0] ?? "password");
                  setForm({ ...form, port: c?.default_port ?? 22, root_path: v === "cpanel_uapi" ? "/public_html" : form.root_path });
                }}
                data={implemented.map((c) => ({ value: c.key, label: c.name }))}
                aria-label="Connection type"
              />
              {current && (
                <Text size="sm" c="dimmed">
                  {current.description}
                </Text>
              )}
              <SimpleGrid cols={{ base: 1, sm: 2 }}>
                <TextInput label="Connection name" required value={form.name} onChange={(e) => setForm({ ...form, name: e.currentTarget.value })} placeholder="e.g. Reseller account 12" />
                <TextInput label="Hosting provider (optional)" value={form.provider_name} onChange={(e) => setForm({ ...form, provider_name: e.currentTarget.value })} />
                <TextInput label="Server hostname" required value={form.hostname} onChange={(e) => setForm({ ...form, hostname: e.currentTarget.value })} placeholder="server.example-host.com" />
                <NumberInput label="Port" required value={form.port} onChange={(v) => setForm({ ...form, port: Number(v) })} min={1} max={65535} />
                <TextInput label={type === "cpanel_uapi" ? "cPanel username" : "SFTP username"} required value={form.username} onChange={(e) => setForm({ ...form, username: e.currentTarget.value })} autoComplete="off" />
                <TextInput
                  label="Authorised root directory"
                  description={type === "cpanel_uapi" ? "Relative to the account home." : "Monitoring never reads outside this path."}
                  value={form.root_path}
                  onChange={(e) => setForm({ ...form, root_path: e.currentTarget.value })}
                />
              </SimpleGrid>
              {current && current.credential_kinds.length > 1 && (
                <SegmentedControl
                  value={kind}
                  onChange={setKind}
                  data={current.credential_kinds.map((k) => ({ value: k, label: k === "private_key" ? "SSH private key" : "Password" }))}
                  aria-label="Credential type"
                />
              )}
              {kind === "private_key" ? (
                <>
                  <Textarea label="SSH private key" description="Ed25519, ECDSA or RSA in OpenSSH/PEM format. Use a key dedicated to CyberWatch." autosize minRows={4} required value={secret} onChange={(e) => setSecret(e.currentTarget.value)} styles={{ input: { fontFamily: "monospace", fontSize: 12 } }} />
                  <PasswordInput label="Key passphrase (if any)" value={passphrase} onChange={(e) => setPassphrase(e.currentTarget.value)} autoComplete="off" />
                </>
              ) : (
                <PasswordInput
                  label={kind === "api_token" ? "cPanel API token" : "Password"}
                  description={kind === "api_token" ? "Create a token in cPanel → Security → Manage API Tokens. Revoke it at any time to disconnect." : undefined}
                  required
                  value={secret}
                  onChange={(e) => setSecret(e.currentTarget.value)}
                  autoComplete="new-password"
                />
              )}
              {type === "sftp" && (
                <TagsInput
                  label="Log directories (optional)"
                  description="Absolute paths to web server logs, if your host exposes them. Access is tested, never assumed."
                  value={form.log_paths}
                  onChange={(v) => setForm({ ...form, log_paths: v })}
                />
              )}
              {error && (
                <Alert color="threat" variant="light" role="alert">
                  {error}
                </Alert>
              )}
              <Group justify="flex-end">
                <Button variant="default" component={Link} to={`/app/${tid}/hosting`}>
                  Cancel
                </Button>
                <Button onClick={() => create.mutate()} loading={create.isPending} disabled={!form.name || !form.hostname || !form.username || !secret} leftSection={<IconPlugConnected size={16} />}>
                  Save and test connection
                </Button>
              </Group>
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 4 }}>
          <Stack>
            <Section title="What happens next">
              <Timeline active={-1} bulletSize={22} lineWidth={2}>
                <Timeline.Item title="Validate destination">Hostname and port are checked against the outbound security policy.</Timeline.Item>
                <Timeline.Item title="Connect securely">For SFTP the server host key is recorded and pinned.</Timeline.Item>
                <Timeline.Item title="Verify credentials">Credentials are tested; the result is shown without exposing secrets.</Timeline.Item>
                <Timeline.Item title="Discover capabilities">Listing, metadata and reading are tested safely; nothing is written.</Timeline.Item>
              </Timeline>
            </Section>
            {planned.length > 0 && (
              <Section title="Coming later">
                <Stack gap={6}>
                  {planned.map((c) => (
                    <Group key={c.key} justify="space-between">
                      <Text size="sm">{c.name}</Text>
                      <Badge color="gray" variant="outline">Planned</Badge>
                    </Group>
                  ))}
                </Stack>
              </Section>
            )}
          </Stack>
        </Grid.Col>
      </Grid>
    </>
  );
}

export function HostingDetailPage() {
  const tid = useTenantId();
  const { accountId } = useParams();
  const can = useCan();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [rotateOpen, rotate] = useDisclosure(false);
  const q = useQuery({
    queryKey: ["hosting-account", tid, accountId],
    queryFn: () => api.get<HostingAccount>(`/tenants/${tid}/hosting-accounts/${accountId}`),
    refetchInterval: (query) => {
      const j = query.state.data?.last_test_job;
      return j && (j.status === "queued" || j.status === "running") ? 2000 : false;
    },
  });
  const test = useMutation({
    mutationFn: () => api.post(`/tenants/${tid}/hosting-accounts/${accountId}/test`),
    onSuccess: () => q.refetch(),
    onError: (e) => notifications.show({ color: "threat", title: "Could not start test", message: errorMessage(e) }),
  });
  const del = useMutation({
    mutationFn: () => api.del(`/tenants/${tid}/hosting-accounts/${accountId}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["hosting", tid] });
      navigate(`/app/${tid}/hosting`);
    },
  });
  const retrust = useMutation({
    mutationFn: () => api.post(`/tenants/${tid}/hosting-accounts/${accountId}/retrust-host-key`, { confirm_fingerprint_change: true, reason: "Host key change confirmed with hosting provider" }),
    onSuccess: () => q.refetch(),
  });

  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  if (!q.data) return <LoadingBlock rows={8} />;
  const h = q.data;
  const job = h.last_test_job;
  const testing = job && (job.status === "queued" || job.status === "running");

  return (
    <>
      <PageHeader
        title={h.name}
        description={`${h.connector_name} · ${h.username}@${h.hostname}:${h.port}`}
        crumbs={[{ label: "Hosting connections", to: `/app/${tid}/hosting` }, { label: h.name }]}
        actions={
          can("hosting:manage") && (
            <>
              <Button variant="default" leftSection={<IconRefresh size={16} />} onClick={() => test.mutate()} loading={test.isPending || !!testing}>
                Test connection
              </Button>
              <Button variant="default" leftSection={<IconKey size={16} />} onClick={rotate.open}>
                Rotate credential
              </Button>
            </>
          )
        }
      />
      <Grid>
        <Grid.Col span={{ base: 12, md: 5 }}>
          <Stack>
            <Section title="Connection" description="Configuration you provided.">
              <KeyValue
                items={[
                  ["Status", <ConnectionBadge key="s" status={h.status} />],
                  ["Connector", h.connector_name],
                  ["Provider", h.provider_name ?? "—"],
                  ["Host", `${h.hostname}:${h.port}`],
                  ["Username", h.username],
                  ["Authorised root", <Code key="r">{h.root_path}</Code>],
                  ["Credential", h.credential_kind ? `${h.credential_kind.replace("_", " ")} · ${h.credential_fingerprint}` : "None"],
                  ["Credential updated", fmtDateTime(h.credential_rotated_at)],
                  ["Host key", h.host_key_fingerprint ? <Text key="k" className="cw-mono">{h.host_key_type} {h.host_key_fingerprint}</Text> : "—"],
                  ["Last tested", fmtDateTime(h.last_tested_at)],
                  ["Last successful", fmtDateTime(h.last_success_at)],
                  ["Websites", h.website_count],
                ]}
              />
            </Section>
            <Section title="Latest diagnostics" description="Sanitised results of the most recent connection test.">
              {!job ? (
                <Text size="sm" c="dimmed">
                  No test has run yet.
                </Text>
              ) : testing ? (
                <Group>
                  <Loader size="sm" />
                  <Text size="sm">Testing connection and discovering capabilities…</Text>
                </Group>
              ) : (
                <Stack gap={6}>
                  {(job.result?.diagnostics ?? []).map((d, i) => (
                    <Group key={i} gap="xs" wrap="nowrap" align="flex-start">
                      <ThemeIcon size={20} radius="xl" color={d.ok ? "secure" : "threat"} variant="light" aria-label={d.ok ? "passed" : "failed"}>
                        {d.ok ? <IconCheck size={13} /> : <IconX size={13} />}
                      </ThemeIcon>
                      <Box>
                        <Text size="sm" fw={600} tt="capitalize">
                          {d.step.replace(/_/g, " ")}
                        </Text>
                        <Text size="xs" c="dimmed">
                          {d.message}
                        </Text>
                      </Box>
                    </Group>
                  ))}
                  {job.error && (
                    <Alert color="threat" variant="light" mt="xs">
                      {job.error}
                    </Alert>
                  )}
                  <Text size="xs" c="dimmed">
                    Finished {fmtRelative(job.finished_at)}
                  </Text>
                </Stack>
              )}
              {h.last_error_code === "host_key_mismatch" && can("hosting:manage") && (
                <Alert color="threat" variant="light" mt="md" title="Server identity changed">
                  <Text size="sm" mb="sm">
                    The server presented a different SSH host key. Confirm with your hosting provider that the server was rebuilt before trusting the
                    new key — otherwise this may indicate interception.
                  </Text>
                  <ConfirmButton size="xs" danger title="Trust the new host key?" message="Only continue if your provider confirmed the change. The next connection will record and pin the new key." onConfirm={() => retrust.mutateAsync()}>
                    I have verified — trust new key
                  </ConfirmButton>
                </Alert>
              )}
            </Section>
          </Stack>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 7 }}>
          <Section title="Discovered capabilities" description="What this account can actually do. Monitoring options are limited to available capabilities.">
            <Stack gap="sm">
              {h.capabilities.map((c) => (
                <Card key={c.capability} p="sm" shadow="none" style={{ background: "var(--cw-surface-alt)" }}>
                  <Group justify="space-between" wrap="nowrap" align="flex-start">
                    <Box>
                      <Text size="sm" fw={600}>
                        {c.label}
                      </Text>
                      <Text size="xs" c="dimmed">
                        {c.detail}
                      </Text>
                      {c.required_permission && c.status !== "available" && (
                        <Text size="xs" c="amber.8" mt={2}>
                          Needs: {c.required_permission}
                        </Text>
                      )}
                    </Box>
                    <CapabilityBadge status={c.status} />
                  </Group>
                </Card>
              ))}
            </Stack>
            <Alert variant="light" color="info" icon={<IconInfoCircle />} mt="md">
              SFTP access never implies log access, server-side malware scanning or real-time upload detection. These appear as available only when
              verified.
            </Alert>
          </Section>
        </Grid.Col>
      </Grid>
      {can("hosting:manage") && (
        <Card mt="md" style={{ borderColor: "var(--cw-red)" }}>
          <Group justify="space-between">
            <Box>
              <Text fw={600}>Delete connection</Text>
              <Text size="sm" c="dimmed">
                Destroys the stored encrypted credential. Websites using it lose file monitoring until reconnected.
              </Text>
            </Box>
            <ConfirmButton danger variant="light" leftSection={<IconTrash size={16} />} title="Delete hosting connection?" message="The encrypted credential is destroyed and file scans for associated websites stop." confirmLabel="Delete connection" onConfirm={() => del.mutateAsync()}>
              Delete
            </ConfirmButton>
          </Group>
        </Card>
      )}
      <RotateModal opened={rotateOpen} onClose={rotate.close} account={h} onDone={() => q.refetch()} />
    </>
  );
}

function RotateModal({ opened, onClose, account, onDone }: { opened: boolean; onClose: () => void; account: HostingAccount; onDone: () => void }) {
  const tid = useTenantId();
  const kinds = account.connector_type === "cpanel_uapi" ? ["api_token"] : ["password", "private_key"];
  const [kind, setKind] = useState(kinds[0]);
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const m = useMutation({
    mutationFn: () => api.put(`/tenants/${tid}/hosting-accounts/${account.id}/credential`, { kind, value }),
    onSuccess: () => {
      setValue("");
      onClose();
      onDone();
      notifications.show({ color: "secure", title: "Credential replaced", message: "A connection test has been queued." });
    },
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <Modal opened={opened} onClose={onClose} title="Rotate credential">
      <Stack>
        <Select label="Credential type" data={kinds.map((k) => ({ value: k, label: k.replace("_", " ") }))} value={kind} onChange={(v) => setKind(v ?? kinds[0])} />
        {kind === "private_key" ? (
          <Textarea label="New private key" autosize minRows={4} value={value} onChange={(e) => setValue(e.currentTarget.value)} />
        ) : (
          <PasswordInput label="New secret" value={value} onChange={(e) => setValue(e.currentTarget.value)} autoComplete="new-password" />
        )}
        {error && <Alert color="threat">{error}</Alert>}
        <Button onClick={() => m.mutate()} loading={m.isPending} disabled={!value}>
          Replace credential
        </Button>
      </Stack>
    </Modal>
  );
}
