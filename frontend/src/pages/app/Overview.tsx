import {
  Alert,
  Anchor,
  Badge,
  Box,
  Button,
  Card,
  Grid,
  Group,
  Progress,
  SimpleGrid,
  Stack,
  Table,
  Text,
  ThemeIcon,
  Title,
} from "@mantine/core";
import {
  IconAlertTriangle,
  IconBell,
  IconCertificate,
  IconFileDiff,
  IconPlugConnected,
  IconPlus,
  IconRadar,
  IconWorld,
} from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { useMe, useTenant, useTenantId } from "../../api/auth";
import { api } from "../../api/client";
import type { Dashboard } from "../../api/types";
import { SERIES_COLORS, StackedBars } from "../../components/charts";
import { fmtDateTime, fmtRelative, humanize } from "../../components/format";
import { HealthBadge, IncidentStatusBadge, ScanBadge, SeverityBadge, SubscriptionBadge } from "../../components/status";
import { EmptyState, ErrorState, LoadingBlock, PageHeader, Section, StatCard } from "../../components/ui";

export function OverviewPage() {
  const tid = useTenantId();
  const me = useMe();
  const tenant = useTenant();
  const q = useQuery({ queryKey: ["dashboard", tid], queryFn: () => api.get<Dashboard>(`/tenants/${tid}/dashboard`), refetchInterval: 60_000 });
  const d = q.data;
  const base = `/app/${tid}`;
  const firstName = (me.data?.full_name || "").split(" ")[0];

  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;

  const sev = d?.incidents.open_by_severity ?? {};
  const high = (sev.critical ?? 0) + (sev.high ?? 0);
  const noWebsites = d && d.websites.total === 0;
  const coverage = d?.websites.coverage ?? {};
  const fullPct = d && d.websites.total ? Math.round(((coverage.full ?? 0) / d.websites.total) * 100) : 0;

  return (
    <>
      <PageHeader
        title={firstName ? `Welcome back, ${firstName}` : "Security overview"}
        description={
          <>
            {tenant.data?.name} · Monitoring summary generated {d ? fmtRelative(d.generated_at) : "…"}. Figures reflect recorded scan
            results only.
          </>
        }
        actions={
          <Button component={Link} to={`${base}/websites/new`} leftSection={<IconPlus size={16} />}>
            Add website
          </Button>
        }
      />

      {noWebsites && (
        <Card mb="lg" p="xl" style={{ borderColor: "var(--cw-blue)", background: "var(--cw-sidebar-active)" }}>
          <Group justify="space-between" wrap="wrap" gap="lg">
            <Group wrap="nowrap" align="flex-start">
              <ThemeIcon size={48} radius="md">
                <IconRadar size={26} />
              </ThemeIcon>
              <Box>
                <Title order={2}>Connect your first website</Title>
                <Text size="sm" c="dimmed" maw={620} mt={4}>
                  Add a website for availability and TLS checks, then connect its hosting account (SFTP or cPanel) to enable SHA-256
                  file-integrity monitoring. CyberWatch only enables checks your connection can actually support.
                </Text>
              </Box>
            </Group>
            <Group>
              <Button component={Link} to={`${base}/hosting/new`} variant="default" leftSection={<IconPlugConnected size={16} />}>
                Connect hosting
              </Button>
              <Button component={Link} to={`${base}/websites/new`} leftSection={<IconPlus size={16} />}>
                Add website
              </Button>
            </Group>
          </Group>
        </Card>
      )}

      {high > 0 && (
        <Alert color="threat" variant="light" icon={<IconAlertTriangle />} mb="lg" title={`${high} high-priority incident${high > 1 ? "s need" : " needs"} attention`}>
          <Anchor component={Link} to={`${base}/incidents?open=1`} size="sm">
            Review open incidents →
          </Anchor>
        </Alert>
      )}

      <SimpleGrid cols={{ base: 1, xs: 2, lg: 4 }} spacing="md" mb="md">
        <StatCard
          label="Websites monitored"
          icon={IconWorld}
          loading={q.isLoading}
          value={d ? `${d.websites.active}` : "—"}
          context={d ? `${coverage.full ?? 0} full · ${coverage.partial ?? 0} partial · ${coverage.none ?? 0} not monitored` : undefined}
          to={`${base}/websites`}
        />
        <StatCard
          label="Open incidents"
          icon={IconAlertTriangle}
          tone={high ? "threat" : "secure"}
          loading={q.isLoading}
          value={d?.incidents.open_total ?? "—"}
          context={d ? `${sev.critical ?? 0} critical · ${sev.high ?? 0} high · ${sev.medium ?? 0} medium` : undefined}
          to={`${base}/incidents`}
        />
        <StatCard
          label="Last successful scan"
          icon={IconFileDiff}
          loading={q.isLoading}
          value={d?.last_successful_scan_at ? fmtRelative(d.last_successful_scan_at) : "No scan yet"}
          context={d?.last_successful_scan_at ? fmtDateTime(d.last_successful_scan_at) : "Enable file-integrity scanning on a website"}
          to={`${base}/files`}
        />
        <StatCard
          label="Hosting connections"
          icon={IconPlugConnected}
          loading={q.isLoading}
          value={d?.hosting_accounts.total ?? "—"}
          context={
            d
              ? Object.entries(d.hosting_accounts.by_status)
                  .map(([k, v]) => `${v} ${humanize(k).toLowerCase()}`)
                  .join(" · ") || "None connected"
              : undefined
          }
          to={`${base}/hosting`}
        />
      </SimpleGrid>

      <Grid gutter="md">
        <Grid.Col span={{ base: 12, lg: 8 }}>
          <Stack gap="md">
            <Section
              title="Monitoring health"
              description="Coverage and scan freshness for each website. A connected host does not by itself mean a website is fully monitored."
              actions={
                <Anchor component={Link} to={`${base}/websites`} size="sm">
                  All websites
                </Anchor>
              }
            >
              {q.isLoading ? (
                <LoadingBlock />
              ) : !d?.websites.items.length ? (
                <EmptyState title="No websites yet" description="Websites you add appear here with their monitoring status." />
              ) : (
                <>
                  <Group gap="xs" mb="sm">
                    <Text size="sm" c="dimmed">
                      Full coverage
                    </Text>
                    <Progress value={fullPct} w={160} color="secure" aria-label={`${fullPct}% of websites fully monitored`} />
                    <Text size="sm" fw={600}>
                      {fullPct}%
                    </Text>
                  </Group>
                  <div className="cw-table-scroll">
                    <Table miw={620}>
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th>Website</Table.Th>
                          <Table.Th>Coverage</Table.Th>
                          <Table.Th>Last file scan</Table.Th>
                          <Table.Th>Availability</Table.Th>
                          <Table.Th>TLS</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {d.websites.items.slice(0, 8).map((w) => (
                          <Table.Tr key={w.id}>
                            <Table.Td>
                              <Anchor component={Link} to={`${base}/websites/${w.id}`} fw={600} size="sm">
                                {w.name}
                              </Anchor>
                              <Text size="xs" c="dimmed">
                                {w.hostname}
                              </Text>
                            </Table.Td>
                            <Table.Td>
                              <HealthBadge state={w.coverage} />
                            </Table.Td>
                            <Table.Td>
                              <ScanBadge status={w.last_scan_status} />
                              <Text size="xs" c="dimmed" mt={2}>
                                {fmtRelative(w.last_scan_at)}
                              </Text>
                            </Table.Td>
                            <Table.Td>
                              <HealthBadge state={w.availability ?? "unknown"} />
                            </Table.Td>
                            <Table.Td>
                              <HealthBadge state={w.tls ?? "unknown"} />
                            </Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </div>
                </>
              )}
            </Section>

            <Section title="Incident trend" description={`New incidents per day by severity (last ${d ? Object.keys(d.trends.incidents).length : 14} days).`}>
              {q.isLoading || !d ? (
                <LoadingBlock />
              ) : (
                <StackedBars
                  label="Incident trend"
                  data={d.trends.incidents}
                  series={[
                    { key: "critical", label: "Critical", color: SERIES_COLORS.critical },
                    { key: "high", label: "High", color: SERIES_COLORS.high },
                    { key: "medium", label: "Medium", color: SERIES_COLORS.medium },
                    { key: "low", label: "Low", color: SERIES_COLORS.low },
                  ]}
                />
              )}
            </Section>

            <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
              <Section title="File scans" description="Outcome of file-integrity scans per day.">
                {d ? (
                  <StackedBars
                    label="File scan outcomes"
                    height={180}
                    data={d.trends.file_scans}
                    series={[
                      { key: "succeeded", label: "Successful", color: SERIES_COLORS.ok },
                      { key: "partial", label: "Partial", color: SERIES_COLORS.warn },
                      { key: "failed", label: "Failed", color: SERIES_COLORS.bad },
                    ]}
                  />
                ) : (
                  <LoadingBlock />
                )}
              </Section>
              <Section title="Availability checks" description="Results of availability checks per day.">
                {d ? (
                  <StackedBars
                    label="Availability checks"
                    height={180}
                    data={d.trends.availability}
                    series={[
                      { key: "up", label: "Up", color: SERIES_COLORS.ok },
                      { key: "degraded", label: "Degraded", color: SERIES_COLORS.warn },
                      { key: "down", label: "Down", color: SERIES_COLORS.bad },
                    ]}
                  />
                ) : (
                  <LoadingBlock />
                )}
              </Section>
            </SimpleGrid>
          </Stack>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 4 }}>
          <Stack gap="md">
            <Section
              title="Open incidents"
              actions={
                <Anchor component={Link} to={`${base}/incidents`} size="sm">
                  View all
                </Anchor>
              }
            >
              {!d ? (
                <LoadingBlock />
              ) : d.incidents.recent.length === 0 ? (
                <EmptyState title="No open incidents" description="New detections appear here." />
              ) : (
                <Stack gap="sm">
                  {d.incidents.recent.map((i) => (
                    <Box key={i.id} component={Link} to={`${base}/incidents/${i.id}`} style={{ textDecoration: "none", color: "inherit" }}>
                      <Group justify="space-between" wrap="nowrap" align="flex-start">
                        <Box style={{ minWidth: 0 }}>
                          <Text size="sm" fw={600} lineClamp={2}>
                            {i.title}
                          </Text>
                          <Text size="xs" c="dimmed">
                            {i.reference} · {i.website_name ?? "—"} · {fmtRelative(i.last_observed_at)}
                          </Text>
                        </Box>
                        <Stack gap={4} align="flex-end">
                          <SeverityBadge severity={i.severity} />
                          <IncidentStatusBadge status={i.status} />
                        </Stack>
                      </Group>
                    </Box>
                  ))}
                </Stack>
              )}
            </Section>

            <Section title="Recent file changes">
              {!d ? (
                <LoadingBlock />
              ) : d.recent_changes.length === 0 ? (
                <EmptyState title="No changes detected" description="Changes appear after a second successful scan." />
              ) : (
                <Stack gap={10}>
                  {d.recent_changes.map((c) => (
                    <Group key={c.id} justify="space-between" wrap="nowrap">
                      <Box style={{ minWidth: 0 }}>
                        <Text size="sm" className="cw-mono" lineClamp={1} title={c.path}>
                          {c.path}
                        </Text>
                        <Text size="xs" c="dimmed">
                          {humanize(c.change_type)} · {c.website_name} · {fmtRelative(c.detected_at)}
                        </Text>
                      </Box>
                      <SeverityBadge severity={c.severity} />
                    </Group>
                  ))}
                </Stack>
              )}
            </Section>

            <Section title="TLS and availability">
              {d ? (
                <Stack gap={8}>
                  <Group justify="space-between">
                    <Group gap={6}>
                      <IconWorld size={16} />
                      <Text size="sm">Sites up</Text>
                    </Group>
                    <Text size="sm" fw={600}>
                      {d.availability.up ?? 0} up · {d.availability.degraded ?? 0} degraded · {d.availability.down ?? 0} down
                    </Text>
                  </Group>
                  <Group justify="space-between">
                    <Group gap={6}>
                      <IconCertificate size={16} />
                      <Text size="sm">Certificates</Text>
                    </Group>
                    <Text size="sm" fw={600}>
                      {d.tls.valid ?? 0} valid · {d.tls.expiring ?? 0} expiring · {d.tls.problem ?? 0} problems
                    </Text>
                  </Group>
                  <Group justify="space-between">
                    <Group gap={6}>
                      <IconBell size={16} />
                      <Text size="sm">Notifications ({d.notifications.window_days}d)</Text>
                    </Group>
                    <Text size="sm" fw={600}>
                      {d.notifications.by_status.sent ?? 0} sent · {(d.notifications.by_status.failed ?? 0) + (d.notifications.by_status.unconfigured ?? 0)} not delivered
                    </Text>
                  </Group>
                </Stack>
              ) : (
                <LoadingBlock rows={3} />
              )}
            </Section>

            <Section
              title="Subscription"
              actions={
                <Anchor component={Link} to={`${base}/billing`} size="sm">
                  Billing
                </Anchor>
              }
            >
              {d ? (
                <Stack gap="sm">
                  <Group justify="space-between">
                    <Text fw={600}>{d.subscription.plan ?? "No plan"}</Text>
                    <SubscriptionBadge status={d.subscription.status} />
                  </Group>
                  {(["websites", "hosting_accounts", "users"] as const).map((k) => {
                    const used = d.subscription.usage[k] ?? 0;
                    const lim = d.subscription.limits[k] ?? 0;
                    const pct = lim ? Math.min(100, Math.round((used / lim) * 100)) : 100;
                    return (
                      <Box key={k}>
                        <Group justify="space-between">
                          <Text size="xs" c="dimmed">
                            {humanize(k)}
                          </Text>
                          <Text size="xs" fw={600}>
                            {used} / {lim}
                          </Text>
                        </Group>
                        <Progress value={pct} color={pct >= 90 ? "amber" : "cyber"} size="sm" aria-label={`${humanize(k)} ${used} of ${lim}`} />
                      </Box>
                    );
                  })}
                  {!d.subscription.in_service && (
                    <Badge color="threat" variant="light">
                      Service restricted — renew to resume monitoring
                    </Badge>
                  )}
                </Stack>
              ) : (
                <LoadingBlock rows={3} />
              )}
            </Section>
          </Stack>
        </Grid.Col>
      </Grid>
    </>
  );
}
