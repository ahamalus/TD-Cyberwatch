import {
  Anchor,
  Badge,
  Box,
  Button,
  Card,
  Container,
  Divider,
  Group,
  List,
  SimpleGrid,
  Stack,
  Text,
  ThemeIcon,
  Title,
} from "@mantine/core";
import {
  IconActivityHeartbeat,
  IconBell,
  IconCertificate,
  IconFileSearch,
  IconFingerprint,
  IconHeadset,
  IconLock,
  IconPlugConnected,
  IconReportAnalytics,
  IconShieldCheck,
} from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { fmtMoney } from "../../components/format";
import { Wordmark } from "../../components/ui";

interface PublicPlan {
  key: string;
  name: string;
  description: string;
  currency: string;
  price_monthly_minor: number | null;
  price_annual_minor: number | null;
  contact_sales: boolean;
  entitlements: Record<string, number | boolean | string>;
}

const FEATURES = [
  { icon: IconFingerprint, title: "File-integrity monitoring", text: "SHA-256 inventories of your website files with baselines, so additions, modifications and deletions are detected between scans." },
  { icon: IconFileSearch, title: "Suspicious-file detection", text: "Documented rules flag scripts in upload folders, disguised extensions and known web-shell names for human review." },
  { icon: IconActivityHeartbeat, title: "Availability monitoring", text: "Regular HTTP checks with response times, so outages and anomalies are visible quickly." },
  { icon: IconCertificate, title: "TLS certificate checks", text: "Certificate validity and expiry tracking with early warnings before certificates lapse." },
  { icon: IconPlugConnected, title: "Provider-neutral connectors", text: "Connect through SFTP or cPanel UAPI today. Each connection's verified capabilities are shown, so you see exactly what is monitored." },
  { icon: IconBell, title: "Email and WhatsApp alerts", text: "Route alerts by severity, website and role, with escalation, quiet hours and delivery history." },
  { icon: IconReportAnalytics, title: "Reports and evidence", text: "Exportable CSV and PDF reports with timestamps and hashed evidence for audits and compliance reviews." },
  { icon: IconLock, title: "Security by design", text: "Tenant isolation, encrypted credentials, read-only monitoring by default, MFA and a tamper-evident audit trail." },
];

export function LandingPage() {
  const plans = useQuery({ queryKey: ["public-plans"], queryFn: () => api.get<PublicPlan[]>("/plans") });
  return (
    <Box bg="var(--cw-white)" c="var(--cw-navy)">
      <Box className="cw-hero" pb={80}>
        <Container size="lg" py="md">
          <Group justify="space-between">
            <Wordmark inverted />
            <Group gap="sm">
              <Button variant="subtle" color="gray.0" component={Link} to="/login">
                Sign in
              </Button>
              <Button component={Link} to="/register">
                Start free trial
              </Button>
            </Group>
          </Group>
        </Container>
        <Container size="lg" pt={72}>
          <Stack maw={720} gap="lg">
            <Badge variant="light" color="cyber" size="lg" w="fit-content">
              Website security monitoring · Managed cybersecurity
            </Badge>
            <Title order={1} fz={{ base: 34, sm: 48 }} lh={1.1} c="white">
              Continuous Monitoring. Smarter Protection. Greater Trust.
            </Title>
            <Text size="lg" c="gray.3">
              TrustData CyberWatch watches your websites for suspicious file changes, availability problems and certificate issues, and
              helps your team respond. Run it yourself, or let the Trust Data security team manage it for you.
            </Text>
            <Group>
              <Button size="md" component={Link} to="/register">
                Connect your first website
              </Button>
              <Button size="md" variant="outline" color="gray.0" component="a" href="#managed">
                Managed security service
              </Button>
            </Group>
          </Stack>
        </Container>
      </Box>

      <Container size="lg" py={72}>
        <Title order={2} ta="center" fz={30}>
          What CyberWatch monitors
        </Title>
        <Text ta="center" c="dimmed" mt="xs" mb={40} maw={640} mx="auto">
          Every check is backed by real scan results. If a hosting connection cannot support a check, CyberWatch tells you instead of
          pretending it is covered.
        </Text>
        <SimpleGrid cols={{ base: 1, sm: 2, md: 4 }} spacing="lg">
          {FEATURES.map((f) => (
            <Card key={f.title} shadow="none" style={{ background: "var(--cw-cloud)", borderColor: "var(--cw-border)" }}>
              <ThemeIcon size={40} radius="md" variant="light">
                <f.icon size={22} />
              </ThemeIcon>
              <Text fw={650} mt="md">
                {f.title}
              </Text>
              <Text size="sm" c="dimmed" mt={6}>
                {f.text}
              </Text>
            </Card>
          ))}
        </SimpleGrid>
      </Container>

      <Box bg="var(--cw-cloud)" py={72} id="managed">
        <Container size="lg">
          <SimpleGrid cols={{ base: 1, md: 2 }} spacing={48}>
            <Stack>
              <ThemeIcon size={44} radius="md">
                <IconShieldCheck size={24} />
              </ThemeIcon>
              <Title order={2}>Self-service</Title>
              <Text c="dimmed">
                Register, connect hosting accounts, choose checks within your plan, and receive alerts. Your team works incidents in the
                CyberWatch console.
              </Text>
              <List size="sm" spacing={6}>
                <List.Item>Guided onboarding for your first website</List.Item>
                <List.Item>Capability-aware monitoring configuration</List.Item>
                <List.Item>Incident centre, reports and team roles</List.Item>
              </List>
            </Stack>
            <Stack>
              <ThemeIcon size={44} radius="md" color="navy">
                <IconHeadset size={24} />
              </ThemeIcon>
              <Title order={2}>Managed security service</Title>
              <Text c="dimmed">
                Authorised Trust Data analysts monitor your estate, investigate incidents and report to you. Staff access is granted
                explicitly by your organisation, time-limited and fully audited.
              </Text>
              <List size="sm" spacing={6}>
                <List.Item>Investigation and response support</List.Item>
                <List.Item>Periodic security reporting</List.Item>
                <List.Item>Remediation only with your recorded approval</List.Item>
              </List>
            </Stack>
          </SimpleGrid>
        </Container>
      </Box>

      <Container size="lg" py={72} id="plans">
        <Title order={2} ta="center" fz={30}>
          Plans
        </Title>
        <Text ta="center" c="dimmed" mt="xs" mb={40}>
          Prices in Nigerian Naira. Every new organisation starts on a trial.
        </Text>
        <SimpleGrid cols={{ base: 1, sm: 2, lg: 5 }} spacing="md">
          {(plans.data ?? []).map((p) => (
            <Card key={p.key} style={{ borderColor: p.key === "business" ? "var(--cw-blue)" : undefined }}>
              <Text fw={700}>{p.name}</Text>
              <Text size="sm" c="dimmed" mih={42}>
                {p.description}
              </Text>
              <Text className="cw-metric" fz={24} mt="sm">
                {p.contact_sales ? "Contact us" : fmtMoney(p.price_monthly_minor, p.currency)}
              </Text>
              {!p.contact_sales && (
                <Text size="xs" c="dimmed">
                  per month
                </Text>
              )}
              <Divider my="sm" />
              <List size="xs" spacing={4}>
                <List.Item>{String(p.entitlements.max_websites)} websites</List.Item>
                <List.Item>{String(p.entitlements.max_hosting_accounts)} hosting connections</List.Item>
                <List.Item>File scans as often as every {String(p.entitlements.min_file_scan_interval_minutes)} min</List.Item>
                <List.Item>{String(p.entitlements.retention_days)} days history</List.Item>
                {p.entitlements.whatsapp_notifications ? <List.Item>WhatsApp alerts</List.Item> : null}
                {p.entitlements.managed_service ? <List.Item>Managed by Trust Data</List.Item> : null}
              </List>
              <Button mt="md" fullWidth variant={p.key === "business" ? "filled" : "light"} component={Link} to={p.contact_sales ? "#contact" : "/register"}>
                {p.contact_sales ? "Talk to us" : "Start trial"}
              </Button>
            </Card>
          ))}
        </SimpleGrid>
        {plans.isError && (
          <Text ta="center" c="dimmed">
            Plan information is temporarily unavailable.
          </Text>
        )}
      </Container>

      <Box bg="var(--cw-navy)" c="gray.3" py={56} id="contact">
        <Container size="lg">
          <SimpleGrid cols={{ base: 1, md: 2 }} spacing={40}>
            <Stack gap="xs">
              <Wordmark inverted />
              <Text size="sm" mt="sm">
                A product of Trust Data Compliance Ltd, Nigeria. To discuss managed security or enterprise plans, contact our team.
              </Text>
              <Anchor href="mailto:team@trustdata.ng" c="cyber.3">
                team@trustdata.ng
              </Anchor>
            </Stack>
            <Text size="xs" c="gray.5">
              Monitoring detects many signs of compromise but cannot guarantee detection or prevention of every attack. File polling detects
              changes between scans, not every transient change. Malware scanning, log analysis and real-time file events are only active where
              a connection has verified support. CyberWatch does not modify customer files without separately recorded authorisation.
            </Text>
          </SimpleGrid>
          <Text size="xs" c="gray.6" mt="xl">
            © {new Date().getFullYear()} Trust Data Compliance Ltd.
          </Text>
        </Container>
      </Box>
    </Box>
  );
}
