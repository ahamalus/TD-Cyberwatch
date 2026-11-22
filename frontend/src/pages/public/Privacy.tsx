import { Anchor, Box, Container, List, Stack, Table, Text, Title } from "@mantine/core";
import { Link } from "react-router-dom";
import { Wordmark } from "../../components/ui";

const CONTACT = "team@trustdata.ng";
const UPDATED = "22 November 2026";

const PROCESSORS: [string, string, string, string][] = [
  ["Cloudflare, Inc.", "Secure network connection to the service (tunnel and web protection)", "All web traffic in transit (encrypted between your browser and Cloudflare, and between Cloudflare and our servers)", "Global network, including the United States"],
  ["Zoho Corporation", "Sending email (alerts, sign-in and account messages)", "Recipient email address, message content", "Zoho data centres (United States and other regions)"],
  ["Paystack Payments Ltd", "Card and bank payments", "Name and email of the payer, payment details (entered on Paystack's page; card numbers never reach CyberWatch)", "Nigeria"],
  ["Meta Platforms (WhatsApp Business)", "WhatsApp alerts, only if you turn them on", "Phone number, alert text", "United States and other regions"],
];

export function PrivacyPage() {
  return (
    <Container size="md" py="xl">
      <Box mb="lg"><Link to="/" style={{ textDecoration: "none", color: "inherit" }}><Wordmark /></Link></Box>
      <Stack gap="md">
        <Title order={1}>Privacy notice</Title>
        <Text c="dimmed" size="sm">Last updated {UPDATED}. Prepared under the Nigeria Data Protection Act 2023 (NDPA).</Text>

        <Title order={2}>Who we are</Title>
        <Text>
          TrustData CyberWatch is operated by Trust Data Compliance Ltd, Nigeria ("we"). For the accounts, billing and alerts of the
          service we are the <b>data controller</b>. For the content of the websites and hosting accounts you ask us to monitor, your
          organisation is the controller and we process that content <b>on your behalf</b> (as a data processor). Contact us about privacy
          at <Anchor href={`mailto:${CONTACT}`}>{CONTACT}</Anchor>.
        </Text>

        <Title order={2}>What we collect and why</Title>
        <Table striped withTableBorder>
          <Table.Thead>
            <Table.Tr><Table.Th>Data</Table.Th><Table.Th>Purpose</Table.Th><Table.Th>Lawful basis (NDPA s.25)</Table.Th></Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            <Table.Tr><Table.Td>Name, work email, phone (optional), organisation, role</Table.Td><Table.Td>Your account, alerts and support</Table.Td><Table.Td>Contract</Table.Td></Table.Tr>
            <Table.Tr><Table.Td>Sign-in records: time, IP address, browser, outcome; active sessions</Table.Td><Table.Td>Account security and fraud prevention</Table.Td><Table.Td>Legitimate interest; security obligations</Table.Td></Table.Tr>
            <Table.Tr><Table.Td>Audit trail of actions taken in the service</Table.Td><Table.Td>Accountability, security investigations, evidence</Table.Td><Table.Td>Legal obligation; legitimate interest</Table.Td></Table.Tr>
            <Table.Tr><Table.Td>Billing details (payer name and email, amounts, Paystack references)</Table.Td><Table.Td>Payments, invoices, refunds</Table.Td><Table.Td>Contract; legal obligation (tax records)</Table.Td></Table.Tr>
            <Table.Tr><Table.Td>WhatsApp number and your consent</Table.Td><Table.Td>WhatsApp alerts, only if you opt in</Table.Td><Table.Td>Consent (reply STOP or turn it off at any time)</Table.Td></Table.Tr>
            <Table.Tr><Table.Td>Website files and metadata from hosting you connect (paths, sizes, fingerprints, short excerpts of suspicious code)</Table.Td><Table.Td>Integrity and malware monitoring for your organisation</Table.Td><Table.Td>Processed on your organisation's instructions (contract)</Table.Td></Table.Tr>
          </Table.Tbody>
        </Table>
        <Text size="sm">
          File contents are read only to compute fingerprints and scan for malware; they are not stored, except short excerpts of code that
          matched a malware rule, kept as evidence in the incident. Hosting credentials are stored encrypted. We do not sell personal data
          or use it for advertising. We use only cookies that are needed to keep you signed in and protect forms; no tracking or advertising
          cookies.
        </Text>

        <Title order={2}>Who we share it with</Title>
        <Text>We use these service providers (sub-processors), under contracts that require them to protect the data:</Text>
        <Table withTableBorder>
          <Table.Thead><Table.Tr><Table.Th>Provider</Table.Th><Table.Th>Purpose</Table.Th><Table.Th>Data involved</Table.Th><Table.Th>Location</Table.Th></Table.Tr></Table.Thead>
          <Table.Tbody>
            {PROCESSORS.map(([name, purpose, data, where]) => (
              <Table.Tr key={name}><Table.Td>{name}</Table.Td><Table.Td>{purpose}</Table.Td><Table.Td>{data}</Table.Td><Table.Td>{where}</Table.Td></Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        <Text size="sm">
          CyberWatch itself, including its database and backups, runs on servers operated by Trust Data in Nigeria. Where a provider processes
          data outside Nigeria, we rely on the safeguards the NDPA allows for international transfers (s.41–43), such as the provider's
          contractual commitments. Trust Data staff can see an organisation's monitoring data only when the organisation grants access, and
          every such access is recorded.
        </Text>

        <Title order={2}>How long we keep it</Title>
        <List size="sm" spacing={4}>
          <List.Item>Account data: while the account is active; deleted or anonymised on request or after the organisation closes.</List.Item>
          <List.Item>Sign-in history: 12 months. Ended sessions: 30 days.</List.Item>
          <List.Item>Monitoring history (scans, checks, changes): as set by your plan's retention period (30 days or more).</List.Item>
          <List.Item>Audit trail and billing records: kept as long as required for security, legal and tax purposes. These records can't
            be changed, because that is what makes them trustworthy. When an account is anonymised, they keep only a random identifier.</List.Item>
          <List.Item>Encrypted backups: 30 days on our servers and 60 days in our off-site copy.</List.Item>
        </List>

        <Title order={2}>Your rights</Title>
        <Text>
          Under the NDPA you can ask to access, correct, move (portability) or erase your personal data, to restrict or object to processing,
          and to withdraw consent at any time. You can download your data yourself under <b>Account security → Download my data</b>, and
          correct your profile in Settings. For anything else, email <Anchor href={`mailto:${CONTACT}`}>{CONTACT}</Anchor>; we reply within 30 days.
          If you are a member of a customer organisation and your question is about the content of its websites, we will refer you to that
          organisation. You may also complain to the Nigeria Data Protection Commission (NDPC).
        </Text>

        <Title order={2}>Security and breaches</Title>
        <Text>
          Data is encrypted in transit, hosting credentials and backups are encrypted at rest, staff access requires multi-factor
          authentication, and a tamper-evident audit trail records actions. If a personal data breach is likely to put your rights at risk,
          we will notify the NDPC within 72 hours and inform affected people without undue delay, as the NDPA requires.
        </Text>

        <Text size="sm" c="dimmed">
          Changes to this notice will be published on this page. <Anchor component={Link} to="/">Back to TrustData CyberWatch</Anchor>
        </Text>
      </Stack>
    </Container>
  );
}
