/** Reusable layout and state components shared by all three portals. */
import {
  Alert,
  Anchor,
  Box,
  Breadcrumbs,
  Button,
  Card,
  Center,
  Group,
  Modal,
  Pagination,
  Skeleton,
  Stack,
  Table,
  Text,
  TextInput,
  ThemeIcon,
  Title,
  UnstyledButton,
  type ButtonProps,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconAlertCircle,
  IconArrowDownRight,
  IconArrowUpRight,
  IconChevronDown,
  IconChevronRight,
  IconChevronUp,
  IconFlask,
  IconInbox,
  IconRefresh,
  IconSearch,
  type Icon,
} from "@tabler/icons-react";
import { type ReactNode, useState } from "react";
import { Link } from "react-router-dom";
import { errorMessage } from "../api/client";

// ---------------------------------------------------------------- brand

export function BrandMark({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" role="img" aria-label="CyberWatch shield">
      <path d="M16 2 4 6.5v8.2C4 22.4 9.1 28.2 16 30c6.9-1.8 12-7.6 12-15.3V6.5Z" fill="#1677FF" />
      <path d="m10.5 16.2 3.8 3.8 7.4-7.6" fill="none" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Wordmark({ compact = false, inverted = false }: { compact?: boolean; inverted?: boolean }) {
  return (
    <Group gap={10} wrap="nowrap">
      <BrandMark />
      {!compact && (
        <Box lh={1.1}>
          <Text fw={700} size="md" c={inverted ? "white" : undefined}>
            <Text span inherit c="cyber.6">TrustData</Text> CyberWatch
          </Text>
          <Text size="10px" c={inverted ? "gray.4" : "dimmed"} tt="uppercase" fw={600} style={{ letterSpacing: 0.6 }}>
            Trust Data Compliance Ltd
          </Text>
        </Box>
      )}
    </Group>
  );
}

// ---------------------------------------------------------------- page structure

export interface Crumb {
  label: string;
  to?: string;
}

export function PageHeader({
  title,
  description,
  crumbs,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  crumbs?: Crumb[];
  actions?: ReactNode;
}) {
  return (
    <Stack gap={6} mb="lg">
      {crumbs && crumbs.length > 0 && (
        <Breadcrumbs separator={<IconChevronRight size={12} />} separatorMargin={4}>
          {crumbs.map((c) =>
            c.to ? (
              <Anchor key={c.label} component={Link} to={c.to} size="sm" c="dimmed">
                {c.label}
              </Anchor>
            ) : (
              <Text key={c.label} size="sm" c="dimmed">
                {c.label}
              </Text>
            ),
          )}
        </Breadcrumbs>
      )}
      <Group justify="space-between" align="flex-start" wrap="wrap" gap="sm">
        <Box style={{ minWidth: 0, flex: 1 }}>
          <Title order={1}>{title}</Title>
          {description &&
            (typeof description === "string" ? (
              <Text c="dimmed" size="sm" mt={4} maw={760}>
                {description}
              </Text>
            ) : (
              <Box c="dimmed" fz="sm" mt={4} maw={760}>
                {description}
              </Box>
            ))}
        </Box>
        {actions && <Group gap="sm">{actions}</Group>}
      </Group>
    </Stack>
  );
}

export function Section({ title, description, actions, children }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <Card>
      <Group justify="space-between" mb="md" wrap="wrap" gap="xs">
        <Box>
          <Title order={3}>{title}</Title>
          {description && (
            <Text size="sm" c="dimmed" mt={2}>
              {description}
            </Text>
          )}
        </Box>
        {actions}
      </Group>
      {children}
    </Card>
  );
}

// ---------------------------------------------------------------- metric cards

export function StatCard({
  label,
  value,
  context,
  icon: IconCmp,
  tone = "cyber",
  to,
  trend,
  loading,
}: {
  label: string;
  value: ReactNode;
  context?: ReactNode;
  icon?: Icon;
  tone?: string;
  to?: string;
  trend?: { direction: "up" | "down"; text: string; good?: boolean };
  loading?: boolean;
}) {
  const body = (
    <Card h="100%" style={{ transition: "border-color 120ms ease" }}>
      <Group justify="space-between" align="flex-start" wrap="nowrap">
        <Text size="xs" c="dimmed" tt="uppercase" fw={600} style={{ letterSpacing: 0.4 }}>
          {label}
        </Text>
        {IconCmp && (
          <ThemeIcon variant="light" color={tone} size={30} radius="md" aria-hidden>
            <IconCmp size={17} />
          </ThemeIcon>
        )}
      </Group>
      {loading ? (
        <Skeleton h={30} w="50%" mt="sm" />
      ) : (
        <Text className="cw-metric" fz={28} mt={6}>
          {value}
        </Text>
      )}
      <Group gap={6} mt={6} wrap="nowrap">
        {trend && (
          <Text size="xs" c={trend.good ? "secure.7" : "threat.6"} fw={600} style={{ display: "flex", alignItems: "center" }}>
            {trend.direction === "up" ? <IconArrowUpRight size={14} /> : <IconArrowDownRight size={14} />}
            {trend.text}
          </Text>
        )}
        {context && (
          <Text size="xs" c="dimmed" lineClamp={2}>
            {context}
          </Text>
        )}
      </Group>
      {to && (
        <Text size="xs" c="cyber.6" fw={600} mt="sm">
          View details →
        </Text>
      )}
    </Card>
  );
  return to ? (
    <UnstyledButton component={Link} to={to} style={{ display: "block", height: "100%" }} aria-label={`${label}: view details`}>
      {body}
    </UnstyledButton>
  ) : (
    body
  );
}

// ---------------------------------------------------------------- states

export function EmptyState({ title, description, action, icon: IconCmp = IconInbox }: { title: string; description?: ReactNode; action?: ReactNode; icon?: Icon }) {
  return (
    <Center py={40}>
      <Stack align="center" gap="xs" maw={440} ta="center">
        <ThemeIcon variant="light" color="gray" size={48} radius="xl" aria-hidden>
          <IconCmp size={24} />
        </ThemeIcon>
        <Text fw={600}>{title}</Text>
        {description && (
          <Text size="sm" c="dimmed">
            {description}
          </Text>
        )}
        {action}
      </Stack>
    </Center>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <Alert color="threat" variant="light" icon={<IconAlertCircle />} title="This information could not be loaded" role="alert">
      <Text size="sm">{errorMessage(error)}</Text>
      {onRetry && (
        <Button size="xs" variant="subtle" mt="xs" leftSection={<IconRefresh size={14} />} onClick={onRetry}>
          Try again
        </Button>
      )}
    </Alert>
  );
}

export function LoadingBlock({ rows = 4 }: { rows?: number }) {
  return (
    <Stack gap="sm" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} h={18} radius="sm" w={`${90 - i * 8}%`} />
      ))}
    </Stack>
  );
}

export function DemoBanner() {
  return (
    <Alert color="amber" variant="light" icon={<IconFlask />} mb="md" title="Demonstration data">
      This organisation contains synthetic data for demonstration only. It does not reflect real monitoring results.
    </Alert>
  );
}

// ---------------------------------------------------------------- confirmation

export function ConfirmButton({
  children,
  title,
  message,
  confirmLabel = "Confirm",
  onConfirm,
  danger = false,
  loading,
  ...props
}: ButtonProps & {
  children: ReactNode;
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  onConfirm: () => void | Promise<unknown>;
  danger?: boolean;
  loading?: boolean;
}) {
  const [opened, { open, close }] = useDisclosure(false);
  return (
    <>
      <Button {...props} color={danger ? "threat" : props.color} onClick={open} loading={loading}>
        {children}
      </Button>
      <Modal opened={opened} onClose={close} title={<Text fw={650}>{title}</Text>}>
        <Text size="sm">{message}</Text>
        <Group justify="flex-end" mt="lg">
          <Button variant="default" onClick={close}>
            Cancel
          </Button>
          <Button
            color={danger ? "threat" : "cyber"}
            onClick={async () => {
              await onConfirm();
              close();
            }}
          >
            {confirmLabel}
          </Button>
        </Group>
      </Modal>
    </>
  );
}

// ---------------------------------------------------------------- data table

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  sortable?: boolean;
  width?: number | string;
  visibleFrom?: "sm" | "md" | "lg";
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading,
  error,
  onRetry,
  empty,
  page,
  pageSize,
  total,
  onPage,
  sort,
  onSort,
  onRowClick,
  caption,
}: {
  columns: Column<T>[];
  rows?: T[];
  rowKey: (row: T) => string;
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  empty?: ReactNode;
  page?: number;
  pageSize?: number;
  total?: number;
  onPage?: (p: number) => void;
  sort?: string;
  onSort?: (s: string) => void;
  onRowClick?: (row: T) => void;
  caption?: string;
}) {
  if (error) return <ErrorState error={error} onRetry={onRetry} />;
  const pages = total && pageSize ? Math.max(1, Math.ceil(total / pageSize)) : 1;
  return (
    <Stack gap="sm">
      <div className="cw-table-scroll">
        <Table highlightOnHover={!!onRowClick} striped={false} miw={560}>
          {caption && <Table.Caption>{caption}</Table.Caption>}
          <Table.Thead>
            <Table.Tr>
              {columns.map((c) => {
                const active = sort?.replace("-", "") === c.key;
                const desc = sort?.startsWith("-");
                return (
                  <Table.Th key={c.key} w={c.width} visibleFrom={c.visibleFrom} aria-sort={active ? (desc ? "descending" : "ascending") : undefined}>
                    {c.sortable && onSort ? (
                      <UnstyledButton onClick={() => onSort(active && !desc ? `-${c.key}` : c.key)} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                        <Text size="xs" fw={650} c="dimmed" tt="uppercase">
                          {c.header}
                        </Text>
                        {active ? desc ? <IconChevronDown size={12} /> : <IconChevronUp size={12} /> : null}
                      </UnstyledButton>
                    ) : (
                      <Text size="xs" fw={650} c="dimmed" tt="uppercase">
                        {c.header}
                      </Text>
                    )}
                  </Table.Th>
                );
              })}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {loading &&
              Array.from({ length: 5 }).map((_, i) => (
                <Table.Tr key={`sk${i}`}>
                  {columns.map((c) => (
                    <Table.Td key={c.key} visibleFrom={c.visibleFrom}>
                      <Skeleton h={14} radius="sm" />
                    </Table.Td>
                  ))}
                </Table.Tr>
              ))}
            {!loading &&
              rows?.map((r) => (
                <Table.Tr
                  key={rowKey(r)}
                  onClick={onRowClick ? () => onRowClick(r) : undefined}
                  style={onRowClick ? { cursor: "pointer" } : undefined}
                  tabIndex={onRowClick ? 0 : undefined}
                  onKeyDown={onRowClick ? (e) => e.key === "Enter" && onRowClick(r) : undefined}
                >
                  {columns.map((c) => (
                    <Table.Td key={c.key} visibleFrom={c.visibleFrom}>
                      {c.render(r)}
                    </Table.Td>
                  ))}
                </Table.Tr>
              ))}
          </Table.Tbody>
        </Table>
      </div>
      {!loading && rows && rows.length === 0 && (empty ?? <EmptyState title="Nothing to show yet" />)}
      {onPage && total !== undefined && total > (pageSize ?? 0) && (
        <Group justify="space-between">
          <Text size="xs" c="dimmed">
            {total.toLocaleString()} results
          </Text>
          <Pagination size="sm" value={page} onChange={onPage} total={pages} />
        </Group>
      )}
    </Stack>
  );
}

export function SearchInput({ value, onChange, placeholder = "Search…" }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  const [v, setV] = useState(value);
  return (
    <TextInput
      leftSection={<IconSearch size={15} />}
      placeholder={placeholder}
      value={v}
      aria-label={placeholder}
      onChange={(e) => {
        setV(e.currentTarget.value);
        onChange(e.currentTarget.value);
      }}
      w={{ base: "100%", sm: 280 }}
    />
  );
}

export function KeyValue({ items }: { items: [string, ReactNode][] }) {
  return (
    <Stack gap={8}>
      {items.map(([k, v]) => (
        <Group key={k} justify="space-between" wrap="nowrap" align="flex-start" gap="md">
          <Text size="sm" c="dimmed" style={{ flexShrink: 0 }}>
            {k}
          </Text>
          <Box ta="right" style={{ minWidth: 0 }}>
            {typeof v === "string" || typeof v === "number" ? <Text size="sm">{v}</Text> : v}
          </Box>
        </Group>
      ))}
    </Stack>
  );
}
