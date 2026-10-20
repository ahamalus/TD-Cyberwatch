/**
 * Security-specific status indicators. Every indicator pairs colour with an
 * icon and a text label, so status is never conveyed by colour alone.
 */
import { Badge, Group, Text, ThemeIcon, Tooltip } from "@mantine/core";
import {
  IconAlertOctagon,
  IconAlertTriangle,
  IconBan,
  IconCircleCheck,
  IconCircleDashed,
  IconCircleX,
  IconClock,
  IconHelpCircle,
  IconInfoCircle,
  IconLoader2,
  IconPlayerPause,
  IconPlugConnected,
  IconPlugConnectedX,
  IconShieldCheck,
  IconShieldQuestion,
  type Icon,
} from "@tabler/icons-react";
import type { ReactNode } from "react";
import { humanize } from "./format";

type Tone = "secure" | "amber" | "threat" | "info" | "gray" | "cyber";

interface Spec {
  tone: Tone;
  icon: Icon;
  label?: string;
}

function StatusBadge({ spec, value, size = "sm", tooltip }: { spec: Spec; value: string; size?: string; tooltip?: ReactNode }) {
  const IconCmp = spec.icon;
  const badge = (
    <Badge
      color={spec.tone}
      size={size}
      leftSection={<IconCmp size={12} stroke={2.2} aria-hidden />}
      styles={{ root: { textTransform: "none", fontWeight: 600, flexShrink: 0, overflow: "visible" }, label: { overflow: "visible" } }}
    >
      {spec.label ?? humanize(value)}
    </Badge>
  );
  return tooltip ? <Tooltip label={tooltip}>{badge}</Tooltip> : badge;
}

const SEVERITY: Record<string, Spec> = {
  critical: { tone: "threat", icon: IconAlertOctagon, label: "Critical" },
  high: { tone: "threat", icon: IconAlertTriangle, label: "High" },
  medium: { tone: "amber", icon: IconAlertTriangle, label: "Medium" },
  low: { tone: "info", icon: IconInfoCircle, label: "Low" },
  informational: { tone: "gray", icon: IconInfoCircle, label: "Info" },
};

export function SeverityBadge({ severity, size }: { severity: string; size?: string }) {
  return <StatusBadge spec={SEVERITY[severity] ?? SEVERITY.informational} value={severity} size={size} />;
}

const INCIDENT_STATUS: Record<string, Spec> = {
  new: { tone: "threat", icon: IconCircleDashed, label: "New" },
  acknowledged: { tone: "amber", icon: IconClock, label: "Acknowledged" },
  investigating: { tone: "cyber", icon: IconLoader2, label: "Investigating" },
  contained: { tone: "info", icon: IconShieldCheck, label: "Contained" },
  resolved: { tone: "secure", icon: IconCircleCheck, label: "Resolved" },
  closed: { tone: "gray", icon: IconCircleCheck, label: "Closed" },
};

export function IncidentStatusBadge({ status }: { status: string }) {
  return <StatusBadge spec={INCIDENT_STATUS[status] ?? { tone: "gray", icon: IconHelpCircle }} value={status} />;
}

/** Healthy / Degraded / Failed / Unknown monitoring states. */
const HEALTH: Record<string, Spec> = {
  healthy: { tone: "secure", icon: IconCircleCheck, label: "Healthy" },
  active: { tone: "secure", icon: IconCircleCheck, label: "Active" },
  full: { tone: "secure", icon: IconShieldCheck, label: "Full coverage" },
  up: { tone: "secure", icon: IconCircleCheck, label: "Up" },
  valid: { tone: "secure", icon: IconShieldCheck, label: "Valid" },
  degraded: { tone: "amber", icon: IconAlertTriangle, label: "Degraded" },
  partial: { tone: "amber", icon: IconAlertTriangle, label: "Partial coverage" },
  expiring: { tone: "amber", icon: IconClock, label: "Expiring" },
  pending: { tone: "info", icon: IconClock, label: "Pending" },
  failed: { tone: "threat", icon: IconCircleX, label: "Failed" },
  down: { tone: "threat", icon: IconCircleX, label: "Down" },
  error: { tone: "threat", icon: IconCircleX, label: "Error" },
  expired: { tone: "threat", icon: IconCircleX, label: "Expired" },
  invalid: { tone: "threat", icon: IconCircleX, label: "Invalid" },
  none: { tone: "threat", icon: IconCircleX, label: "Not monitored" },
  disabled: { tone: "gray", icon: IconPlayerPause, label: "Disabled" },
  paused: { tone: "gray", icon: IconPlayerPause, label: "Paused" },
  unavailable: { tone: "gray", icon: IconBan, label: "Unavailable" },
  unsupported: { tone: "gray", icon: IconBan, label: "Unsupported" },
  not_applicable: { tone: "gray", icon: IconBan, label: "Not applicable" },
  unknown: { tone: "gray", icon: IconHelpCircle, label: "Unknown" },
};

export function HealthBadge({ state, tooltip, size }: { state?: string | null; tooltip?: ReactNode; size?: string }) {
  const s = state ?? "unknown";
  return <StatusBadge spec={HEALTH[s] ?? HEALTH.unknown} value={s} tooltip={tooltip} size={size} />;
}

/** Connected / Disconnected / Expired hosting connections. */
const CONNECTION: Record<string, Spec> = {
  connected: { tone: "secure", icon: IconPlugConnected, label: "Connected" },
  untested: { tone: "info", icon: IconClock, label: "Not yet tested" },
  disconnected: { tone: "amber", icon: IconPlugConnectedX, label: "Disconnected" },
  auth_failed: { tone: "threat", icon: IconPlugConnectedX, label: "Credentials rejected" },
  expired: { tone: "threat", icon: IconPlugConnectedX, label: "Expired" },
  error: { tone: "threat", icon: IconCircleX, label: "Error" },
};

export function ConnectionBadge({ status }: { status: string }) {
  return <StatusBadge spec={CONNECTION[status] ?? { tone: "gray", icon: IconHelpCircle }} value={status} />;
}

/** Successful / Failed / Partial / Incomplete scans and jobs. */
const SCAN: Record<string, Spec> = {
  completed: { tone: "secure", icon: IconCircleCheck, label: "Successful" },
  succeeded: { tone: "secure", icon: IconCircleCheck, label: "Succeeded" },
  partial: { tone: "amber", icon: IconAlertTriangle, label: "Partial" },
  running: { tone: "cyber", icon: IconLoader2, label: "Running" },
  queued: { tone: "info", icon: IconClock, label: "Queued" },
  failed: { tone: "threat", icon: IconCircleX, label: "Failed" },
  cancelled: { tone: "gray", icon: IconBan, label: "Cancelled" },
  incomplete: { tone: "amber", icon: IconCircleDashed, label: "Incomplete" },
};

export function ScanBadge({ status }: { status?: string | null }) {
  if (!status) return <StatusBadge spec={{ tone: "gray", icon: IconCircleDashed, label: "No scan yet" }} value="none" />;
  return <StatusBadge spec={SCAN[status] ?? { tone: "gray", icon: IconHelpCircle }} value={status} />;
}

/** Verified vs unverified security findings. */
export function VerificationBadge({ requiresHuman, confidence }: { requiresHuman: boolean; confidence: string }) {
  return requiresHuman ? (
    <StatusBadge
      spec={{ tone: "amber", icon: IconShieldQuestion, label: `Unverified · ${humanize(confidence)} confidence` }}
      value="unverified"
      tooltip="Heuristic finding. A person should verify it; it is not proof of compromise."
    />
  ) : (
    <StatusBadge spec={{ tone: "secure", icon: IconShieldCheck, label: `Verified · ${humanize(confidence)} confidence` }} value="verified" />
  );
}

/** Active / Trial / Grace period / Cancelled / Expired subscriptions. */
const SUBSCRIPTION: Record<string, Spec> = {
  active: { tone: "secure", icon: IconCircleCheck, label: "Active" },
  trialing: { tone: "cyber", icon: IconClock, label: "Trial" },
  past_due: { tone: "amber", icon: IconAlertTriangle, label: "Past due" },
  grace_period: { tone: "amber", icon: IconClock, label: "Grace period" },
  cancelled: { tone: "gray", icon: IconBan, label: "Cancelled" },
  expired: { tone: "threat", icon: IconCircleX, label: "Expired" },
};

export function SubscriptionBadge({ status }: { status?: string | null }) {
  return <StatusBadge spec={SUBSCRIPTION[status ?? ""] ?? { tone: "gray", icon: IconHelpCircle, label: "No subscription" }} value={status ?? "none"} />;
}

const CAPABILITY: Record<string, Spec> = {
  available: { tone: "secure", icon: IconCircleCheck, label: "Available" },
  unavailable: { tone: "threat", icon: IconCircleX, label: "Unavailable" },
  untested: { tone: "info", icon: IconCircleDashed, label: "Untested" },
  unsupported: { tone: "gray", icon: IconBan, label: "Unsupported" },
};

export function CapabilityBadge({ status }: { status: string }) {
  return <StatusBadge spec={CAPABILITY[status] ?? CAPABILITY.untested} value={status} />;
}

export function Dot({ tone, label }: { tone: Tone; label: string }) {
  return (
    <Group gap={6} wrap="nowrap">
      <ThemeIcon size={8} radius="xl" color={tone} aria-hidden>
        <span />
      </ThemeIcon>
      <Text size="sm">{label}</Text>
    </Group>
  );
}
