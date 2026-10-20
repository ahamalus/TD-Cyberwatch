export type UUID = string;

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface Membership {
  tenant_id: UUID;
  tenant_name: string;
  tenant_status: string;
  is_demo: boolean;
  role: string;
  permissions: string[];
}

export interface Me {
  id: UUID;
  email: string;
  full_name: string;
  phone: string | null;
  email_verified: boolean;
  mfa_enabled: boolean;
  is_platform_staff: boolean;
  platform_roles: string[];
  platform_permissions: string[];
  platform_mfa_required: boolean;
  preferences: Record<string, unknown>;
  memberships: Membership[];
}

export interface Tenant {
  id: UUID;
  name: string;
  slug: string;
  status: string;
  country: string;
  industry: string | null;
  contact_email: string | null;
  contact_phone: string | null;
  timezone: string;
  is_demo: boolean;
  created_at: string;
  role: string | null;
  permissions: string[];
  via_managed_service_grant: boolean;
  read_only: boolean;
  entitlements: Record<string, number | boolean | string>;
  usage: { websites: number; hosting_accounts: number; users: number };
  plan: { key: string | null; name: string | null; status: string | null; in_service: boolean };
}

export interface CoverageCheck {
  key: string;
  label: string;
  state: string;
  detail: string;
  freshness?: string;
  last_success?: string | null;
  last_status?: string | null;
  last_checked?: string | null;
  expires_at?: string | null;
  hashing?: boolean;
}

export interface Coverage {
  overall: "full" | "partial" | "none" | "paused";
  checks: CoverageCheck[];
  reasons: string[];
  active_core_checks: number;
  core_checks: number;
}

export interface MonitoringConfig {
  file_scan_enabled: boolean;
  file_scan_interval_minutes: number;
  availability_enabled: boolean;
  availability_interval_minutes: number;
  tls_enabled: boolean;
  tls_expiry_warning_days: number;
  availability_failure_threshold: number;
  slow_response_ms: number;
  incident_min_severity: string;
  exclusions: string[];
  critical_paths: string[];
  max_file_bytes: number | null;
  max_total_mb: number | null;
  max_files: number | null;
  maintenance_windows: { start: string; end: string; weekday: number | null; timezone: string; label?: string }[];
}

export interface Website {
  id: UUID;
  name: string;
  url: string;
  hostname: string;
  environment: string;
  group_id: UUID | null;
  group_name: string | null;
  hosting_account_id: UUID | null;
  hosting_account_name: string | null;
  document_root: string | null;
  technology: string | null;
  notes: string | null;
  status: string;
  verification_status: string;
  verified_at: string | null;
  baseline_snapshot_id: UUID | null;
  baseline_approved_at: string | null;
  last_scan_at: string | null;
  last_scan_status: string | null;
  last_successful_scan_at: string | null;
  last_availability_at: string | null;
  last_availability_status: string | null;
  last_tls_status: string | null;
  tls_expires_at: string | null;
  created_at: string;
  coverage: Coverage | null;
  monitoring: MonitoringConfig | null;
}

export interface Capability {
  capability: string;
  label: string;
  status: "available" | "unavailable" | "untested" | "unsupported";
  detail: string;
  required_permission: string | null;
  discovered_at: string | null;
}

export interface HostingAccount {
  id: UUID;
  name: string;
  connector_type: string;
  connector_name: string;
  provider_name: string | null;
  hostname: string;
  port: number;
  username: string;
  root_path: string;
  status: string;
  credential_kind: string | null;
  credential_fingerprint: string | null;
  credential_rotated_at: string | null;
  host_key_type: string | null;
  host_key_fingerprint: string | null;
  host_key_confirmed_at: string | null;
  last_tested_at: string | null;
  last_success_at: string | null;
  last_error_code: string | null;
  last_error_message: string | null;
  website_count: number;
  log_paths: string[];
  capabilities: Capability[];
  last_test_job: {
    id: string;
    status: string;
    queued_at: string;
    finished_at: string | null;
    result: { ok?: boolean; diagnostics?: { step: string; ok: boolean; message: string; code: string | null }[] };
    error: string | null;
  } | null;
  created_at: string;
}

export interface ConnectorInfo {
  key: string;
  name: string;
  status: string;
  version: string;
  description: string;
  default_port: number | null;
  credential_kinds: string[];
}

export interface Incident {
  id: UUID;
  reference: string;
  title: string;
  summary: string;
  category: string;
  finding_class: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  confidence: string;
  status: string;
  detection_source: string;
  rule_key: string;
  website_id: UUID | null;
  website_name: string | null;
  first_detected_at: string;
  last_observed_at: string;
  occurrence_count: number;
  assigned_to: UUID | null;
  assigned_to_name: string | null;
  requires_human_verification: boolean;
  risk_score: number | null;
  is_false_positive: boolean;
  is_demo: boolean;
  resolved_at: string | null;
  closed_at: string | null;
}

export interface IncidentDetail extends Incident {
  recommended_action: string;
  affected_resources: Record<string, unknown>[];
  risk_explanation: { factor: string; points: number; detail: string }[];
  resolution_notes: string | null;
  history_verified: boolean;
  events: {
    seq: number;
    event_type: string;
    actor_type: string;
    actor_name: string | null;
    from_status: string | null;
    to_status: string | null;
    body: string | null;
    data: Record<string, unknown>;
    is_manual: boolean;
    created_at: string;
    hash: string;
  }[];
  evidence: {
    id: string;
    kind: string;
    source: string;
    collection_method: string;
    collected_at: string;
    content: Record<string, unknown>;
    content_sha256: string;
    integrity_ok: boolean;
  }[];
  notifications: { channel: string; recipient: string; status: string; attempts: number; sent_at: string | null; last_error: string | null; created_at: string }[];
  allowed_transitions: string[];
}

export interface FileChange {
  id: string;
  website_id: string;
  website_name: string | null;
  snapshot_id: string;
  path: string;
  old_path: string | null;
  change_type: string;
  entry_type: string;
  old_sha256: string | null;
  new_sha256: string | null;
  old_size: number | null;
  new_size: number | null;
  confidence: string;
  flags: string[];
  severity: string;
  detected_at: string;
}

export interface Snapshot {
  id: string;
  website_id: string;
  status: string;
  connector_type: string;
  root_path: string;
  started_at: string;
  completed_at: string | null;
  files_seen: number;
  dirs_seen: number;
  files_hashed: number;
  files_not_hashed: number;
  bytes_hashed: number;
  error_count: number;
  limits_hit: string[];
  exclusions: string[];
  compared_to_snapshot_id: string | null;
  changes_added: number;
  changes_modified: number;
  changes_deleted: number;
  changes_renamed: number;
  deletions_unverified: number;
  failure_reason: string | null;
  is_baseline: boolean;
}

export interface Job {
  id: string;
  job_type: string;
  status: string;
  trigger: string;
  website_id: string | null;
  website_name?: string | null;
  hosting_account_id: string | null;
  attempts: number;
  max_attempts: number;
  queued_at: string;
  started_at: string | null;
  finished_at: string | null;
  heartbeat_at: string | null;
  error_class: string | null;
  error_message: string | null;
  result_summary: Record<string, unknown>;
  cancel_requested: boolean;
  duration_seconds: number | null;
  tenant?: string;
  tenant_id?: string;
}

export interface Dashboard {
  generated_at: string;
  is_demo: boolean;
  organisation: { id: string; name: string; status: string };
  websites: {
    total: number;
    active: number;
    coverage: Record<string, number>;
    items: {
      id: string;
      name: string;
      hostname: string;
      status: string;
      coverage: string;
      last_scan_at: string | null;
      last_scan_status: string | null;
      last_successful_scan_at: string | null;
      availability: string | null;
      tls: string | null;
      tls_expires_at: string | null;
    }[];
  };
  hosting_accounts: { total: number; by_status: Record<string, number> };
  last_successful_scan_at: string | null;
  incidents: {
    open_by_severity: Record<string, number>;
    open_total: number;
    recent: { id: string; reference: string; title: string; severity: string; status: string; website_name: string | null; last_observed_at: string; category: string }[];
  };
  recent_changes: { id: string; path: string; change_type: string; severity: string; website_name: string | null; detected_at: string; flags: string[] }[];
  recent_scans: { id: string; website_name: string | null; status: string; started_at: string; completed_at: string | null; files_seen: number; error_count: number; changes: number }[];
  availability: Record<string, number>;
  tls: Record<string, number>;
  notifications: { by_status: Record<string, number>; window_days: number };
  subscription: {
    plan: string | null;
    status: string | null;
    in_service: boolean;
    limits: Record<string, number>;
    usage: Record<string, number>;
  };
  trends: Record<string, Record<string, Record<string, number>>>;
}
