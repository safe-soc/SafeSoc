/**
 * SafeSOC — Shared API Types
 * Mirrors the backend's core/enums.py vocabularies and the response
 * shapes of GET /api/v1/alerts, GET /api/v1/endpoints, etc.
 */

export type Severity = 'low' | 'medium' | 'high' | 'critical';
export const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical'];

export type LogType = 'authentication' | 'network' | 'process' | 'file' | 'privilege' | 'cloud' | 'system';
export const LOG_TYPES: LogType[] = ['authentication', 'network', 'process', 'file', 'privilege', 'cloud', 'system'];

export type LogSource = 'wazuh' | 'synthetic' | 'aws_cloudtrail' | 'aws_guardduty' | 'cloudlens';
export const LOG_SOURCES: LogSource[] = ['wazuh', 'synthetic', 'aws_cloudtrail', 'aws_guardduty', 'cloudlens'];

export interface Alert {
  alert_id: string;
  tenant_id: string;
  source: LogSource;
  log_type: LogType;
  timestamp: string;
  host_id: string;
  host_ip: string;
  host_os?: string | null;
  user: string;
  action: string;
  description: string;
  severity: Severity;
  source_ip?: string | null;
  mitre_technique?: string | null;
  mitre_tactic?: string | null;
  // Merged in by GET /api/v1/alerts from the alert_annotations table
  // (SS-107) — default false for an alert with no annotation row yet.
  acknowledged?: boolean;
  dismissed?: boolean;
}

// POST /api/v1/alerts/{id}/acknowledge, .../dismiss (SS-107)
export interface AlertAnnotation {
  alert_id: string;
  acknowledged: boolean;
  dismissed: boolean;
  updated_by_user_id: string;
  updated_at: string;
}

export interface AlertSearchResponse {
  total: number;
  page: number;
  size: number;
  pages: number;
  alerts: Alert[];
}

export type IncidentStatus = 'open' | 'investigating' | 'resolved' | 'false_positive';

// Mirrors backend/app/services/incidents.py's _ALLOWED_TRANSITIONS
// exactly — the UI must only ever offer transitions the backend's own
// state machine allows (AC), never invent UI-only states.
export const ALLOWED_TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
  open: ['investigating'],
  investigating: ['resolved', 'false_positive'],
  resolved: [],
  false_positive: [],
};

export interface Incident {
  id: string;
  tenant_id: string;
  status: IncidentStatus;
  alert_ids: string[];
  assigned_analyst_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface IncidentListResponse {
  total: number;
  page: number;
  size: number;
  pages: number;
  incidents: Incident[];
}

export interface IncidentNote {
  id: string;
  incident_id: string;
  author_user_id: string;
  body: string;
  created_at: string;
}

// GET /api/v1/incidents/{id}/timeline (SS-099) — a chronological merge
// of linked alerts, audit-log activity, and notes. `data`'s shape
// depends on `type`: an "alert" entry carries a raw Alert-shaped
// object, "audit" carries {action, actor_user_id, details}, "note"
// carries {id, author_user_id, body}.
export type TimelineEntryType = 'alert' | 'audit' | 'note';

export interface TimelineEntry {
  type: TimelineEntryType;
  timestamp: string;
  data: Record<string, unknown>;
}

export interface IncidentTimelineResponse {
  incident_id: string;
  entries: TimelineEntry[];
}

// GET /api/v1/incidents/{id}/evidence (SS-100/101) — distinct entities
// involved in an incident, annotated with data already computed
// elsewhere (Endpoint risk, ti_cache verdicts). Every annotation field
// is nullable/optional: null/undefined means "not available", never
// an error — render a neutral state for those, not a blank/broken one.
export interface HostEntity {
  host_id: string;
  host_os?: string | null;
  risk_score?: number | null;
  risk_level?: Severity | null;
  alert_count: number;
}

export interface IPEntity {
  ip: string;
  roles: string[];
  is_malicious?: boolean | null;
  alert_count: number;
}

export interface UserEntity {
  user: string;
  alert_count: number;
}

export interface CloudResourceEntity {
  resource_id: string;
  alert_count: number;
}

export interface IncidentEvidence {
  incident_id: string;
  hosts: HostEntity[];
  ips: IPEntity[];
  users: UserEntity[];
  cloud_resources: CloudResourceEntity[];
}

export interface InvestigateResponse {
  session_id: string;
  intent: string;
  answer: string;
  data: Record<string, unknown>;
  is_fallback: boolean;
}

// GET /api/v1/endpoints (SS-034) — no host_os field on this resource;
// pages that want an OS hint derive it best-effort from recently-seen
// alerts for that host_id instead (see lib/hostOs.ts).
export interface Endpoint {
  id: string;
  tenant_id: string;
  host_id: string;
  risk_score: number;
  risk_level: Severity;
  updated_at: string;
}
