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
  user: string;
  action: string;
  description: string;
  severity: Severity;
  source_ip?: string | null;
  mitre_technique?: string | null;
  mitre_tactic?: string | null;
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

export interface InvestigateResponse {
  session_id: string;
  intent: string;
  answer: string;
  data: Record<string, unknown>;
}
