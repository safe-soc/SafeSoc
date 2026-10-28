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

// Why an alert was dismissed (backend core/enums.py DismissReason).
export type DismissReason = 'false_positive' | 'expected_activity' | 'duplicate' | 'other';
export const DISMISS_REASONS: DismissReason[] = ['false_positive', 'expected_activity', 'duplicate', 'other'];

// GET /api/v1/alerts?triage= (backend core/enums.py TriageStatus).
export type TriageStatus = 'untriaged' | 'acknowledged' | 'dismissed';
export const TRIAGE_STATUSES: TriageStatus[] = ['untriaged', 'acknowledged', 'dismissed'];

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
  // Set while dismissed; the note is required for reason "other".
  dismiss_reason?: DismissReason | null;
  dismiss_note?: string | null;
}

// GET /api/v1/alerts/{id}/context — the full OpenSearch document, so
// every NormalizedLog field may be present; unknown extras are allowed.
export interface AlertDocument extends Alert {
  ingested_at?: string | null;
  rule_id?: string | null;
  source_port?: number | null;
  destination_ip?: string | null;
  destination_port?: number | null;
  protocol?: string | null;
  file_path?: string | null;
  file_hash?: string | null;
  file_size?: number | null;
  process_name?: string | null;
  process_id?: number | null;
  parent_process?: string | null;
  command_line?: string | null;
  raw_log?: string | null;
  ti_enriched?: boolean | null;
  ti_result?: Record<string, unknown> | null;
  risk_score?: number | null;
  anomaly_score?: number | null;
  [key: string]: unknown;
}

export interface AlertContextIncident {
  id: string;
  category: CorrelationPattern | null;
  hosts: string[];
  status: IncidentStatus;
  created_at: string;
  updated_at: string;
}

export interface AlertIPIntel {
  // null = no ti_cache row for this IP.
  ti: IPThreatIntel | null;
  is_public: boolean;
}

export interface AlertContext {
  alert: AlertDocument;
  incident: AlertContextIncident | null;
  ip_intel: Record<string, AlertIPIntel>;
}

// POST /api/v1/alerts/{id}/acknowledge, .../dismiss, .../restore (SS-107)
export interface AlertAnnotation {
  alert_id: string;
  acknowledged: boolean;
  dismissed: boolean;
  dismiss_reason: DismissReason | null;
  dismiss_note: string | null;
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

// GET /api/v1/alerts/summary — severity breakdown for the SAME
// tenant+time-window population GET /api/v1/alerts pages through, via
// an aggregation rather than a page of documents, so it isn't capped
// by that endpoint's `size` limit. Only severities with at least one
// matching alert appear as keys.
export interface AlertSeveritySummary {
  total: number;
  timerange_hours: number;
  by_severity: Partial<Record<Severity, number>>;
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

// Correlation-engine chain patterns (backend core/enums.py CorrelationPattern).
export type CorrelationPattern =
  | 'credential_brute_force'
  | 'successful_compromise'
  | 'recon_to_exploitation'
  | 'privilege_escalation'
  | 'data_exfiltration'
  | 'lateral_movement';

export interface Incident {
  id: string;
  tenant_id: string;
  status: IncidentStatus;
  alert_ids: string[];
  assigned_analyst_id: string | null;
  // SS-094: the detected chain's pattern and confidence at creation/last
  // merge — null for a manually-created incident, which has no detected chain.
  category: CorrelationPattern | null;
  confidence: number | null;
  // Read-only, derived server-side from the linked alerts on every read:
  // hosts ordered by alert count (most first, CloudLens resources
  // excluded); severity is the highest linked alert severity, null when
  // none of the alerts resolve.
  hosts: string[];
  severity: Severity | null;
  // SS-106: free-form analyst-authored labels.
  tags: string[];
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

// GET /api/v1/incidents/{id}/graph (SS-104/105) — a lightweight
// relationship view: nodes are the same entities Evidence Explorer
// shows, edges are alerts connecting them, ordered by real timestamp.
export type GraphNodeType = 'host' | 'ip' | 'user' | 'cloud_resource';

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  alert_id: string;
  timestamp: string;
  mitre_technique?: string | null;
  mitre_tactic?: string | null;
}

export interface IncidentGraph {
  incident_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// GET /api/v1/threat-analytics (SS-111/112) — a tenant-wide rollup of
// correlation-pattern trends over a rolling window.
export interface CategoryTrend {
  category: string;
  mitre_tactic: string;
  mitre_technique_ids: string[];
  current_count: number;
  previous_count: number;
  // null = previous_count was 0, so a percentage change is undefined
  // (not infinite/zero).
  change_pct: number | null;
}

export interface ThreatAnalyticsKPIs {
  total_incidents: number;
  open_incidents: number;
  critical_high_incidents: number;
  // Incidents whose severity couldn't be resolved from their linked
  // alerts (e.g. pruned by OpenSearch retention) — excluded from
  // critical_high_incidents/severity_breakdown rather than guessed.
  incidents_with_unknown_severity: number;
  affected_endpoints: number;
  affected_users: number;
  detection_categories: number;
}

export interface DailyIncidentCount {
  date: string; // YYYY-MM-DD, UTC
  count: number;
}

export interface StatusCount {
  status: IncidentStatus;
  count: number;
}

export interface SeverityCount {
  severity: Severity;
  count: number;
}

export interface MitreTechniqueCount {
  technique_id: string;
  // null when no alert carrying this technique also carried a tactic string.
  tactic: string | null;
  incident_count: number;
  // Capped, real ids/hosts only — never a fabricated "N more" placeholder.
  related_incident_ids: string[];
  affected_endpoints: string[];
}

export interface AffectedAsset {
  host_id: string;
  incident_count: number;
  // null when this host has no Endpoint row yet (never scored).
  highest_risk: Severity | null;
  // null when none of this host's incidents in-window had a category
  // (e.g. all manually created).
  dominant_category: string | null;
}

export interface ThreatAnalyticsResponse {
  window_days: number;
  trends: CategoryTrend[];
  // false when the ENTIRE previous window had no detected activity at
  // all (e.g. a freshly seeded dataset) — show an explicit "no
  // previous-period data" state rather than implying 0%/no change.
  has_previous_period_data: boolean;
  kpis: ThreatAnalyticsKPIs;
  daily_trend: DailyIncidentCount[];
  status_breakdown: StatusCount[];
  severity_breakdown: SeverityCount[];
  mitre_techniques: MitreTechniqueCount[];
  affected_assets: AffectedAsset[];
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
  // SS-103: true if any alert tied to this host exceeded the anomaly threshold.
  has_anomalous_activity?: boolean;
}

// Per-provider IP details captured from the same VirusTotal / AbuseIPDB
// calls enrichment already makes (backend schemas/log.py).
export interface VTFlaggedEngine {
  engine: string;
  category: string;
  result: string | null;
}

export interface VTIPDetails {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  total: number;
  reputation: number | null;
  asn: number | null;
  as_owner: string | null;
  network: string | null;
  country: string | null;
  last_analysis_date: string | null;
  tags: string[];
  flagged_by: VTFlaggedEngine[];
}

export interface AbuseIPDetails {
  confidence: number;
  total_reports: number;
  num_distinct_users: number;
  last_reported_at: string | null;
  isp: string | null;
  usage_type: string | null;
  domain: string | null;
  country_code: string | null;
  hostnames: string[];
  is_tor: boolean;
  is_whitelisted: boolean | null;
  max_age_days: number;
}

// ok = row with details; legacy = row cached before details were
// collected; not_found = the provider has no report for the IP
// (VirusTotal 404, "not seen before"); missing = no row from that provider.
export type TIDetailStatus = 'ok' | 'legacy' | 'not_found' | 'missing';

export interface IPThreatIntel {
  is_malicious: boolean;
  // Latest real provider lookup (moves when a refresh completes).
  checked_at: string | null;
  vt: VTIPDetails | null;
  abuse: AbuseIPDetails | null;
  vt_status: TIDetailStatus;
  abuse_status: TIDetailStatus;
}

export interface IPEntity {
  ip: string;
  roles: string[];
  is_malicious?: boolean | null;
  alert_count: number;
  // Absent/null = no ti_cache row at all.
  ti?: IPThreatIntel | null;
  is_public?: boolean;
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

// POST /api/v1/incidents/{id}/narrative (SS-109/110) — an AI-generated
// attack-chain summary, grounded in the same aggregated data returned
// in `data`. `is_fallback` mirrors InvestigateResponse's own field:
// true means the LLM was unavailable/too slow and this is a
// deterministic templated summary instead.
export interface IncidentNarrativeResponse {
  incident_id: string;
  narrative: string;
  is_fallback: boolean;
  data: {
    incident_id: string;
    events: TimelineEntry[];
    hosts: HostEntity[];
    ips: IPEntity[];
    users: UserEntity[];
    cloud_resources: CloudResourceEntity[];
    mitre_techniques: string[];
    confidence: number | null;
  };
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

// GET /api/v1/endpoints/{host_id}/software — demo-simulation software/
// vulnerability inventory. `is_synthetic: false` means `id` is a real,
// publicly-documented CVE genuinely known to affect this exact
// software+version; `true` means a clearly-labeled demo-only finding
// (id formatted "DEMO-VULN-####"), never a real vulnerability database entry.
export type SoftwareCategory = 'operating_system' | 'browser' | 'productivity' | 'runtime' | 'remote_admin' | 'security' | 'other';

export interface Vulnerability {
  id: string;
  severity: Severity;
  title: string;
  is_synthetic: boolean;
}

export interface EndpointSoftware {
  id: string;
  host_id: string;
  name: string;
  version: string;
  category: SoftwareCategory;
  vulnerabilities: Vulnerability[];
  updated_at: string;
}

// POST /api/v1/incidents/{id}/report, POST /api/v1/endpoints/{host_id}/report
// — generates a PDF investigation report; download_url is the existing
// GET /api/v1/reports/{filename} route (SS-054), unchanged.
export interface InvestigationReportResponse {
  filename: string;
  generated_at: string;
  size_bytes: number;
  download_url: string;
}

// Persistent, incident-scoped Investigation Sessions
// (/api/v1/incidents/{id}/investigation/...). Distinct from the
// general Investigate page's session_id (ephemeral, Redis-backed,
// 10-minute TTL) — these survive a page refresh or a return days later.
export type FindingCategory = 'confirmed' | 'hypothesis' | 'open_question';
export type FindingOrigin = 'analyst' | 'ai_suggested';
export type InvestigationActionStatus = 'open' | 'in_progress' | 'completed';

export interface InvestigationSessionSummary {
  id: string;
  incident_id: string;
  created_by_user_id: string;
  created_at: string;
}

export interface InvestigationTurn {
  id: string;
  asked_by_user_id: string;
  question: string;
  answer: string;
  is_fallback: boolean;
  created_at: string;
}

export interface InvestigationFinding {
  id: string;
  text: string;
  category: FindingCategory;
  origin: FindingOrigin;
  created_by_user_id: string | null;
  confirmed_by_user_id: string | null;
  confirmed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface InvestigationAction {
  id: string;
  description: string;
  status: InvestigationActionStatus;
  created_by_user_id: string;
  completed_by_user_id: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface InvestigationNote {
  id: string;
  author_user_id: string;
  body: string;
  created_at: string;
}

// The live "KNOWN" list — always freshly retrieved, never a stored snapshot.
export interface InvestigationEvidenceSummary {
  hosts: string[];
  users: string[];
  mitre_techniques: string[];
  alert_count: number;
}

export interface InvestigationSessionDetail {
  id: string;
  incident_id: string;
  created_by_user_id: string;
  created_at: string;
  evidence: InvestigationEvidenceSummary;
  turns: InvestigationTurn[];
  findings: InvestigationFinding[];
  actions: InvestigationAction[];
  notes: InvestigationNote[];
}

export interface AskQuestionResponse {
  turn: InvestigationTurn;
}

// GET /api/v1/compliance/requirements, GET /api/v1/compliance/requirements/{id}
// — Indian regulatory compliance evidence mapping (DPDP Act 2023, CERT-In
// Directions 28.04.2022). Every status is computed live from existing
// SafeSOC evidence sources; NONE of these values is ever a legal-
// compliance determination — see docs/compliance.md. The frontend must
// only ever render the four approved phrasings (COMPLIANCE_STATUS_LABELS
// below) — never "compliant"/"non-compliant" in any form.
export type ComplianceStatus = 'evidence_available' | 'partially_supported' | 'gap' | 'not_assessable';

export type ComplianceFramework = 'dpdp_act_2023' | 'cert_in_directions_2022' | 'dpiit';

export interface ComplianceRequirementSummary {
  id: string;
  framework: ComplianceFramework;
  title: string;
  reference: string;
  status: ComplianceStatus;
  evidence_summary: string;
  evidence_count: number;
  last_evaluated: string;
}

export interface ComplianceFrameworkSummary {
  framework: ComplianceFramework;
  title: string;
  total_requirements: number;
  evidence_available: number;
  partially_supported: number;
  gaps: number;
  not_assessable: number;
}

export interface CompliancePostureResponse {
  requirements_assessed: number;
  evidence_available: number;
  partially_supported: number;
  gaps: number;
  not_assessable: number;
  frameworks: ComplianceFrameworkSummary[];
  requirements: ComplianceRequirementSummary[];
}

export interface RelatedIncidentRef {
  id: string;
  status: IncidentStatus;
  category: string | null;
  created_at: string;
}

export interface RelatedInvestigationRef {
  session_id: string;
  incident_id: string;
  created_at: string;
}

// SOAR (Security Orchestration, Automation and Response) — GET
// /api/v1/soar/runs, GET /api/v1/incidents/{id}/soar/runs[/{run_id}],
// POST .../actions/{action_id}/approve|reject. Every action here runs
// only against SafeSOC's own simulated adapters — see the Simulation
// Mode banner on the /soar page; nothing here ever reaches real
// external infrastructure.
export type SoarActionType =
  | 'collect_additional_evidence'
  | 'create_investigation_action'
  | 'enrich_indicator'
  | 'add_incident_note'
  | 'increase_incident_priority'
  | 'isolate_endpoint'
  | 'disable_account'
  | 'block_indicator'
  | 'terminate_process'
  | 'revoke_credentials';

export type AutonomyClass = 'automatic' | 'approval_required';

export type SoarRunStatus = 'pending' | 'running' | 'awaiting_approval' | 'completed' | 'failed' | 'cancelled';

export type SoarActionStatus = 'pending' | 'awaiting_approval' | 'approved' | 'rejected' | 'executing' | 'succeeded' | 'failed';

export type SoarTriggerSource = 'auto_trigger' | 'manual' | 'ai_recommended';

export type RecommendationSource = 'analyst' | 'ai_suggested' | 'playbook_auto';

export type SoarVerificationStatus = 'not_verified' | 'verified' | 'verification_failed';

export interface SoarActionExecution {
  id: string;
  action_type: SoarActionType;
  parameters: Record<string, unknown>;
  autonomy_class: AutonomyClass;
  recommended_by: RecommendationSource;
  status: SoarActionStatus;
  approved_by_user_id: string | null;
  approved_at: string | null;
  rejected_by_user_id: string | null;
  rejected_at: string | null;
  decision_reason: string | null;
  executed_at: string | null;
  result: Record<string, unknown> | null;
  verification_status: SoarVerificationStatus;
  verified_at: string | null;
  created_at: string;
}

export interface SoarPlaybookRunSummary {
  id: string;
  incident_id: string;
  playbook_id: string;
  triggered_by: SoarTriggerSource;
  status: SoarRunStatus;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface SoarPlaybookRunDetail extends SoarPlaybookRunSummary {
  actions: SoarActionExecution[];
}

export interface ApprovalDecisionRequest {
  reason?: string;
}

// GET /api/v1/soar/playbooks — the static playbook catalog, same for every tenant.
export interface PlaybookStepResponse {
  action_type: SoarActionType;
  parameter_field: string;
  static_parameters: Record<string, unknown>;
}

export interface PlaybookResponse {
  id: string;
  title: string;
  trigger_pattern: string;
  trigger_min_confidence: number;
  steps: PlaybookStepResponse[];
}

export interface ComplianceRequirementDetail {
  id: string;
  framework: ComplianceFramework;
  title: string;
  reference: string;
  authoritative_source: string;
  requirement_summary: string;
  what_safesoc_can_observe: string;
  what_safesoc_cannot_verify: string;
  recommended_action: string;
  status: ComplianceStatus;
  evidence_summary: string;
  evidence_count: number;
  // Requirement-specific structured numbers (e.g. {"audit_events": 12}
  // or {"configured_retention_days": 90, "required_retention_days": 180}).
  metrics: Record<string, number>;
  last_evaluated: string;
  related_incidents: RelatedIncidentRef[];
  related_investigations: RelatedInvestigationRef[];
}
