/**
 * SafeSOC — Endpoint Detail
 * Dedicated investigation view for a single host, replacing the old
 * "click an endpoint -> its alert log" drill-down (Endpoints.tsx used
 * to link straight to /alerts?host_id=...; that filtered alert view is
 * still one click away here via "View all alerts").
 *
 * Every section is built from data an existing endpoint already
 * returns — no new backend concept was introduced beyond threading an
 * optional host_id through the existing severity-summary aggregation
 * (GET /api/v1/alerts/summary, already used by the Dashboard fix).
 * "Why is this endpoint risky?" is computed client-side from this
 * host's own recent alerts using the exact same signal categories
 * services/risk_scoring.py's calculate_risk_score() weighs (severity,
 * confirmed-malicious threat intel, anomaly flags, MITRE mapping,
 * after-hours timing) — the backend only persists the final score, not
 * a factor breakdown, so this reads the same evidence rather than
 * inventing a new one. "Associated incidents" and "Attack Chain" are
 * derived by cross-referencing GET /api/v1/incidents' alert_ids
 * against this host's own alert ids — no per-host incident/graph
 * endpoint exists, so this reuses the existing per-incident graph
 * endpoint for whichever associated incident is most relevant, rather
 * than inventing a host-centric one. Software & Vulnerabilities is
 * backed by GET /api/v1/endpoints/{host_id}/software (added alongside
 * this page's demo-data generator, injector/simulate.py) — an empty
 * list renders the same explicit "no data" state as before for any
 * host that genuinely has none recorded.
 */

import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import AttackChainGraphView from '../components/AttackChainGraphView';
import EmptyState from '../components/EmptyState';
import EndpointAiAnalyst from '../components/EndpointAiAnalyst';
import GenerateReportButton from '../components/GenerateReportButton';
import LevelBadge from '../components/LevelBadge';
import Layout from '../components/Layout';
import OsIcon from '../components/OsIcon';
import PageHeader from '../components/PageHeader';
import Spinner from '../components/Spinner';
import StatusBadge from '../components/StatusBadge';
import { AlertIcon, ChevronLeftIcon } from '../components/icons';
import { api } from '../lib/api';
import Timestamp from '../components/Timestamp';
import type {
  Alert,
  AlertSearchResponse,
  AlertSeveritySummary,
  Endpoint,
  EndpointSoftware,
  Incident,
  IncidentGraph,
  IncidentListResponse,
} from '../lib/types';

const ACTIVITY_WINDOW_HOURS = 720; // 30 days — the max GET /api/v1/alerts already allows
const RECENT_ALERTS_SAMPLE_SIZE = 200; // bounded fetch for the factors/timeline/table below; "View all" links to the full filtered query
const RECENT_ALERTS_TABLE_ROWS = 8;

const SEVERITY_COLORS: Record<string, string> = {
  low: '#94a3b8',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
};

interface RiskFactor {
  label: string;
  count: number;
  detail: string;
}

function computeRiskFactors(alerts: Alert[]): RiskFactor[] {
  if (alerts.length === 0) return [];

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  let maliciousTi = 0;
  let anomalous = 0;
  let mitreMapped = 0;
  let afterHours = 0;

  for (const alert of alerts) {
    if (alert.severity in bySeverity) bySeverity[alert.severity as keyof typeof bySeverity] += 1;
    const record = alert as unknown as Record<string, unknown>;
    const ti = record.ti_result as { is_malicious?: boolean } | null | undefined;
    if (ti?.is_malicious) maliciousTi += 1;
    const anomalyScore = record.anomaly_score;
    if (typeof anomalyScore === 'number' && anomalyScore > 0) anomalous += 1;
    if (alert.mitre_technique) mitreMapped += 1;
    const hour = new Date(alert.timestamp).getUTCHours();
    const day = new Date(alert.timestamp).getUTCDay();
    if (day === 0 || day === 6 || hour < 8 || hour >= 18) afterHours += 1;
  }

  const factors: RiskFactor[] = [];
  if (bySeverity.critical > 0) {
    factors.push({ label: 'Critical-severity alerts', count: bySeverity.critical, detail: `${bySeverity.critical} of ${alerts.length} recent alerts` });
  }
  if (bySeverity.high > 0) {
    factors.push({ label: 'High-severity alerts', count: bySeverity.high, detail: `${bySeverity.high} of ${alerts.length} recent alerts` });
  }
  if (maliciousTi > 0) {
    factors.push({ label: 'Confirmed-malicious indicators', count: maliciousTi, detail: `${maliciousTi} alert(s) matched a known-malicious IP/hash via threat intel` });
  }
  if (anomalous > 0) {
    factors.push({ label: 'Anomalous activity', count: anomalous, detail: `${anomalous} alert(s) flagged by the anomaly detector` });
  }
  if (mitreMapped > 0) {
    factors.push({ label: 'Mapped to a MITRE technique', count: mitreMapped, detail: `${mitreMapped} alert(s) matched a known attack technique` });
  }
  if (afterHours > 0) {
    factors.push({ label: 'After-hours activity', count: afterHours, detail: `${afterHours} alert(s) outside 08:00-18:00 weekdays (UTC)` });
  }
  return factors;
}

export default function EndpointDetail() {
  const { hostId } = useParams<{ hostId: string }>();

  const [endpoint, setEndpoint] = useState<Endpoint | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [alertsTotal, setAlertsTotal] = useState(0);
  const [severitySummary, setSeveritySummary] = useState<AlertSeveritySummary | null>(null);
  const [associatedIncidents, setAssociatedIncidents] = useState<Incident[]>([]);
  const [graph, setGraph] = useState<IncidentGraph | null>(null);
  const [graphIncident, setGraphIncident] = useState<Incident | null>(null);
  const [software, setSoftware] = useState<EndpointSoftware[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!hostId) return;
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    Promise.all([
      api.get<Endpoint[]>('/api/v1/endpoints'),
      api.get<AlertSearchResponse>('/api/v1/alerts', {
        params: { host_id: hostId, timerange_hours: ACTIVITY_WINDOW_HOURS, size: RECENT_ALERTS_SAMPLE_SIZE },
      }),
      api.get<AlertSeveritySummary>('/api/v1/alerts/summary', {
        params: { host_id: hostId, timerange_hours: ACTIVITY_WINDOW_HOURS },
      }),
      api.get<IncidentListResponse>('/api/v1/incidents', { params: { size: 500 } }),
      api.get<EndpointSoftware[]>(`/api/v1/endpoints/${encodeURIComponent(hostId)}/software`),
    ])
      .then(async ([endpointsRes, alertsRes, summaryRes, incidentsRes, softwareRes]) => {
        if (cancelled) return;

        setEndpoint(endpointsRes.data.find((e) => e.host_id === hostId) ?? null);
        setAlerts(alertsRes.data.alerts);
        setAlertsTotal(alertsRes.data.total);
        setSeveritySummary(summaryRes.data);
        setSoftware(softwareRes.data);

        const hostAlertIds = new Set(alertsRes.data.alerts.map((a) => a.alert_id));
        const related = incidentsRes.data.incidents
          .filter((incident) => incident.alert_ids.some((id) => hostAlertIds.has(id)))
          .sort((a, b) => b.updated_at.localeCompare(a.updated_at));
        setAssociatedIncidents(related);

        // Attack chain: the most relevant associated incident's own graph —
        // prefer a still-open one over an already-closed one, else most recent.
        const primary = related.find((i) => i.status === 'open' || i.status === 'investigating') ?? related[0];
        if (primary) {
          setGraphIncident(primary);
          try {
            const graphRes = await api.get<IncidentGraph>(`/api/v1/incidents/${primary.id}/graph`);
            if (!cancelled) setGraph(graphRes.data);
          } catch {
            if (!cancelled) setGraph(null);
          }
        } else {
          setGraphIncident(null);
          setGraph(null);
        }
      })
      .catch(() => {
        if (!cancelled) setError('Failed to load this endpoint.');
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [hostId]);

  const riskFactors = useMemo(() => computeRiskFactors(alerts), [alerts]);
  const hostOs = alerts.find((a) => a.host_os)?.host_os;

  const severityCounts = useMemo(() => {
    if (!severitySummary) return [];
    return (['critical', 'high', 'medium', 'low'] as const)
      .map((sev) => ({ severity: sev, count: severitySummary.by_severity[sev] ?? 0 }))
      .filter((entry) => entry.count > 0);
  }, [severitySummary]);

  if (!hostId) return null;

  return (
    <Layout>
      <Link to="/endpoints" className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-300">
        <ChevronLeftIcon className="h-4 w-4" />
        Back to Endpoints
      </Link>

      <div className="mt-2">
        <PageHeader
          title={hostId}
          description={
            <span className="flex items-center gap-2">
              <OsIcon os={hostOs} />
              Endpoint investigation view
            </span>
          }
          actions={
            <div className="flex items-center gap-3">
              <Link
                to={`/alerts?host_id=${encodeURIComponent(hostId)}`}
                className="rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-1.5 text-sm text-slate-200 transition-colors hover:border-blue-500 hover:bg-slate-700"
              >
                View all alerts
              </Link>
              <GenerateReportButton scope="endpoint" id={hostId} />
            </div>
          }
        />
      </div>

      {error && <p className="mt-4 text-sm text-red-400">{error}</p>}

      {isLoading ? (
        <div className="mt-8 flex justify-center">
          <Spinner className="h-6 w-6 text-slate-600" />
        </div>
      ) : (
        <>
          {/* 1. Endpoint header */}
          <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500">Hostname</p>
                <p className="mt-1 font-mono text-lg text-slate-100">{hostId}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500">Risk Score</p>
                <p className="mt-1 text-lg tabular-nums text-slate-100">{endpoint ? endpoint.risk_score : '—'}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500">Risk Level</p>
                <div className="mt-1.5">{endpoint ? <LevelBadge level={endpoint.risk_level} /> : <span className="text-sm text-slate-500">Not yet scored</span>}</div>
              </div>
              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500">Last Updated</p>
                <p className="mt-1 text-sm text-slate-300"><Timestamp iso={endpoint?.updated_at} /></p>
              </div>
            </div>
            {!endpoint && (
              <p className="mt-3 text-sm text-slate-500">
                This host hasn't been through risk scoring yet — evidence below is drawn directly from its alert history.
              </p>
            )}
          </section>

          {/* 2. Why is this endpoint risky? */}
          <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <h2 className="text-sm font-semibold text-slate-200">Why is this endpoint risky?</h2>
            <p className="mt-1 text-xs text-slate-500">
              Contributing factors from this host's own alert history, in the same categories the risk score itself weighs.
            </p>
            {riskFactors.length === 0 ? (
              <p className="mt-3 text-sm text-slate-500">
                {alerts.length === 0
                  ? 'No recent alerts for this host — no contributing risk factors to show.'
                  : `${alerts.length} recent alert(s), all low-severity with no other risk signals (no confirmed-malicious indicators, anomalies, or MITRE-mapped techniques).`}
              </p>
            ) : (
              <ul className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
                {riskFactors.map((factor) => (
                  <li key={factor.label} className="rounded-lg border border-slate-800/80 bg-slate-950/50 px-3 py-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-slate-200">{factor.label}</span>
                      <span className="rounded-full bg-slate-800 px-2 py-0.5 text-xs tabular-nums text-slate-300">{factor.count}</span>
                    </div>
                    <p className="mt-0.5 text-xs text-slate-500">{factor.detail}</p>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {/* 3. Security activity */}
          <section className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
              <h2 className="text-sm font-semibold text-slate-200">Severity Distribution</h2>
              <p className="text-xs text-slate-500">{severitySummary?.total ?? 0} alert(s) in the last 30 days</p>
              {severityCounts.length === 0 ? (
                <div className="mt-4 flex h-32 items-center justify-center text-sm text-slate-500">No alerts in this window.</div>
              ) : (
                <ul className="mt-3 space-y-2">
                  {severityCounts.map(({ severity, count }) => (
                    <li key={severity} className="flex items-center gap-2 text-sm">
                      <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[severity] }} />
                      <span className="w-16 capitalize text-slate-300">{severity}</span>
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-800">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${Math.round((count / (severitySummary?.total || 1)) * 100)}%`,
                            backgroundColor: SEVERITY_COLORS[severity],
                          }}
                        />
                      </div>
                      <span className="w-10 text-right tabular-nums text-slate-400">{count}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
              <h2 className="text-sm font-semibold text-slate-200">Recent Activity</h2>
              <p className="text-xs text-slate-500">Most recent alert timestamps</p>
              {alerts.length === 0 ? (
                <div className="mt-4 flex h-32 items-center justify-center text-sm text-slate-500">No activity to show.</div>
              ) : (
                <ul className="mt-3 space-y-1.5">
                  {alerts.slice(0, 5).map((alert) => (
                    <li key={alert.alert_id} className="flex items-center justify-between text-sm">
                      <span className="truncate text-slate-300">{alert.description}</span>
                      <Timestamp iso={alert.timestamp} format="relative" className="ml-2 shrink-0 text-xs text-slate-500" />
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>

          {/* 4. Associated incidents */}
          <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <h2 className="text-sm font-semibold text-slate-200">Associated Incidents ({associatedIncidents.length})</h2>
            {associatedIncidents.length === 0 ? (
              <p className="mt-3 text-sm text-slate-500">No incidents currently link an alert on this host.</p>
            ) : (
              <ul className="mt-3 space-y-1.5">
                {associatedIncidents.map((incident) => (
                  <li key={incident.id}>
                    <Link
                      to={`/incidents/${incident.id}`}
                      className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-800/80 bg-slate-950/50 px-3 py-2 text-sm transition-colors hover:border-blue-500/50 hover:bg-slate-900"
                    >
                      <span className="font-mono text-slate-300">{incident.id.slice(0, 8)}</span>
                      <StatusBadge status={incident.status} />
                      <span className="text-xs text-slate-500">{incident.alert_ids.length} alert{incident.alert_ids.length === 1 ? '' : 's'}</span>
                      <Timestamp iso={incident.updated_at} format="relative" className="ml-auto text-xs text-slate-600" />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {/* 5. Attack chain */}
          <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <h2 className="text-sm font-semibold text-slate-200">Attack Chain</h2>
            {graphIncident && (
              <p className="text-xs text-slate-500">
                Showing relationships from{' '}
                <Link to={`/incidents/${graphIncident.id}`} className="text-blue-400 hover:underline">
                  incident {graphIncident.id.slice(0, 8)}
                </Link>
                {associatedIncidents.length > 1 ? ` (most relevant of ${associatedIncidents.length} associated incidents)` : ''}.
              </p>
            )}
            <div className="mt-3">
              {graph ? (
                <AttackChainGraphView graph={graph} />
              ) : (
                <p className="text-sm text-slate-500">
                  {associatedIncidents.length === 0
                    ? 'No relationships to show — this host has no associated incidents.'
                    : 'Loading attack-chain graph…'}
                </p>
              )}
            </div>
          </section>

          {/* 6. Recent alerts */}
          <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-200">Recent Alerts</h2>
              <Link to={`/alerts?host_id=${encodeURIComponent(hostId)}`} className="text-xs text-blue-400 hover:underline">
                View all alerts →
              </Link>
            </div>
            {alertsTotal > alerts.length && (
              <p className="mt-1 text-xs text-slate-500">
                {alertsTotal.toLocaleString()} matching alert{alertsTotal === 1 ? '' : 's'} in the last 30 days. Showing the {Math.min(RECENT_ALERTS_TABLE_ROWS, alerts.length)} most recent below.
              </p>
            )}
            {alerts.length === 0 ? (
              <EmptyState
                icon={<AlertIcon className="h-10 w-10 text-slate-700" />}
                title="No recent alerts"
                description="This host has no alerts in the last 30 days."
              />
            ) : (
              <div className="mt-3 overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="text-xs uppercase tracking-wide text-slate-500">
                    <tr>
                      <th className="px-2 py-2 font-medium">Timestamp</th>
                      <th className="px-2 py-2 font-medium">Severity</th>
                      <th className="px-2 py-2 font-medium">Description</th>
                      <th className="px-2 py-2 font-medium">User</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.slice(0, RECENT_ALERTS_TABLE_ROWS).map((alert) => (
                      <tr key={alert.alert_id} className="border-t border-slate-800/70">
                        <td className="whitespace-nowrap px-2 py-2 text-slate-400">
                          <Timestamp iso={alert.timestamp} />
                        </td>
                        <td className="px-2 py-2">
                          <LevelBadge level={alert.severity} />
                        </td>
                        <td className="max-w-xs truncate px-2 py-2 text-slate-300">{alert.description}</td>
                        <td className="px-2 py-2 text-slate-400">{alert.user}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {/* 7. Software & Vulnerabilities */}
          <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <h2 className="text-sm font-semibold text-slate-200">Software & Vulnerabilities</h2>
            {software.length === 0 ? (
              <div className="mt-3">
                <EmptyState
                  title="No software inventory data available for this endpoint."
                  description="SafeSOC does not currently collect software or CVE inventory data for this host."
                />
              </div>
            ) : (
              <div className="mt-3 overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="text-xs uppercase tracking-wide text-slate-500">
                    <tr>
                      <th className="px-2 py-2 font-medium">Software</th>
                      <th className="px-2 py-2 font-medium">Version</th>
                      <th className="px-2 py-2 font-medium">Category</th>
                      <th className="px-2 py-2 font-medium">Vulnerabilities</th>
                    </tr>
                  </thead>
                  <tbody>
                    {software.map((item) => (
                      <tr key={item.id} className="border-t border-slate-800/70 align-top">
                        <td className="whitespace-nowrap px-2 py-2 text-slate-200">{item.name}</td>
                        <td className="whitespace-nowrap px-2 py-2 font-mono text-xs text-slate-400">{item.version}</td>
                        <td className="whitespace-nowrap px-2 py-2 capitalize text-slate-400">{item.category.replace(/_/g, ' ')}</td>
                        <td className="px-2 py-2">
                          {item.vulnerabilities.length === 0 ? (
                            <span className="text-xs text-slate-600">None known</span>
                          ) : (
                            <div className="flex flex-col gap-1.5">
                              {item.vulnerabilities.map((vuln) => (
                                <div key={vuln.id} className="flex flex-wrap items-center gap-1.5">
                                  <LevelBadge level={vuln.severity} />
                                  <span className="font-mono text-xs text-slate-300">{vuln.id}</span>
                                  <span
                                    className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
                                      vuln.is_synthetic
                                        ? 'bg-slate-800 text-slate-500'
                                        : 'bg-blue-500/10 text-blue-300'
                                    }`}
                                    title={vuln.is_synthetic ? 'Demo-only finding, not a real CVE' : 'A real, publicly-documented CVE'}
                                  >
                                    {vuln.is_synthetic ? 'DEMO' : 'CVE'}
                                  </span>
                                  <span className="text-xs text-slate-500">{vuln.title}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className="mt-3 text-[11px] text-slate-600">
                  Synthetic demonstration data. "CVE"-tagged entries are real, publicly-documented vulnerabilities
                  attached to intentionally old software versions for realism — not vulnerabilities actually found on
                  a real machine. "DEMO"-tagged entries are placeholder findings, not real CVE database records.
                </p>
              </div>
            )}
          </section>

          {/* 8. AI Endpoint Analyst */}
          <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <h2 className="text-sm font-semibold text-slate-200">AI Endpoint Analyst</h2>
            <p className="mt-1 text-xs text-slate-500">
              Scoped to this host for the current session only — nothing here is remembered after you leave this page.
            </p>
            <div className="mt-3">
              <EndpointAiAnalyst hostId={hostId} />
            </div>
          </section>
        </>
      )}
    </Layout>
  );
}
