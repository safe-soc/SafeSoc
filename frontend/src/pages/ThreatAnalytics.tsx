/**
 * SafeSOC — Threat Analytics Dashboard (SS-112, extended)
 * Renders GET /api/v1/threat-analytics' full rollup: KPIs, incident
 * trend, category distribution, MITRE technique tally, affected
 * assets, status/severity breakdown, and a deterministic key-findings
 * summary — all backend-computed from real incidents/alerts/endpoints
 * for the same selected window, plus the original current-vs-previous
 * category trend chart/table (SS-111/112), unchanged. Visual language
 * matches Dashboard.tsx's existing charts/widgets (ChartCard/KpiCard
 * shells, same color palette) — no new visual system introduced.
 */

import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import Layout from '../components/Layout';
import PageHeader from '../components/PageHeader';
import KpiCard from '../components/KpiCard';
import ChartCard from '../components/dashboard/ChartCard';
import EmptyState from '../components/EmptyState';
import LevelBadge from '../components/LevelBadge';
import Spinner from '../components/Spinner';
import { AlertIcon, EndpointIcon, IncidentIcon, LayersIcon, UsersIcon } from '../components/icons';
import { titleCase } from '../lib/format';
import { api } from '../lib/api';
import type {
  AffectedAsset,
  CategoryTrend,
  MitreTechniqueCount,
  StatusCount,
  ThreatAnalyticsResponse,
} from '../lib/types';

const WINDOW_OPTIONS = [7, 14, 30, 90];

const CATEGORY_COLORS: Record<string, string> = {
  credential_brute_force: '#3b82f6',
  successful_compromise: '#ef4444',
  recon_to_exploitation: '#f97316',
  privilege_escalation: '#a855f7',
  data_exfiltration: '#eab308',
  lateral_movement: '#22c55e',
  ransomware_precursor: '#e11d48',
};

const SEVERITY_COLORS: Record<string, string> = {
  low: '#94a3b8',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
};

const STATUS_COLORS: Record<string, string> = {
  open: '#3b82f6',
  investigating: '#eab308',
  resolved: '#22c55e',
  false_positive: '#64748b',
};

const STATUS_LABELS: Record<string, string> = {
  open: 'Open',
  investigating: 'Investigating',
  resolved: 'Resolved',
  false_positive: 'False Positive',
};

const selectClasses =
  'rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500';

function formatChangePct(trend: CategoryTrend): string {
  if (trend.change_pct === null) return trend.current_count > 0 ? 'new' : '—';
  const sign = trend.change_pct > 0 ? '+' : '';
  return `${sign}${trend.change_pct}%`;
}

function changeTone(trend: CategoryTrend): string {
  if (trend.change_pct === null) return trend.current_count > 0 ? 'text-blue-400' : 'text-slate-500';
  if (trend.change_pct > 0) return 'text-red-400';
  if (trend.change_pct < 0) return 'text-green-400';
  return 'text-slate-400';
}

function categoryColor(category: string): string {
  return CATEGORY_COLORS[category] ?? '#64748b';
}

function buildKeyFindings(data: ThreatAnalyticsResponse): string[] {
  const findings: string[] = [];

  const topCategory = data.trends.find((t) => t.current_count > 0);
  if (topCategory) {
    findings.push(`Most observed attack pattern: ${titleCase(topCategory.category)} (${topCategory.current_count} incident${topCategory.current_count === 1 ? '' : 's'}).`);
  }

  const topTechnique = data.mitre_techniques[0];
  if (topTechnique) {
    const tactic = topTechnique.tactic ? ` (${topTechnique.tactic})` : '';
    findings.push(`Most observed MITRE technique: ${topTechnique.technique_id}${tactic} — ${topTechnique.incident_count} incident${topTechnique.incident_count === 1 ? '' : 's'}.`);
  }

  const topAsset = data.affected_assets[0];
  if (topAsset) {
    findings.push(`Most affected endpoint: ${topAsset.host_id} (${topAsset.incident_count} incident${topAsset.incident_count === 1 ? '' : 's'}).`);
  }

  const severityOrder = ['critical', 'high', 'medium', 'low'];
  const topSeverity = severityOrder
    .map((sev) => data.severity_breakdown.find((s) => s.severity === sev))
    .find((s) => s && s.count > 0);
  if (topSeverity) {
    findings.push(`Highest observed severity: ${titleCase(topSeverity.severity)} (${topSeverity.count} incident${topSeverity.count === 1 ? '' : 's'}).`);
  }

  findings.push(`${data.kpis.affected_endpoints} endpoint${data.kpis.affected_endpoints === 1 ? '' : 's'} affected in this window.`);
  findings.push(`${data.kpis.affected_users} user${data.kpis.affected_users === 1 ? '' : 's'} affected in this window.`);

  return findings;
}

// Deterministic risk ranking for Investigation Priorities — reuses the
// same 4-tier vocabulary as LevelBadge, no new scoring algorithm.
const RISK_RANK: Record<string, number> = { critical: 3, high: 2, medium: 1, low: 0 };

function investigationPriorityRank(asset: AffectedAsset): number {
  return asset.highest_risk ? (RISK_RANK[asset.highest_risk] ?? -1) : -1;
}

function buildInvestigationPriorities(data: ThreatAnalyticsResponse): AffectedAsset[] {
  return [...data.affected_assets]
    .sort((a, b) => investigationPriorityRank(b) - investigationPriorityRank(a) || b.incident_count - a.incident_count)
    .slice(0, 5);
}

function buildRecommendedActions(data: ThreatAnalyticsResponse): string[] {
  const actions: string[] = [];

  const topAsset = buildInvestigationPriorities(data)[0];
  if (topAsset) {
    const risk = topAsset.highest_risk ? ` (${titleCase(topAsset.highest_risk)} risk)` : '';
    actions.push(`Investigate the highest-priority endpoint: ${topAsset.host_id}${risk} — ${topAsset.incident_count} incident${topAsset.incident_count === 1 ? '' : 's'}.`);
  }

  const topCategory = data.trends.find((t) => t.current_count > 0);
  if (topCategory) {
    actions.push(`Review the most frequent attack category: ${titleCase(topCategory.category)} (${topCategory.current_count} incident${topCategory.current_count === 1 ? '' : 's'}).`);
  }

  const topTechnique = data.mitre_techniques[0];
  if (topTechnique) {
    actions.push(`Review the most frequently observed MITRE technique: ${topTechnique.technique_id} — ${topTechnique.incident_count} incident${topTechnique.incident_count === 1 ? '' : 's'}.`);
  }

  const criticalHigh = data.kpis.critical_high_incidents;
  if (criticalHigh > 0) {
    actions.push(`Triage ${criticalHigh} critical/high-severity incident${criticalHigh === 1 ? '' : 's'} in this window.`);
  }

  return actions;
}

// Fixed presentation order for the Observed Attack Progression strip —
// a MITRE kill-chain-style ordering of the existing categories'
// already-assigned tactics (Reconnaissance -> Initial Access ->
// Credential Access -> Privilege Escalation -> Lateral Movement ->
// Exfiltration -> Impact). Only real counts are shown; categories absent
// from the current window are simply omitted, not zero-padded.
const ATTACK_PROGRESSION_ORDER = [
  'recon_to_exploitation',
  'successful_compromise',
  'credential_brute_force',
  'privilege_escalation',
  'lateral_movement',
  'data_exfiltration',
  'ransomware_precursor',
];

function DistributionBar({ label, count, total, color }: { label: string; count: number; total: number; color: string }) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return (
    <li className="flex items-center gap-2 text-sm">
      <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ backgroundColor: color }} />
      <span className="max-w-[11rem] shrink-0 truncate text-slate-300" title={label}>{label}</span>
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-800">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
      <span className="w-8 shrink-0 text-right tabular-nums text-slate-400">{count}</span>
    </li>
  );
}

function AffectedAssetsTable({ assets }: { assets: AffectedAsset[] }) {
  if (assets.length === 0) {
    return <EmptyState title="No affected endpoints" description="No incident in this window links an alert to a known host." />;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-2 py-2 font-medium">Host</th>
            <th className="px-2 py-2 font-medium">Incidents</th>
            <th className="px-2 py-2 font-medium">Highest Risk</th>
            <th className="px-2 py-2 font-medium">Dominant Category</th>
          </tr>
        </thead>
        <tbody>
          {assets.map((asset) => (
            <tr key={asset.host_id} className="border-t border-slate-800/70">
              <td className="px-2 py-2">
                <Link to={`/endpoints/${encodeURIComponent(asset.host_id)}`} className="font-mono text-slate-200 hover:text-blue-400 hover:underline">
                  {asset.host_id}
                </Link>
              </td>
              <td className="px-2 py-2 tabular-nums text-slate-200">{asset.incident_count}</td>
              <td className="px-2 py-2">{asset.highest_risk ? <LevelBadge level={asset.highest_risk} /> : <span className="text-xs text-slate-600">Not yet scored</span>}</td>
              <td className="px-2 py-2 text-slate-400">{asset.dominant_category ? titleCase(asset.dominant_category) : <span className="text-slate-600">—</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function MitreTechniquesTable({
  techniques,
  selectedId,
  onSelect,
}: {
  techniques: MitreTechniqueCount[];
  selectedId: string | null;
  onSelect: (technique: MitreTechniqueCount) => void;
}) {
  if (techniques.length === 0) {
    return <EmptyState title="No MITRE techniques observed" description="No alert linked to an incident in this window carried a MITRE ATT&CK technique." />;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-2 py-2 font-medium">Technique ID</th>
            <th className="px-2 py-2 font-medium">Tactic</th>
            <th className="px-2 py-2 font-medium">Incidents</th>
          </tr>
        </thead>
        <tbody>
          {techniques.map((technique) => (
            <tr
              key={technique.technique_id}
              onClick={() => onSelect(technique)}
              className={`cursor-pointer border-t border-slate-800/70 transition-colors hover:bg-slate-800/40 ${
                selectedId === technique.technique_id ? 'bg-blue-500/10' : ''
              }`}
            >
              <td className="px-2 py-2 font-mono text-blue-300">{technique.technique_id}</td>
              <td className="px-2 py-2 text-slate-400">{technique.tactic ?? <span className="text-slate-600">—</span>}</td>
              <td className="px-2 py-2 tabular-nums text-slate-200">{technique.incident_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function MitreTechniqueDetail({ technique, onClose }: { technique: MitreTechniqueCount; onClose: () => void }) {
  return (
    <div className="mt-3 rounded-lg border border-blue-700/40 bg-blue-500/5 p-4">
      <div className="flex items-start justify-between">
        <div>
          <p className="font-mono text-sm text-blue-300">{technique.technique_id}</p>
          <p className="text-xs text-slate-500">{technique.tactic ?? 'Tactic not recorded'} · {technique.incident_count} incident{technique.incident_count === 1 ? '' : 's'}</p>
        </div>
        <button type="button" onClick={onClose} aria-label="Close technique detail" className="text-slate-500 hover:text-slate-200">
          ×
        </button>
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div>
          <p className="text-xs uppercase tracking-wide text-slate-500">Related Incidents</p>
          {technique.related_incident_ids.length === 0 ? (
            <p className="mt-1 text-xs text-slate-600">Not available.</p>
          ) : (
            <ul className="mt-1.5 flex flex-wrap gap-1.5">
              {technique.related_incident_ids.map((id) => (
                <li key={id}>
                  <Link to={`/incidents/${id}`} className="rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5 font-mono text-xs text-slate-300 hover:border-blue-500 hover:text-blue-300">
                    {id.slice(0, 8)}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <p className="text-xs uppercase tracking-wide text-slate-500">Affected Endpoints</p>
          {technique.affected_endpoints.length === 0 ? (
            <p className="mt-1 text-xs text-slate-600">Not available.</p>
          ) : (
            <ul className="mt-1.5 flex flex-wrap gap-1.5">
              {technique.affected_endpoints.map((host) => (
                <li key={host}>
                  <Link to={`/endpoints/${encodeURIComponent(host)}`} className="rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5 font-mono text-xs text-slate-300 hover:border-blue-500 hover:text-blue-300">
                    {host}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

function InvestigationPriorities({ assets }: { assets: AffectedAsset[] }) {
  if (assets.length === 0) {
    return <EmptyState title="No investigation targets" description="No endpoint had both incident activity and a risk score in this window." />;
  }
  return (
    <ol className="space-y-2">
      {assets.map((asset, index) => (
        <li key={asset.host_id} className="flex items-center gap-3 rounded-lg border border-slate-800/80 bg-slate-950/50 px-3 py-2.5">
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-slate-800 text-xs font-semibold text-slate-400">{index + 1}</span>
          <div className="min-w-0 flex-1">
            <Link to={`/endpoints/${encodeURIComponent(asset.host_id)}`} className="font-mono text-sm text-slate-200 hover:text-blue-400 hover:underline">
              {asset.host_id}
            </Link>
            <p className="text-xs text-slate-500">
              {asset.incident_count} incident{asset.incident_count === 1 ? '' : 's'}
              {asset.dominant_category ? ` · ${titleCase(asset.dominant_category)}` : ''}
            </p>
          </div>
          {asset.highest_risk ? <LevelBadge level={asset.highest_risk} /> : <span className="shrink-0 text-xs text-slate-600">Not scored</span>}
        </li>
      ))}
    </ol>
  );
}

function AttackProgression({ trends }: { trends: CategoryTrend[] }) {
  const byCategory = new Map(trends.map((t) => [t.category, t]));
  const stages = ATTACK_PROGRESSION_ORDER.map((category) => byCategory.get(category)).filter(
    (t): t is CategoryTrend => t !== undefined && t.current_count > 0,
  );

  if (stages.length === 0) {
    return <p className="text-sm text-slate-500">No categorized incidents in this window to show a progression for.</p>;
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      {stages.map((stage, index) => (
        <div key={stage.category} className="flex items-center gap-2">
          <div className="rounded-lg border px-3 py-2" style={{ borderColor: `${categoryColor(stage.category)}66`, backgroundColor: `${categoryColor(stage.category)}14` }}>
            <p className="text-xs font-medium text-slate-200">{titleCase(stage.category)}</p>
            <p className="text-xs text-slate-500">{stage.mitre_tactic} · {stage.current_count} incident{stage.current_count === 1 ? '' : 's'}</p>
          </div>
          {index < stages.length - 1 && <span className="text-slate-600">→</span>}
        </div>
      ))}
    </div>
  );
}

export default function ThreatAnalytics() {
  const [windowDays, setWindowDays] = useState(7);
  const [data, setData] = useState<ThreatAnalyticsResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedTechniqueId, setSelectedTechniqueId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);
    setSelectedTechniqueId(null);

    api
      .get<ThreatAnalyticsResponse>('/api/v1/threat-analytics', { params: { window_days: windowDays } })
      .then((response) => {
        if (!cancelled) setData(response.data);
      })
      .catch(() => {
        if (!cancelled) setError('Failed to load threat analytics.');
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [windowDays]);

  const chartData = (data?.trends ?? []).map((trend) => ({
    name: titleCase(trend.category),
    Current: trend.current_count,
    Previous: trend.previous_count,
  }));

  const trendChartData = useMemo(
    () =>
      (data?.daily_trend ?? []).map((d) => ({
        date: d.date,
        label: new Date(d.date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
        count: d.count,
      })),
    [data],
  );

  const categoryDistribution = (data?.trends ?? [])
    .filter((t) => t.current_count > 0)
    .map((t) => ({ name: titleCase(t.category), value: t.current_count, color: categoryColor(t.category) }));
  const categoryTotal = categoryDistribution.reduce((sum, c) => sum + c.value, 0);

  const statusTotal = (data?.status_breakdown ?? []).reduce((sum, s) => sum + s.count, 0);
  const severityTotal = (data?.severity_breakdown ?? []).reduce((sum, s) => sum + s.count, 0);

  const keyFindings = data ? buildKeyFindings(data) : [];
  const investigationPriorities = data ? buildInvestigationPriorities(data) : [];
  const recommendedActions = data ? buildRecommendedActions(data) : [];
  const selectedTechnique = data?.mitre_techniques.find((t) => t.technique_id === selectedTechniqueId) ?? null;

  const statusOrder: StatusCount['status'][] = ['open', 'investigating', 'resolved', 'false_positive'];
  const sortedStatusBreakdown = statusOrder
    .map((status) => data?.status_breakdown.find((s) => s.status === status))
    .filter((s): s is StatusCount => s !== undefined);

  return (
    <Layout>
      <PageHeader
        title="Threat Analytics"
        description="Security intelligence rollup across your tenant's detected incidents."
        actions={
          <label className="flex items-center gap-2 text-sm text-slate-400">
            Window
            <select
              value={windowDays}
              onChange={(e) => setWindowDays(Number(e.target.value))}
              className={selectClasses}
            >
              {WINDOW_OPTIONS.map((days) => (
                <option key={days} value={days}>
                  {days} days
                </option>
              ))}
            </select>
          </label>
        }
      />

      {error && <p className="mt-4 text-sm text-red-400">{error}</p>}

      {/* 1. KPI strip */}
      <section className="mt-6 grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <KpiCard label="Total Incidents" value={data?.kpis.total_incidents ?? 0} hint={`Last ${windowDays} days`} icon={<IncidentIcon className="h-5 w-5" />} tone="default" isLoading={isLoading} />
        <KpiCard label="Open Incidents" value={data?.kpis.open_incidents ?? 0} hint="Awaiting investigation" icon={<IncidentIcon className="h-5 w-5" />} tone="warning" isLoading={isLoading} />
        <KpiCard label="Critical/High" value={data?.kpis.critical_high_incidents ?? 0} hint="By highest linked-alert severity" icon={<AlertIcon className="h-5 w-5" />} tone="danger" isLoading={isLoading} />
        <KpiCard label="Affected Endpoints" value={data?.kpis.affected_endpoints ?? 0} hint="Distinct hosts in window" icon={<EndpointIcon className="h-5 w-5" />} tone="info" isLoading={isLoading} />
        <KpiCard label="Affected Users" value={data?.kpis.affected_users ?? 0} hint="Distinct users in window" icon={<UsersIcon className="h-5 w-5" />} tone="info" isLoading={isLoading} />
        <KpiCard label="Detection Categories" value={data?.kpis.detection_categories ?? 0} hint="Distinct patterns observed" icon={<LayersIcon className="h-5 w-5" />} tone="default" isLoading={isLoading} />
      </section>

      {/* 7. Key findings */}
      <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm shadow-black/20">
        <h2 className="text-sm font-semibold text-slate-200">Key Findings</h2>
        <p className="text-xs text-slate-500">Deterministic summary computed from this window's data — not AI-generated.</p>
        {isLoading ? (
          <div className="mt-3 flex items-center gap-2 text-sm text-slate-500">
            <Spinner className="h-4 w-4" />
            Loading…
          </div>
        ) : keyFindings.length === 0 ? (
          <p className="mt-3 text-sm text-slate-500">No notable activity in this window.</p>
        ) : (
          <ul className="mt-3 space-y-1.5">
            {keyFindings.map((finding) => (
              <li key={finding} className="flex items-start gap-2 text-sm text-slate-300">
                <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-blue-400" />
                {finding}
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Investigation priorities + recommended actions */}
      <section className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm shadow-black/20">
          <h2 className="text-sm font-semibold text-slate-200">Investigation Priorities</h2>
          <p className="text-xs text-slate-500">Ranked by highest endpoint risk, then incident count — no separate scoring model.</p>
          <div className="mt-3">
            {isLoading ? (
              <div className="flex h-32 items-center justify-center"><Spinner className="h-5 w-5 text-slate-600" /></div>
            ) : (
              <InvestigationPriorities assets={investigationPriorities} />
            )}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm shadow-black/20">
          <h2 className="text-sm font-semibold text-slate-200">Recommended Investigation</h2>
          <p className="text-xs text-slate-500">Deterministic, traceable to the data on this page — not AI-generated.</p>
          {isLoading ? (
            <div className="mt-3 flex items-center gap-2 text-sm text-slate-500">
              <Spinner className="h-4 w-4" />
              Loading…
            </div>
          ) : recommendedActions.length === 0 ? (
            <p className="mt-3 text-sm text-slate-500">No recommended actions — no notable activity in this window.</p>
          ) : (
            <ul className="mt-3 space-y-1.5">
              {recommendedActions.map((action) => (
                <li key={action} className="flex items-start gap-2 text-sm text-slate-300">
                  <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-blue-400" />
                  {action}
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      {/* 2. Incident trend */}
      <section className="mt-4">
        <ChartCard title="Incident Trend" subtitle={`Incidents detected per day, last ${windowDays} days`}>
          {isLoading ? (
            <div className="flex h-56 items-center justify-center text-sm text-slate-500">Loading…</div>
          ) : trendChartData.every((d) => d.count === 0) ? (
            <div className="flex h-56 items-center justify-center text-sm text-slate-500">No incidents detected in this window.</div>
          ) : (
            <ResponsiveContainer width="100%" height={224}>
              <AreaChart data={trendChartData} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="incidentTrendFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="label" tick={{ fill: '#64748b', fontSize: 12 }} axisLine={{ stroke: '#1e293b' }} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: '#64748b', fontSize: 12 }} axisLine={false} tickLine={false} width={32} />
                <Tooltip
                  contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: '#cbd5e1' }}
                  itemStyle={{ color: '#93c5fd' }}
                />
                <Area type="monotone" dataKey="count" name="Incidents" stroke="#3b82f6" strokeWidth={2} fill="url(#incidentTrendFill)" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </ChartCard>
      </section>

      {/* 3. Attack category distribution + 6. Status/Severity */}
      <section className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <ChartCard title="Attack Category Distribution" subtitle={`Current ${windowDays}-day window`}>
          {isLoading ? (
            <div className="flex h-48 items-center justify-center"><Spinner className="h-5 w-5 text-slate-600" /></div>
          ) : categoryDistribution.length === 0 ? (
            <div className="flex h-48 items-center justify-center text-sm text-slate-500">No detected patterns in this window.</div>
          ) : (
            <div className="flex items-center gap-3">
              <ResponsiveContainer width="45%" height={170}>
                <PieChart>
                  <Pie data={categoryDistribution} dataKey="value" nameKey="name" innerRadius={40} outerRadius={68} paddingAngle={2}>
                    {categoryDistribution.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} stroke="#0f172a" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, fontSize: 12 }} labelStyle={{ color: '#cbd5e1' }} />
                </PieChart>
              </ResponsiveContainer>
              <ul className="flex-1 space-y-1.5">
                {categoryDistribution.map((entry) => (
                  <DistributionBar key={entry.name} label={entry.name} count={entry.value} total={categoryTotal} color={entry.color} />
                ))}
              </ul>
            </div>
          )}
        </ChartCard>

        <ChartCard title="Incident Status" subtitle={`Current ${windowDays}-day window`}>
          {isLoading ? (
            <div className="flex h-48 items-center justify-center"><Spinner className="h-5 w-5 text-slate-600" /></div>
          ) : statusTotal === 0 ? (
            <div className="flex h-48 items-center justify-center text-sm text-slate-500">No incidents in this window.</div>
          ) : (
            <ul className="mt-2 space-y-2.5">
              {sortedStatusBreakdown.map((s) => (
                <DistributionBar key={s.status} label={STATUS_LABELS[s.status]} count={s.count} total={statusTotal} color={STATUS_COLORS[s.status]} />
              ))}
            </ul>
          )}
        </ChartCard>

        <ChartCard title="Incident Severity" subtitle={`Current ${windowDays}-day window`}>
          {isLoading ? (
            <div className="flex h-48 items-center justify-center"><Spinner className="h-5 w-5 text-slate-600" /></div>
          ) : severityTotal === 0 ? (
            <div className="flex h-48 items-center justify-center text-sm text-slate-500">
              {data && data.kpis.incidents_with_unknown_severity > 0
                ? 'Severity could not be determined for these incidents.'
                : 'No incidents in this window.'}
            </div>
          ) : (
            <ul className="mt-2 space-y-2.5">
              {(data?.severity_breakdown ?? []).map((s) => (
                <DistributionBar key={s.severity} label={titleCase(s.severity)} count={s.count} total={severityTotal} color={SEVERITY_COLORS[s.severity]} />
              ))}
            </ul>
          )}
          {data && data.kpis.incidents_with_unknown_severity > 0 && (
            <p className="mt-3 text-xs text-slate-600">{data.kpis.incidents_with_unknown_severity} incident(s) excluded — severity not resolvable from linked alerts.</p>
          )}
        </ChartCard>
      </section>

      {/* Observed attack progression */}
      <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm shadow-black/20">
        <h2 className="text-sm font-semibold text-slate-200">Observed Attack Progression</h2>
        <p className="text-xs text-slate-500">
          Aggregated categories observed in this window, in typical kill-chain order — not a reconstructed chain for any single incident.
        </p>
        <div className="mt-3">
          {isLoading ? (
            <div className="flex h-16 items-center justify-center"><Spinner className="h-5 w-5 text-slate-600" /></div>
          ) : (
            <AttackProgression trends={data?.trends ?? []} />
          )}
        </div>
      </section>

      {/* 4. MITRE ATT&CK analysis + 5. Affected assets */}
      <section className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm shadow-black/20">
          <h2 className="text-sm font-semibold text-slate-200">MITRE ATT&amp;CK Analysis</h2>
          <p className="text-xs text-slate-500">Most frequently observed techniques, by distinct incident count. Click a technique for detail.</p>
          <div className="mt-3">
            {isLoading ? (
              <div className="flex h-32 items-center justify-center"><Spinner className="h-5 w-5 text-slate-600" /></div>
            ) : (
              <>
                <MitreTechniquesTable
                  techniques={data?.mitre_techniques ?? []}
                  selectedId={selectedTechniqueId}
                  onSelect={(technique) => setSelectedTechniqueId((current) => (current === technique.technique_id ? null : technique.technique_id))}
                />
                {selectedTechnique && <MitreTechniqueDetail technique={selectedTechnique} onClose={() => setSelectedTechniqueId(null)} />}
              </>
            )}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm shadow-black/20">
          <h2 className="text-sm font-semibold text-slate-200">Most Affected Endpoints</h2>
          <p className="text-xs text-slate-500">Ranked by distinct incident count in this window.</p>
          <div className="mt-3">
            {isLoading ? (
              <div className="flex h-32 items-center justify-center"><Spinner className="h-5 w-5 text-slate-600" /></div>
            ) : (
              <AffectedAssetsTable assets={data?.affected_assets ?? []} />
            )}
          </div>
        </div>
      </section>

      {/* 8. Existing: Detected Pattern Trends chart + comparison table */}
      <section className="mt-4">
        <ChartCard title="Detected Pattern Trends" subtitle={`Current vs. previous ${windowDays}-day window`}>
          {!isLoading && data && !data.has_previous_period_data && (
            <p className="mb-3 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-2 text-xs text-slate-400">
              No previous-period data available for comparison — likely a freshly seeded dataset. Figures below reflect the current window only.
            </p>
          )}
          {isLoading ? (
            <div className="flex h-56 items-center justify-center text-sm text-slate-500">Loading…</div>
          ) : chartData.length === 0 ? (
            <div className="flex h-56 items-center justify-center text-sm text-slate-500">
              No detected patterns in either window.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={chartData} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 12 }} axisLine={{ stroke: '#1e293b' }} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: '#64748b', fontSize: 12 }} axisLine={false} tickLine={false} width={32} />
                <Tooltip
                  contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: '#cbd5e1' }}
                />
                <Legend wrapperStyle={{ fontSize: 12, color: '#94a3b8' }} />
                <Bar dataKey="Previous" fill="#334155" radius={[4, 4, 0, 0]} />
                <Bar dataKey="Current" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>
      </section>

      <section className="mt-4 overflow-hidden rounded-xl border border-slate-800">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-3 font-medium">Category</th>
                <th className="px-4 py-3 font-medium">MITRE Tactic</th>
                <th className="px-4 py-3 font-medium">Techniques</th>
                <th className="px-4 py-3 font-medium">Current</th>
                <th className="px-4 py-3 font-medium">Previous</th>
                <th className="px-4 py-3 font-medium">Change</th>
              </tr>
            </thead>
            <tbody>
              {!isLoading && (data?.trends.length ?? 0) === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-sm text-slate-500">
                    No detected patterns in either window.
                  </td>
                </tr>
              ) : (
                (data?.trends ?? []).map((trend) => (
                  <tr key={trend.category} className="border-t border-slate-800/70">
                    <td className="px-4 py-2.5 text-slate-200">{titleCase(trend.category)}</td>
                    <td className="px-4 py-2.5 text-slate-400">{trend.mitre_tactic}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-slate-500">{trend.mitre_technique_ids.join(', ')}</td>
                    <td className="px-4 py-2.5 tabular-nums text-slate-200">{trend.current_count}</td>
                    <td className="px-4 py-2.5 tabular-nums text-slate-400">{trend.previous_count}</td>
                    <td className={`px-4 py-2.5 tabular-nums font-medium ${changeTone(trend)}`}>{formatChangePct(trend)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </Layout>
  );
}
