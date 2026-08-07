/**
 * SafeSOC — Dashboard
 * KPI summary + charts, built entirely from existing endpoints
 * (GET /api/v1/alerts, /api/v1/incidents, /api/v1/endpoints) — none of
 * this data comes from a dedicated aggregation endpoint, since none
 * exists; every chart/KPI buckets a plain resource fetch client-side.
 * "Active Attack Chains" is a derived heuristic, not a first-class
 * backend concept: a non-terminal (open/investigating) incident whose
 * alert_ids has more than one entry is the product of the correlation
 * engine merging a detected chain (SS-031), vs. a single-alert
 * incident that was most likely created manually.
 */

import { useEffect, useState } from 'react';
import Layout from '../components/Layout';
import PageHeader from '../components/PageHeader';
import KpiCard from '../components/KpiCard';
import { AlertIcon, ChainIcon, EndpointIcon, IncidentIcon } from '../components/icons';
import AlertsOverTimeChart from '../components/dashboard/AlertsOverTimeChart';
import SeverityDistributionChart from '../components/dashboard/SeverityDistributionChart';
import TopHostsWidget from '../components/dashboard/TopHostsWidget';
import LatestIncidentsWidget from '../components/dashboard/LatestIncidentsWidget';
import { useAuth } from '../hooks/useAuth';
import { useRealtimeEvents, type RealtimeEvent } from '../hooks/useRealtimeEvents';
import { api } from '../lib/api';
import type { Alert, AlertSearchResponse, Endpoint, Incident, IncidentListResponse } from '../lib/types';

const WINDOW_HOURS = 168; // 7 days — see module docstring for why this window
const WINDOW_DAYS = WINDOW_HOURS / 24;

function describeEvent(event: RealtimeEvent): string {
  if (event.type === 'new_alert') {
    return `Critical alert on ${event.host_id}: ${event.description}`;
  }
  if (event.type === 'chain_detected') {
    const confidence = typeof event.confidence === 'number' ? Math.round(event.confidence * 100) : '?';
    return `Attack chain detected on ${event.host_id}: ${event.pattern} (${confidence}% confidence)`;
  }
  return JSON.stringify(event);
}

interface DashboardData {
  totalAlerts: number;
  alerts: Alert[];
  openIncidentsCount: number;
  activeAttackChains: number;
  highRiskEndpoints: number;
  latestIncidents: Incident[];
}

export default function Dashboard() {
  const { claims } = useAuth();
  const { events, isConnected } = useRealtimeEvents();

  const [data, setData] = useState<DashboardData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    Promise.all([
      api.get<AlertSearchResponse>('/api/v1/alerts', { params: { timerange_hours: WINDOW_HOURS, size: 500 } }),
      api.get<IncidentListResponse>('/api/v1/incidents', { params: { status: 'open', size: 500 } }),
      api.get<IncidentListResponse>('/api/v1/incidents', { params: { status: 'investigating', size: 500 } }),
      api.get<IncidentListResponse>('/api/v1/incidents', { params: { size: 5 } }),
      api.get<Endpoint[]>('/api/v1/endpoints'),
    ])
      .then(([alertsRes, openRes, investigatingRes, latestRes, endpointsRes]) => {
        if (cancelled) return;

        const nonTerminal = [...openRes.data.incidents, ...investigatingRes.data.incidents];
        const activeAttackChains = nonTerminal.filter((incident) => incident.alert_ids.length > 1).length;
        const highRiskEndpoints = endpointsRes.data.filter(
          (endpoint) => endpoint.risk_level === 'high' || endpoint.risk_level === 'critical',
        ).length;

        setData({
          totalAlerts: alertsRes.data.total,
          alerts: alertsRes.data.alerts,
          openIncidentsCount: openRes.data.total,
          activeAttackChains,
          highRiskEndpoints,
          latestIncidents: latestRes.data.incidents,
        });
      })
      .catch(() => {
        if (!cancelled) setError('Failed to load dashboard data.');
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <Layout>
      <PageHeader
        title="Dashboard"
        description={
          <>
            Signed in as <span className="text-slate-300">{claims?.role}</span> for tenant{' '}
            <span className="font-mono text-slate-300">{claims?.tenant_id}</span>
          </>
        }
      />

      {error && <p className="mt-4 text-sm text-red-400">{error}</p>}

      <section className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard
          label="Total Alerts"
          value={data?.totalAlerts ?? 0}
          hint={`Last ${WINDOW_DAYS} days`}
          icon={<AlertIcon className="h-5 w-5" />}
          tone="info"
          isLoading={isLoading}
        />
        <KpiCard
          label="Open Incidents"
          value={data?.openIncidentsCount ?? 0}
          hint="Awaiting investigation"
          icon={<IncidentIcon className="h-5 w-5" />}
          tone="warning"
          isLoading={isLoading}
        />
        <KpiCard
          label="High Risk Endpoints"
          value={data?.highRiskEndpoints ?? 0}
          hint="Risk level high or critical"
          icon={<EndpointIcon className="h-5 w-5" />}
          tone="danger"
          isLoading={isLoading}
        />
        <KpiCard
          label="Active Attack Chains"
          value={data?.activeAttackChains ?? 0}
          hint="Multi-alert incidents, not yet closed"
          icon={<ChainIcon className="h-5 w-5" />}
          tone="danger"
          isLoading={isLoading}
        />
      </section>

      <section className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <AlertsOverTimeChart alerts={data?.alerts ?? []} days={WINDOW_DAYS} />
        <SeverityDistributionChart alerts={data?.alerts ?? []} />
      </section>

      <section className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <TopHostsWidget alerts={data?.alerts ?? []} />
        <LatestIncidentsWidget incidents={data?.latestIncidents ?? []} isLoading={isLoading} />
      </section>

      <section className="mt-6 rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm shadow-black/20">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-semibold text-slate-200">Live Activity</h2>
          <span
            className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs ${
              isConnected ? 'bg-green-500/10 text-green-400' : 'bg-slate-800 text-slate-400'
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${isConnected ? 'animate-pulse bg-green-400' : 'bg-slate-500'}`} />
            {isConnected ? 'Live' : 'Reconnecting…'}
          </span>
        </div>

        <ul className="mt-3 space-y-1.5">
          {events.length === 0 ? (
            <li className="text-sm text-slate-500">
              No real-time events yet — new critical alerts and detected attack chains will appear here.
            </li>
          ) : (
            [...events].reverse().map((event, index) => (
              <li key={index} className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-sm text-slate-200">
                {describeEvent(event)}
              </li>
            ))
          )}
        </ul>
      </section>
    </Layout>
  );
}
