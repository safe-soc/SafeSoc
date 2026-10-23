/**
 * SafeSOC — Compliance Posture (Compliance Center)
 * Renders GET /api/v1/compliance/requirements: KPI totals, a
 * per-framework rollup (DPDP Act, CERT-In Directions, DPIIT/Other
 * Applicable Requirements), and the full requirement table. Every
 * value is computed live server-side from existing SafeSOC evidence —
 * see services/compliance.py. This page never asserts legal
 * compliance; ComplianceStatusBadge renders only the four approved
 * phrasings. Visual language matches ThreatAnalytics.tsx/Incidents.tsx
 * exactly — no new visual system, no AI-flavored decoration.
 */

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import Layout from '../components/Layout';
import PageHeader from '../components/PageHeader';
import KpiCard from '../components/KpiCard';
import ComplianceStatusBadge from '../components/ComplianceStatusBadge';
import EmptyState from '../components/EmptyState';
import TableSkeleton from '../components/TableSkeleton';
import { AlertIcon, ComplianceIcon, EndpointIcon, IncidentIcon, LayersIcon } from '../components/icons';
import { api } from '../lib/api';
import Timestamp from '../components/Timestamp';
import type { CompliancePostureResponse, ComplianceFrameworkSummary } from '../lib/types';

function FrameworkCard({ framework }: { framework: ComplianceFrameworkSummary }) {
  const rows: { label: string; count: number; tone: string }[] = [
    { label: 'Evidence available', count: framework.evidence_available, tone: 'text-green-400' },
    { label: 'Control appears supported', count: framework.partially_supported, tone: 'text-blue-400' },
    { label: 'Evidence gap', count: framework.gaps, tone: 'text-amber-400' },
    { label: 'Not assessable', count: framework.not_assessable, tone: 'text-slate-500' },
  ];

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm shadow-black/20">
      <h3 className="text-sm font-semibold text-slate-200">{framework.title}</h3>
      <p className="mt-0.5 text-xs text-slate-500">{framework.total_requirements} requirement{framework.total_requirements === 1 ? '' : 's'} tracked</p>
      <ul className="mt-3 space-y-1.5">
        {rows.map((row) => (
          <li key={row.label} className="flex items-center justify-between text-sm">
            <span className="text-slate-400">{row.label}</span>
            <span className={`font-medium tabular-nums ${row.tone}`}>{row.count}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function Compliance() {
  const [data, setData] = useState<CompliancePostureResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    api
      .get<CompliancePostureResponse>('/api/v1/compliance/requirements')
      .then((response) => {
        if (!cancelled) setData(response.data);
      })
      .catch(() => {
        if (!cancelled) setError('Failed to load compliance posture.');
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
        title="Compliance Posture"
        description="Evidence mapping against applicable Indian regulatory requirements — the Digital Personal Data Protection Act, 2023 and the CERT-In Directions dated 28.04.2022. SafeSOC evidence supports, but does not by itself establish, legal compliance — see docs/compliance.md."
      />

      {error && <p className="mt-4 text-sm text-red-400">{error}</p>}

      {/* 1. KPI row */}
      <section className="mt-6 grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
        <KpiCard label="Requirements Assessed" value={data?.requirements_assessed ?? 0} hint="Across all frameworks" icon={<ComplianceIcon className="h-5 w-5" />} tone="default" isLoading={isLoading} />
        <KpiCard label="Evidence Available" value={data?.evidence_available ?? 0} hint="Meaningful evidence found" icon={<IncidentIcon className="h-5 w-5" />} tone="info" isLoading={isLoading} />
        <KpiCard label="Control Appears Supported" value={data?.partially_supported ?? 0} hint="Partial technical evidence" icon={<LayersIcon className="h-5 w-5" />} tone="info" isLoading={isLoading} />
        <KpiCard label="Evidence Gaps" value={data?.gaps ?? 0} hint="No meaningful evidence found" icon={<AlertIcon className="h-5 w-5" />} tone="warning" isLoading={isLoading} />
        <KpiCard label="Not Assessable" value={data?.not_assessable ?? 0} hint="Outside SafeSOC telemetry" icon={<EndpointIcon className="h-5 w-5" />} tone="default" isLoading={isLoading} />
      </section>

      {/* 2. Framework cards */}
      <section className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        {isLoading
          ? Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="h-40 animate-pulse rounded-xl border border-slate-800 bg-slate-900/40" />
            ))
          : (data?.frameworks ?? []).map((framework) => <FrameworkCard key={framework.framework} framework={framework} />)}
      </section>

      {/* 3. Requirement table */}
      <section className="mt-4 overflow-hidden rounded-xl border border-slate-800">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-3 font-medium">Framework</th>
                <th className="px-4 py-3 font-medium">Requirement</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Evidence</th>
                <th className="px-4 py-3 font-medium">Last Evaluated</th>
                <th className="px-4 py-3 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <TableSkeleton rows={10} columns={6} />
              ) : (data?.requirements.length ?? 0) === 0 ? (
                <tr>
                  <td colSpan={6}>
                    <EmptyState title="No requirements configured" description="No compliance requirement mapping is available." />
                  </td>
                </tr>
              ) : (
                (data?.requirements ?? []).map((req) => (
                  <tr key={req.id} className="border-t border-slate-800/70 transition-colors hover:bg-slate-800/30">
                    <td className="px-4 py-2.5 text-slate-400">{req.reference.split(';')[0]}</td>
                    <td className="px-4 py-2.5">
                      <Link to={`/compliance/${req.id}`} className="font-medium text-slate-200 hover:text-blue-400 hover:underline">
                        {req.title}
                      </Link>
                      <p className="mt-0.5 font-mono text-xs text-slate-600">{req.id}</p>
                    </td>
                    <td className="px-4 py-2.5"><ComplianceStatusBadge status={req.status} /></td>
                    <td className="max-w-sm px-4 py-2.5 text-slate-400" title={req.evidence_summary}>
                      <span className="line-clamp-2">{req.evidence_summary}</span>
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap text-slate-500"><Timestamp iso={req.last_evaluated} /></td>
                    <td className="px-4 py-2.5 text-right">
                      <Link to={`/compliance/${req.id}`} className="text-xs font-medium text-blue-400 hover:text-blue-300 hover:underline">
                        View
                      </Link>
                    </td>
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
