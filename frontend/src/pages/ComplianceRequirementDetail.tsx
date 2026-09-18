/**
 * SafeSOC — Compliance Requirement Detail
 * Renders GET /api/v1/compliance/requirements/{id}. Deliberately keeps
 * "Regulatory requirement" (what the law says) and "SafeSOC evidence"
 * (what SafeSOC observed) as two visually distinct sections — never
 * blended into one "compliance" verdict. Related incidents/
 * investigations link back into the existing Incident Detail page
 * (which hosts the persistent investigation panel) rather than
 * duplicating any of that UI here.
 */

import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import Layout from '../components/Layout';
import PageHeader from '../components/PageHeader';
import ComplianceStatusBadge from '../components/ComplianceStatusBadge';
import StatusBadge from '../components/StatusBadge';
import EmptyState from '../components/EmptyState';
import Spinner from '../components/Spinner';
import { ChevronLeftIcon } from '../components/icons';
import { api } from '../lib/api';
import { formatDateTime, titleCase } from '../lib/format';
import type { ComplianceRequirementDetail as ComplianceRequirementDetailType } from '../lib/types';

const FRAMEWORK_LABELS: Record<string, string> = {
  dpdp_act_2023: 'Digital Personal Data Protection Act, 2023',
  cert_in_directions_2022: 'CERT-In Directions, 28.04.2022',
  dpiit: 'DPIIT / Other Applicable Requirements',
};

function metricLabel(key: string): string {
  return titleCase(key);
}

export default function ComplianceRequirementDetail() {
  const { requirementId } = useParams<{ requirementId: string }>();

  const [detail, setDetail] = useState<ComplianceRequirementDetailType | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!requirementId) return;
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    api
      .get<ComplianceRequirementDetailType>(`/api/v1/compliance/requirements/${requirementId}`)
      .then((response) => {
        if (!cancelled) setDetail(response.data);
      })
      .catch((err) => {
        if (cancelled) return;
        if (err?.response?.status === 404) setError('This compliance requirement could not be found.');
        else setError('Failed to load this compliance requirement.');
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [requirementId]);

  if (isLoading) {
    return (
      <Layout>
        <div className="flex h-64 items-center justify-center">
          <Spinner className="h-6 w-6 text-slate-600" />
        </div>
      </Layout>
    );
  }

  if (error || !detail) {
    return (
      <Layout>
        <Link to="/compliance" className="inline-flex items-center gap-1 text-sm text-slate-400 hover:text-slate-200">
          <ChevronLeftIcon className="h-4 w-4" /> Back to Compliance
        </Link>
        <div className="mt-6">
          <EmptyState title="Requirement not found" description={error ?? 'This compliance requirement could not be loaded.'} />
        </div>
      </Layout>
    );
  }

  const metricEntries = Object.entries(detail.metrics);

  return (
    <Layout>
      <Link to="/compliance" className="inline-flex items-center gap-1 text-sm text-slate-400 hover:text-slate-200">
        <ChevronLeftIcon className="h-4 w-4" /> Back to Compliance
      </Link>

      <div className="mt-3">
        <PageHeader
          title={detail.title}
          description={
            <span className="font-mono text-xs text-slate-500">
              {detail.id} · {FRAMEWORK_LABELS[detail.framework] ?? detail.framework} · {detail.reference}
            </span>
          }
          actions={<ComplianceStatusBadge status={detail.status} />}
        />
      </div>

      <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Regulatory requirement — what the law says */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm shadow-black/20">
          <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Regulatory Requirement</h2>
          <p className="mt-3 text-sm leading-relaxed text-slate-300">{detail.requirement_summary}</p>
          <div className="mt-4 border-t border-slate-800 pt-3">
            <p className="text-xs font-medium uppercase tracking-wide text-slate-600">Authoritative Source</p>
            <p className="mt-1 text-xs leading-relaxed text-slate-500">{detail.authoritative_source}</p>
          </div>
        </div>

        {/* SafeSOC evidence — kept visually distinct from the requirement itself */}
        <div className="rounded-xl border border-blue-800/40 bg-blue-500/5 p-5 shadow-sm shadow-black/20">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-blue-300/80">SafeSOC Evidence</h2>
            <span className="text-xs text-slate-500">as of {formatDateTime(detail.last_evaluated)}</span>
          </div>
          <p className="mt-3 text-sm leading-relaxed text-slate-200">{detail.evidence_summary}</p>
          <p className="mt-1 text-xs text-slate-500">What SafeSOC can observe: {detail.what_safesoc_can_observe}</p>

          {metricEntries.length > 0 && (
            <dl className="mt-4 grid grid-cols-2 gap-2.5 border-t border-blue-800/30 pt-3 sm:grid-cols-3">
              {metricEntries.map(([key, value]) => (
                <div key={key}>
                  <dt className="text-[11px] uppercase tracking-wide text-slate-500">{metricLabel(key)}</dt>
                  <dd className="text-lg font-semibold tabular-nums text-slate-100">{value}</dd>
                </div>
              ))}
            </dl>
          )}
        </div>
      </div>

      {/* What SafeSOC cannot verify — the limitation, called out on its own */}
      <div className="mt-4 rounded-xl border border-amber-800/40 bg-amber-500/5 p-5">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-amber-300/80">What SafeSOC Cannot Verify</h2>
        <p className="mt-2 text-sm leading-relaxed text-slate-300">{detail.what_safesoc_cannot_verify}</p>
        <p className="mt-3 text-xs text-slate-500">
          SafeSOC evidence supports, but never by itself establishes, legal compliance. Any compliance determination
          requires organizational and/or legal verification.
        </p>
      </div>

      {/* Recommended action */}
      <div className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="text-sm font-semibold text-slate-200">Recommended Action</h2>
        <p className="mt-2 text-sm text-slate-300">{detail.recommended_action}</p>
      </div>

      {/* Related incidents / investigations — deep links into the existing investigation system */}
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="text-sm font-semibold text-slate-200">Related Incidents</h2>
          <p className="text-xs text-slate-500">Most recent incidents for this tenant relevant to this requirement's evidence.</p>
          {detail.related_incidents.length === 0 ? (
            <p className="mt-3 text-sm text-slate-600">No related incidents.</p>
          ) : (
            <ul className="mt-3 space-y-2">
              {detail.related_incidents.map((incident) => (
                <li key={incident.id}>
                  <Link
                    to={`/incidents/${incident.id}`}
                    className="flex items-center justify-between rounded-lg border border-slate-800/80 bg-slate-950/50 px-3 py-2 text-sm transition-colors hover:border-blue-700/60 hover:bg-slate-900"
                  >
                    <span className="flex items-center gap-2">
                      <span className="font-mono text-xs text-slate-400">{incident.id.slice(0, 8)}</span>
                      {incident.category && <span className="text-slate-500">{titleCase(incident.category)}</span>}
                    </span>
                    <span className="flex items-center gap-2">
                      <StatusBadge status={incident.status} />
                      <span className="text-xs text-slate-600">{formatDateTime(incident.created_at)}</span>
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="text-sm font-semibold text-slate-200">Related Investigations</h2>
          <p className="text-xs text-slate-500">Persistent investigation sessions on this tenant's incidents — confirmed findings/actions live there.</p>
          {detail.related_investigations.length === 0 ? (
            <p className="mt-3 text-sm text-slate-600">No related investigations.</p>
          ) : (
            <ul className="mt-3 space-y-2">
              {detail.related_investigations.map((investigation) => (
                <li key={investigation.session_id}>
                  <Link
                    to={`/incidents/${investigation.incident_id}`}
                    className="flex items-center justify-between rounded-lg border border-slate-800/80 bg-slate-950/50 px-3 py-2 text-sm transition-colors hover:border-blue-700/60 hover:bg-slate-900"
                  >
                    <span className="font-mono text-xs text-slate-400">Session {investigation.session_id.slice(0, 8)}</span>
                    <span className="text-xs text-slate-600">{formatDateTime(investigation.created_at)}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Layout>
  );
}
