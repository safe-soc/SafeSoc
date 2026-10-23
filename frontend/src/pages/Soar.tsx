/**
 * SafeSOC — SOAR Operations (Phase 3)
 * Tenant-wide view over every playbook run (GET /api/v1/soar/runs):
 * KPI summary, actions awaiting approval (highest priority), active
 * runs, recent activity, and full execution history. Every value here
 * is derived client-side from that one fetch — no dedicated
 * aggregation endpoint exists, same approach Dashboard.tsx already
 * takes for its own KPIs. Visual language matches Dashboard.tsx/
 * Compliance.tsx exactly — no new design system.
 */

import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import AutonomyBadge from '../components/AutonomyBadge';
import EmptyState from '../components/EmptyState';
import KpiCard from '../components/KpiCard';
import Layout from '../components/Layout';
import PageHeader from '../components/PageHeader';
import SoarActionApprovalDialog from '../components/SoarActionApprovalDialog';
import SoarStatusBadge from '../components/SoarStatusBadge';
import Spinner from '../components/Spinner';
import { AlertIcon, CheckIcon, SoarIcon, TrendingIcon } from '../components/icons';
import { api } from '../lib/api';
import { titleCase } from '../lib/format';
import Timestamp from '../components/Timestamp';
import { describeTarget, formatActionType } from '../lib/soarLabels';
import type { PlaybookResponse, SoarActionExecution, SoarPlaybookRunDetail } from '../lib/types';

interface AwaitingApprovalEntry {
  run: SoarPlaybookRunDetail;
  action: SoarActionExecution;
}

function mostRecentTimestamp(action: SoarActionExecution): string {
  const candidates = [action.verified_at, action.executed_at, action.rejected_at, action.approved_at, action.created_at].filter(
    (v): v is string => Boolean(v),
  );
  return candidates.sort().at(-1) ?? action.created_at;
}

export default function Soar() {
  const [runs, setRuns] = useState<SoarPlaybookRunDetail[]>([]);
  const [playbookTitles, setPlaybookTitles] = useState<Record<string, string>>({});
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reviewing, setReviewing] = useState<AwaitingApprovalEntry | null>(null);

  const load = useCallback(() => {
    setIsLoading(true);
    setError(null);
    api
      .get<SoarPlaybookRunDetail[]>('/api/v1/soar/runs')
      .then((response) => setRuns(response.data))
      .catch(() => setError('Failed to load SOAR activity.'))
      .finally(() => setIsLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    api
      .get<PlaybookResponse[]>('/api/v1/soar/playbooks')
      .then((response) => {
        const map: Record<string, string> = {};
        for (const playbook of response.data) map[playbook.id] = playbook.title;
        setPlaybookTitles(map);
      })
      .catch(() => undefined);
  }, []);

  const allActions = runs.flatMap((run) => run.actions.map((action) => ({ run, action })));
  const awaitingApproval: AwaitingApprovalEntry[] = allActions.filter((entry) => entry.action.status === 'awaiting_approval');
  const activeRuns = runs.filter((run) => run.status === 'running' || run.status === 'awaiting_approval');
  const automaticExecuted = allActions.filter((entry) => entry.action.autonomy_class === 'automatic' && entry.action.status !== 'pending');
  const successfulActions = allActions.filter((entry) => entry.action.status === 'succeeded');
  const failedActions = allActions.filter((entry) => entry.action.status === 'failed');

  const recentActivity = [...allActions]
    .filter((entry) => entry.action.status !== 'pending')
    .sort((a, b) => mostRecentTimestamp(b.action).localeCompare(mostRecentTimestamp(a.action)))
    .slice(0, 10);

  const runHistory = [...runs].sort((a, b) => b.created_at.localeCompare(a.created_at));

  return (
    <Layout>
      <PageHeader
        title="SOAR Operations"
        description="Security Orchestration, Automation and Response — automated and human-approved playbook actions across every incident in this tenant."
      />

      <div className="mt-4 flex items-start gap-3 rounded-xl border border-blue-800/40 bg-blue-500/5 p-4">
        <SoarIcon className="mt-0.5 h-5 w-5 shrink-0 text-blue-300" />
        <div>
          <p className="text-sm font-semibold text-blue-200">Simulation Mode</p>
          <p className="mt-0.5 text-sm text-blue-300/80">
            No external security infrastructure is modified. Every action here executes only against SafeSOC's own
            simulated adapters — there is no shell, HTTP, or arbitrary-command execution, and no connection to real
            firewalls, EDR agents, or identity providers.
          </p>
        </div>
      </div>

      {error && <p className="mt-4 text-sm text-red-400">{error}</p>}

      {/* KPI row */}
      <section className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <KpiCard label="Active Playbook Runs" value={activeRuns.length} icon={<SoarIcon className="h-5 w-5" />} tone="info" isLoading={isLoading} />
        <KpiCard
          label="Actions Awaiting Approval"
          value={awaitingApproval.length}
          hint="Highest priority"
          icon={<AlertIcon className="h-5 w-5" />}
          tone="warning"
          isLoading={isLoading}
        />
        <KpiCard label="Automatic Actions Executed" value={automaticExecuted.length} icon={<TrendingIcon className="h-5 w-5" />} tone="default" isLoading={isLoading} />
        <KpiCard label="Successful Actions" value={successfulActions.length} icon={<CheckIcon className="h-5 w-5" />} tone="default" isLoading={isLoading} />
        <KpiCard label="Failed Actions" value={failedActions.length} icon={<AlertIcon className="h-5 w-5" />} tone="danger" isLoading={isLoading} />
      </section>

      {/* Actions Awaiting Approval */}
      <section className="mt-6 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="text-sm font-semibold text-slate-200">Actions Awaiting Approval</h2>
        {isLoading ? (
          <div className="mt-3 flex items-center gap-2 text-sm text-slate-500">
            <Spinner />
            Loading…
          </div>
        ) : awaitingApproval.length === 0 ? (
          <p className="mt-3 text-sm text-slate-500">Nothing is currently waiting on an analyst decision.</p>
        ) : (
          <ul className="mt-3 space-y-2">
            {awaitingApproval.map(({ run, action }) => (
              <li
                key={action.id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-800/40 bg-amber-500/5 px-3 py-2.5"
              >
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="font-medium text-slate-200">{formatActionType(action.action_type)}</span>
                  {describeTarget(action) && <span className="font-mono text-xs text-slate-400">{describeTarget(action)}</span>}
                  <AutonomyBadge autonomyClass={action.autonomy_class} />
                  <Link to={`/incidents/${run.incident_id}`} className="text-xs text-blue-400 hover:underline">
                    View incident
                  </Link>
                  <Timestamp iso={action.created_at} format="relative" className="text-xs text-slate-600" />
                </div>
                <button
                  type="button"
                  onClick={() => setReviewing({ run, action })}
                  className="rounded-lg bg-amber-500/15 px-3 py-1 text-xs font-medium text-amber-300 ring-1 ring-inset ring-amber-500/30 transition-colors hover:bg-amber-500/25"
                >
                  Review
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Active Playbook Runs */}
        <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="text-sm font-semibold text-slate-200">Active Playbook Runs</h2>
          {isLoading ? (
            <div className="mt-3 flex items-center gap-2 text-sm text-slate-500">
              <Spinner />
              Loading…
            </div>
          ) : activeRuns.length === 0 ? (
            <p className="mt-3 text-sm text-slate-500">No playbook run is currently in progress.</p>
          ) : (
            <ul className="mt-3 space-y-2">
              {activeRuns.map((run) => (
                <li key={run.id} className="rounded-lg border border-slate-800/70 bg-slate-950/40 px-3 py-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <Link to={`/incidents/${run.incident_id}`} className="text-sm font-medium text-slate-200 hover:text-blue-400 hover:underline">
                      {playbookTitles[run.playbook_id] ?? run.playbook_id}
                    </Link>
                    <SoarStatusBadge status={run.status} />
                  </div>
                  <p className="mt-1 text-xs text-slate-500">
                    {run.actions.length} action{run.actions.length === 1 ? '' : 's'} · <Timestamp iso={run.created_at} format="relative" />
                  </p>
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* Recent SOAR Activity */}
        <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="text-sm font-semibold text-slate-200">Recent SOAR Activity</h2>
          {isLoading ? (
            <div className="mt-3 flex items-center gap-2 text-sm text-slate-500">
              <Spinner />
              Loading…
            </div>
          ) : recentActivity.length === 0 ? (
            <p className="mt-3 text-sm text-slate-500">No SOAR actions have run yet.</p>
          ) : (
            <ul className="mt-3 space-y-2">
              {recentActivity.map(({ run, action }) => (
                <li key={action.id} className="flex items-center justify-between gap-2 rounded-lg border border-slate-800/70 bg-slate-950/40 px-3 py-2 text-sm">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-300">{formatActionType(action.action_type)}</span>
                    <Link to={`/incidents/${run.incident_id}`} className="text-xs text-blue-400 hover:underline">
                      incident
                    </Link>
                  </div>
                  <div className="flex items-center gap-2">
                    <SoarStatusBadge status={action.status} />
                    <Timestamp iso={mostRecentTimestamp(action)} format="relative" className="text-xs text-slate-600" />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      {/* Playbook Execution History */}
      <section className="mt-4 overflow-hidden rounded-xl border border-slate-800">
        <div className="border-b border-slate-800 bg-slate-900/60 px-5 py-3">
          <h2 className="text-sm font-semibold text-slate-200">Playbook Execution History</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-3 font-medium">Playbook</th>
                <th className="px-4 py-3 font-medium">Incident</th>
                <th className="px-4 py-3 font-medium">Triggered By</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Actions</th>
                <th className="px-4 py-3 font-medium">Started</th>
                <th className="px-4 py-3 font-medium">Completed</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? null : runHistory.length === 0 ? (
                <tr>
                  <td colSpan={7}>
                    <EmptyState title="No playbook runs yet" description="No SOAR playbook has been triggered in this tenant yet." />
                  </td>
                </tr>
              ) : (
                runHistory.map((run) => (
                  <tr key={run.id} className="border-t border-slate-800/70 transition-colors hover:bg-slate-800/30">
                    <td className="px-4 py-2.5 font-medium text-slate-200">{playbookTitles[run.playbook_id] ?? run.playbook_id}</td>
                    <td className="px-4 py-2.5">
                      <Link to={`/incidents/${run.incident_id}`} className="text-blue-400 hover:underline">
                        {run.incident_id.slice(0, 8)}
                      </Link>
                    </td>
                    <td className="px-4 py-2.5 text-slate-400">{titleCase(run.triggered_by)}</td>
                    <td className="px-4 py-2.5">
                      <SoarStatusBadge status={run.status} />
                    </td>
                    <td className="px-4 py-2.5 text-slate-400">{run.actions.length}</td>
                    <td className="px-4 py-2.5 whitespace-nowrap text-slate-500"><Timestamp iso={run.started_at} /></td>
                    <td className="px-4 py-2.5 whitespace-nowrap text-slate-500"><Timestamp iso={run.completed_at} /></td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {reviewing && (
        <SoarActionApprovalDialog
          incidentId={reviewing.run.incident_id}
          runId={reviewing.run.id}
          action={reviewing.action}
          onClose={() => setReviewing(null)}
          onDecided={load}
        />
      )}
    </Layout>
  );
}
