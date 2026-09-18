/**
 * SafeSOC — SOAR Response Panel (Phase 3)
 * Mounted on IncidentDetail: every playbook run triggered for this
 * incident, each action's execution-timeline (reusing the Lifecycle
 * section's numbered-circle stepper idiom from IncidentDetail.tsx),
 * and the review entry point for any action currently
 * AWAITING_APPROVAL. Always re-fetches from the backend after a
 * decision — never renders an optimistic result.
 */

import { useCallback, useEffect, useState } from 'react';
import AutonomyBadge from './AutonomyBadge';
import SoarActionApprovalDialog from './SoarActionApprovalDialog';
import SoarStatusBadge from './SoarStatusBadge';
import Spinner from './Spinner';
import { api } from '../lib/api';
import { formatDateTime, formatRelativeTime } from '../lib/format';
import { formatActionType } from '../lib/soarLabels';
import { titleCase } from '../lib/format';
import type { PlaybookResponse, SoarActionExecution, SoarPlaybookRunDetail, SoarPlaybookRunSummary } from '../lib/types';

interface Step {
  key: string;
  label: string;
  timestamp: string | null;
  state: 'done' | 'current' | 'pending' | 'bad';
}

function actionSteps(action: SoarActionExecution): Step[] {
  const s = action.status;

  if (action.autonomy_class === 'automatic') {
    const resultLabel = s === 'failed' ? 'Failed' : 'Succeeded';
    const resultState: Step['state'] = s === 'failed' ? 'bad' : s === 'succeeded' ? 'done' : 'pending';
    return [
      { key: 'pending', label: 'Pending', timestamp: action.created_at, state: 'done' },
      {
        key: 'executing',
        label: 'Executing',
        timestamp: action.executed_at,
        state: s === 'executing' ? 'current' : s === 'succeeded' || s === 'failed' ? 'done' : 'pending',
      },
      { key: 'result', label: resultLabel, timestamp: action.executed_at, state: resultState },
    ];
  }

  if (s === 'rejected') {
    return [
      { key: 'pending', label: 'Pending', timestamp: action.created_at, state: 'done' },
      { key: 'awaiting_approval', label: 'Awaiting Approval', timestamp: action.created_at, state: 'done' },
      { key: 'rejected', label: 'Rejected', timestamp: action.rejected_at, state: 'bad' },
    ];
  }

  const currentIndex =
    s === 'pending' ? 0 : s === 'awaiting_approval' ? 1 : s === 'approved' ? 2 : s === 'executing' ? 3 : 4;
  const resultLabel = s === 'failed' ? 'Failed' : 'Succeeded';

  return [
    { key: 'pending', label: 'Pending', timestamp: action.created_at, state: 'done' },
    {
      key: 'awaiting_approval',
      label: 'Awaiting Approval',
      timestamp: action.created_at,
      state: currentIndex > 1 ? 'done' : currentIndex === 1 ? 'current' : 'pending',
    },
    {
      key: 'approved',
      label: 'Approved',
      timestamp: action.approved_at,
      state: currentIndex > 2 ? 'done' : currentIndex === 2 ? 'current' : 'pending',
    },
    {
      key: 'executing',
      label: 'Executing',
      timestamp: action.executed_at,
      state: currentIndex > 3 ? 'done' : currentIndex === 3 ? 'current' : 'pending',
    },
    {
      key: 'result',
      label: resultLabel,
      timestamp: action.executed_at,
      state: currentIndex < 4 ? 'pending' : s === 'failed' ? 'bad' : 'done',
    },
  ];
}

function ActionTimeline({ action }: { action: SoarActionExecution }) {
  const steps = actionSteps(action);
  return (
    <div className="mt-3 flex items-center">
      {steps.map((step, index) => (
        <div key={step.key} className="flex flex-1 items-center last:flex-none">
          <div className="flex flex-col items-center gap-1 text-center">
            <div
              className={`flex h-6 w-6 items-center justify-center rounded-full border-2 text-[10px] font-semibold ${
                step.state === 'done'
                  ? 'border-green-500 bg-green-500/20 text-green-400'
                  : step.state === 'current'
                    ? 'border-blue-500 bg-blue-500/20 text-blue-300'
                    : step.state === 'bad'
                      ? 'border-red-500 bg-red-500/20 text-red-400'
                      : 'border-slate-700 bg-slate-900 text-slate-600'
              }`}
            >
              {step.state === 'done' ? '✓' : step.state === 'bad' ? '×' : index + 1}
            </div>
            <span className={`text-[10px] leading-tight ${step.state === 'pending' ? 'text-slate-600' : 'text-slate-400'}`}>
              {step.label}
            </span>
            {step.timestamp && <span className="text-[9px] text-slate-600">{formatRelativeTime(step.timestamp)}</span>}
          </div>
          {index < steps.length - 1 && (
            <div className={`mx-1.5 h-0.5 flex-1 rounded ${step.state === 'done' ? 'bg-green-500/60' : 'bg-slate-800'}`} />
          )}
        </div>
      ))}
    </div>
  );
}

export default function SoarResponsePanel({ incidentId }: { incidentId: string }) {
  const [runs, setRuns] = useState<SoarPlaybookRunDetail[]>([]);
  const [playbookTitles, setPlaybookTitles] = useState<Record<string, string>>({});
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reviewing, setReviewing] = useState<{ run: SoarPlaybookRunDetail; action: SoarActionExecution } | null>(null);

  const load = useCallback(() => {
    setIsLoading(true);
    setError(null);
    api
      .get<SoarPlaybookRunSummary[]>(`/api/v1/incidents/${incidentId}/soar/runs`)
      .then(async (response) => {
        const details = await Promise.all(
          response.data.map((run) => api.get<SoarPlaybookRunDetail>(`/api/v1/incidents/${incidentId}/soar/runs/${run.id}`)),
        );
        setRuns(details.map((d) => d.data));
      })
      .catch(() => setError('Failed to load SOAR playbook runs for this incident.'))
      .finally(() => setIsLoading(false));
  }, [incidentId]);

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

  if (isLoading) {
    return (
      <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="text-sm font-semibold text-slate-200">SOAR Response</h2>
        <div className="mt-3 flex items-center gap-2 text-sm text-slate-500">
          <Spinner />
          Loading SOAR activity…
        </div>
      </section>
    );
  }

  return (
    <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">SOAR Response</h2>
        <span className="rounded-full border border-slate-700 bg-slate-800/60 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-slate-400">
          Simulation Mode
        </span>
      </div>

      {error && <p className="mt-3 text-sm text-red-400">{error}</p>}

      {runs.length === 0 ? (
        <p className="mt-3 text-sm text-slate-500">No SOAR playbook has been triggered for this incident yet.</p>
      ) : (
        <div className="mt-3 space-y-4">
          {runs.map((run) => (
            <div key={run.id} className="rounded-lg border border-slate-800/80 bg-slate-950/40 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p className="text-sm font-medium text-slate-200">{playbookTitles[run.playbook_id] ?? run.playbook_id}</p>
                  <p className="mt-0.5 text-xs text-slate-500">
                    Triggered {titleCase(run.triggered_by)} · {formatDateTime(run.created_at)}
                  </p>
                </div>
                <SoarStatusBadge status={run.status} />
              </div>

              <ul className="mt-4 space-y-4">
                {run.actions.map((action) => (
                  <li key={action.id} className="rounded-lg border border-slate-800/70 bg-slate-900/40 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-slate-200">{formatActionType(action.action_type)}</span>
                        <AutonomyBadge autonomyClass={action.autonomy_class} />
                        <SoarStatusBadge status={action.status} />
                      </div>
                      {action.status === 'awaiting_approval' && (
                        <button
                          type="button"
                          onClick={() => setReviewing({ run, action })}
                          className="rounded-lg bg-amber-500/15 px-3 py-1 text-xs font-medium text-amber-300 ring-1 ring-inset ring-amber-500/30 transition-colors hover:bg-amber-500/25"
                        >
                          Review
                        </button>
                      )}
                    </div>

                    <ActionTimeline action={action} />

                    {action.decision_reason && (
                      <p className="mt-2 text-xs text-slate-500">
                        {action.status === 'rejected' ? 'Rejection reason' : 'Approval reason'}: {action.decision_reason}
                      </p>
                    )}
                    {action.result && typeof action.result.message === 'string' && (
                      <p className={`mt-2 text-xs ${action.result.success ? 'text-slate-400' : 'text-red-400'}`}>
                        {action.result.message}
                      </p>
                    )}
                    {action.verification_status !== 'not_verified' && (
                      <p className="mt-1 text-xs text-slate-500">
                        Verification:{' '}
                        <span className={action.verification_status === 'verified' ? 'text-green-400' : 'text-red-400'}>
                          {titleCase(action.verification_status)}
                        </span>
                        {action.verified_at && ` · ${formatRelativeTime(action.verified_at)}`}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}

      {reviewing && (
        <SoarActionApprovalDialog
          incidentId={incidentId}
          runId={reviewing.run.id}
          action={reviewing.action}
          onClose={() => setReviewing(null)}
          onDecided={load}
        />
      )}
    </section>
  );
}
