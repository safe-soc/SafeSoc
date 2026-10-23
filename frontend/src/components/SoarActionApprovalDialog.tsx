/**
 * SafeSOC — SOAR Action Approval Dialog (Phase 3)
 * Review surface for one AWAITING_APPROVAL action: what it is, what it
 * targets, and what it would do in SafeSOC's simulated environment
 * (never a real external system — see lib/soarLabels.ts). Approve/
 * Reject POST directly to the backend and always call onDecided()
 * afterward so the parent re-fetches real state from the server —
 * this dialog never assumes success and renders an optimistic result.
 *
 * The first modal in this codebase (no existing dialog/overlay
 * pattern to follow) — styled to match the existing card convention
 * (rounded-xl border border-slate-800 bg-slate-900) rather than
 * introducing a new visual language.
 */

import { useState } from 'react';
import { api } from '../lib/api';
import Timestamp from './Timestamp';
import { describeSimulatedImpact, describeTarget, formatActionType } from '../lib/soarLabels';
import type { SoarActionExecution } from '../lib/types';

export default function SoarActionApprovalDialog({
  incidentId,
  runId,
  action,
  onClose,
  onDecided,
}: {
  incidentId: string;
  runId: string;
  action: SoarActionExecution;
  onClose: () => void;
  onDecided: () => void;
}) {
  const [reason, setReason] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const target = describeTarget(action);

  const decide = async (decision: 'approve' | 'reject') => {
    setIsSubmitting(true);
    setError(null);
    try {
      await api.post(
        `/api/v1/incidents/${incidentId}/soar/runs/${runId}/actions/${action.id}/${decision}`,
        reason.trim() ? { reason: reason.trim() } : {},
      );
      onDecided();
      onClose();
    } catch {
      setError(`Failed to ${decision} this action. It may have already been decided — refreshing may show its current state.`);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="soar-approval-dialog-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-xl shadow-black/40"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3">
          <div>
            <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/10 px-2.5 py-0.5 text-xs font-medium text-amber-300 ring-1 ring-inset ring-amber-500/30">
              Approval Required
            </span>
            <h2 id="soar-approval-dialog-title" className="mt-2 text-base font-semibold text-slate-50">
              {formatActionType(action.action_type)}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="text-slate-500 hover:text-slate-200"
          >
            ×
          </button>
        </div>

        <dl className="mt-4 space-y-3 text-sm">
          {target && (
            <div>
              <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">Target</dt>
              <dd className="mt-0.5 font-mono text-slate-200">{target}</dd>
            </div>
          )}
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">Expected Simulated Impact</dt>
            <dd className="mt-0.5 text-slate-300">{describeSimulatedImpact(action.action_type)}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">Queued</dt>
            <dd className="mt-0.5 text-slate-400">
              <Timestamp iso={action.created_at} />
            </dd>
          </div>
        </dl>

        <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950/60 p-3">
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Simulation Mode</p>
          <p className="mt-1 text-xs text-slate-400">
            No external security infrastructure is modified. This action only affects SafeSOC's own simulated
            environment.
          </p>
        </div>

        <label htmlFor="decision-reason" className="mt-4 block text-xs font-medium uppercase tracking-wide text-slate-500">
          Reasoning (optional)
        </label>
        <textarea
          id="decision-reason"
          rows={2}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Why are you approving or rejecting this action?"
          className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
        />

        {error && <p className="mt-3 text-sm text-red-400">{error}</p>}

        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            onClick={() => decide('reject')}
            disabled={isSubmitting}
            className="rounded-lg border border-red-800/60 px-3.5 py-2 text-sm font-medium text-red-300 transition-colors hover:bg-red-500/10 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Reject
          </button>
          <button
            type="button"
            onClick={() => decide('approve')}
            disabled={isSubmitting}
            className="rounded-lg bg-blue-600 px-3.5 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Approve &amp; Execute
          </button>
        </div>
      </div>
    </div>
  );
}
