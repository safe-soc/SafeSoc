/**
 * SafeSOC — Incident Detail View (SS-061)
 * Transitions, alert linking, and notes for one incident (SS-036/037).
 * Only transition buttons the backend's own state machine allows for
 * the incident's CURRENT status are ever rendered (AC) — driven by
 * ALLOWED_TRANSITIONS, the same map services/incidents.py enforces.
 *
 * Per-alert host/severity/MITRE detail is a best-effort lookup against
 * a recent alert fetch (lib/alertLookup.ts) — the Incident resource
 * itself only carries alert_ids (bare strings); an alert outside that
 * lookup window falls back to showing just its ID.
 */

import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Link, useParams } from 'react-router-dom';
import GenerateReportButton from '../components/GenerateReportButton';
import IncidentInvestigationPanel from '../components/IncidentInvestigationPanel';
import SoarResponsePanel from '../components/SoarResponsePanel';
import Layout from '../components/Layout';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import LevelBadge from '../components/LevelBadge';
import MitreBadge from '../components/MitreBadge';
import IncidentTimeline from '../components/IncidentTimeline';
import EvidenceExplorer from '../components/EvidenceExplorer';
import { MarkdownAnswer } from '../components/MarkdownAnswer';
import AttackChainGraph from '../components/AttackChainGraph';
import AttackChainGraphView from '../components/AttackChainGraphView';
import Spinner from '../components/Spinner';
import { api } from '../lib/api';
import { fetchAlertLookup, type AlertLookup } from '../lib/alertLookup';
import { formatDateTime, formatRelativeTime, incidentTitle } from '../lib/format';
import {
  ALLOWED_TRANSITIONS,
  type Incident,
  type IncidentEvidence,
  type IncidentGraph,
  type IncidentNarrativeResponse,
  type IncidentNote,
  type IncidentStatus,
  type TimelineEntry,
} from '../lib/types';

const LIFECYCLE_STEPS: IncidentStatus[] = ['open', 'investigating', 'resolved'];

const inputClasses =
  'flex-1 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500';

export default function IncidentDetail() {
  const { incidentId } = useParams<{ incidentId: string }>();

  const [incident, setIncident] = useState<Incident | null>(null);
  const [notes, setNotes] = useState<IncidentNote[]>([]);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [evidence, setEvidence] = useState<IncidentEvidence | null>(null);
  const [graph, setGraph] = useState<IncidentGraph | null>(null);
  const [lookup, setLookup] = useState<AlertLookup | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const [narrative, setNarrative] = useState<IncidentNarrativeResponse | null>(null);
  const [isGeneratingNarrative, setIsGeneratingNarrative] = useState(false);
  const [narrativeError, setNarrativeError] = useState<string | null>(null);

  const [newAlertId, setNewAlertId] = useState('');
  const [newNoteBody, setNewNoteBody] = useState('');
  const [newTag, setNewTag] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const load = useCallback(() => {
    if (!incidentId) return;
    setIsLoading(true);
    setError(null);
    Promise.all([
      api.get<Incident>(`/api/v1/incidents/${incidentId}`),
      api.get<IncidentNote[]>(`/api/v1/incidents/${incidentId}/notes`),
      api.get<{ incident_id: string; entries: TimelineEntry[] }>(`/api/v1/incidents/${incidentId}/timeline`),
      api.get<IncidentEvidence>(`/api/v1/incidents/${incidentId}/evidence`),
      api.get<IncidentGraph>(`/api/v1/incidents/${incidentId}/graph`),
    ])
      .then(([incidentResponse, notesResponse, timelineResponse, evidenceResponse, graphResponse]) => {
        setIncident(incidentResponse.data);
        setNotes(notesResponse.data);
        setTimeline(timelineResponse.data.entries);
        setEvidence(evidenceResponse.data);
        setGraph(graphResponse.data);
      })
      .catch(() => setError('Failed to load this incident.'))
      .finally(() => setIsLoading(false));
  }, [incidentId]);

  useEffect(() => {
    load();
  }, [load]);

  // Best-effort refresh after an action that changes the timeline
  // (transition/link/note) — mirrors the alert-lookup fetch below in
  // not blocking or erroring the page if it fails.
  const refreshTimeline = useCallback(() => {
    if (!incidentId) return;
    api
      .get<{ incident_id: string; entries: TimelineEntry[] }>(`/api/v1/incidents/${incidentId}/timeline`)
      .then((response) => setTimeline(response.data.entries))
      .catch(() => undefined);
  }, [incidentId]);

  useEffect(() => {
    fetchAlertLookup().then(setLookup).catch(() => undefined);
  }, []);

  const handleTransition = async (toStatus: IncidentStatus) => {
    if (!incidentId) return;
    setActionError(null);
    try {
      const response = await api.post<Incident>(`/api/v1/incidents/${incidentId}/transitions`, {
        to_status: toStatus,
      });
      setIncident(response.data);
      refreshTimeline();
    } catch {
      setActionError('Failed to transition this incident.');
    }
  };

  const handleAddTag = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!incidentId || !incident || !newTag.trim()) return;
    const tag = newTag.trim();
    if (incident.tags.includes(tag)) {
      setNewTag('');
      return;
    }
    setActionError(null);
    try {
      const response = await api.post<Incident>(`/api/v1/incidents/${incidentId}/tags`, {
        tags: [...incident.tags, tag],
      });
      setIncident(response.data);
      setNewTag('');
      refreshTimeline();
    } catch {
      setActionError('Failed to add that tag.');
    }
  };

  const handleRemoveTag = async (tag: string) => {
    if (!incidentId || !incident) return;
    setActionError(null);
    try {
      const response = await api.post<Incident>(`/api/v1/incidents/${incidentId}/tags`, {
        tags: incident.tags.filter((t) => t !== tag),
      });
      setIncident(response.data);
      refreshTimeline();
    } catch {
      setActionError('Failed to remove that tag.');
    }
  };

  const handleGenerateNarrative = async () => {
    if (!incidentId) return;
    setNarrativeError(null);
    setIsGeneratingNarrative(true);
    try {
      const response = await api.post<IncidentNarrativeResponse>(`/api/v1/incidents/${incidentId}/narrative`);
      setNarrative(response.data);
    } catch {
      setNarrativeError('Failed to generate a narrative for this incident.');
    } finally {
      setIsGeneratingNarrative(false);
    }
  };

  const handleLinkAlert = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!incidentId || !newAlertId.trim()) return;
    setActionError(null);
    setIsSubmitting(true);
    try {
      // SS-108: a comma-separated list links a batch in one request;
      // a single id (the common case) keeps sending the original
      // alert_id shape unchanged.
      const ids = newAlertId
        .split(',')
        .map((id) => id.trim())
        .filter(Boolean);
      const payload = ids.length > 1 ? { alert_ids: ids } : { alert_id: ids[0] };
      const response = await api.post<Incident>(`/api/v1/incidents/${incidentId}/alerts`, payload);
      setIncident(response.data);
      setNewAlertId('');
      refreshTimeline();
    } catch {
      setActionError('Failed to link that alert.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleAddNote = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!incidentId || !newNoteBody.trim()) return;
    setActionError(null);
    setIsSubmitting(true);
    try {
      const response = await api.post<IncidentNote>(`/api/v1/incidents/${incidentId}/notes`, {
        body: newNoteBody.trim(),
      });
      setNotes((prev) => [...prev, response.data]);
      setNewNoteBody('');
      refreshTimeline();
    } catch {
      setActionError('Failed to add that note.');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading) {
    return (
      <Layout>
        <div className="flex items-center gap-2 text-slate-500">
          <Spinner />
          Loading incident…
        </div>
      </Layout>
    );
  }

  if (error || !incident) {
    return (
      <Layout>
        <p className="text-sm text-red-400">{error ?? 'Incident not found.'}</p>
      </Layout>
    );
  }

  const availableTransitions = ALLOWED_TRANSITIONS[incident.status];
  const isFalsePositive = incident.status === 'false_positive';
  const currentStepIndex = isFalsePositive ? -1 : LIFECYCLE_STEPS.indexOf(incident.status);

  return (
    <Layout>
      <Link to="/incidents" className="text-sm text-blue-400 hover:underline">
        ← Back to incidents
      </Link>

      <div className="mt-2">
        <PageHeader
          title={incidentTitle(incident)}
          description={
            <>
              Incident{' '}
              <span className="select-all font-mono text-slate-300" title={incident.id}>
                {incident.id.slice(0, 8)}
              </span>{' '}
              · Created {formatDateTime(incident.created_at)} · Updated {formatRelativeTime(incident.updated_at)}
            </>
          }
          actions={<GenerateReportButton scope="incident" id={incident.id} />}
        />
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {incident.severity && <LevelBadge level={incident.severity} />}
          <StatusBadge status={incident.status} />
          {incident.confidence != null && (
            <span className="inline-flex items-center rounded-full bg-violet-500/10 px-2.5 py-0.5 text-xs font-medium tabular-nums text-violet-300 ring-1 ring-inset ring-violet-500/30">
              {Math.round(incident.confidence * 100)}% confidence
            </span>
          )}
        </div>
      </div>

      {actionError && <p className="mt-3 text-sm text-red-400">{actionError}</p>}

      {/* AI narrative */}
      <section className="mt-6 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200">AI Attack-Chain Summary</h2>
          <button
            type="button"
            onClick={handleGenerateNarrative}
            disabled={isGeneratingNarrative}
            className="rounded-lg bg-slate-800 px-3.5 py-1.5 text-xs text-slate-200 transition-colors hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {isGeneratingNarrative ? 'Generating…' : narrative ? 'Regenerate' : 'Generate summary'}
          </button>
        </div>
        {narrativeError && <p className="mt-3 text-sm text-red-400">{narrativeError}</p>}
        {isGeneratingNarrative ? (
          <div className="mt-3 flex items-center gap-2 text-sm text-slate-500">
            <Spinner />
            Summarizing this incident…
          </div>
        ) : narrative ? (
          <div className="mt-3">
            {narrative.is_fallback ? (
              <span className="inline-flex items-center gap-1 rounded-full border border-slate-700 bg-slate-800/80 px-2 py-0.5 text-[11px] text-slate-400">
                Deterministic summary
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 rounded-full border border-blue-700/40 bg-blue-500/10 px-2 py-0.5 text-[11px] text-blue-300">
                AI-generated summary
              </span>
            )}
            <MarkdownAnswer className="mt-2">{narrative.narrative}</MarkdownAnswer>
            {narrative.is_fallback && (
              <p className="mt-2 text-xs text-slate-500">
                The AI summarizer was unavailable — this is a deterministic summary of the same data.
              </p>
            )}
          </div>
        ) : (
          <p className="mt-3 text-sm text-slate-500">Generate an AI-written summary of this incident's attack chain.</p>
        )}
      </section>

      {/* Investigation session — persistent, incident-scoped Q&A/findings/actions/notes */}
      {incidentId && <IncidentInvestigationPanel incidentId={incidentId} />}

      {/* Lifecycle */}
      <section className="mt-6 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="text-sm font-semibold text-slate-200">Lifecycle</h2>

        {isFalsePositive ? (
          <p className="mt-3 text-sm text-slate-500">Marked as a false positive — no further transitions are allowed.</p>
        ) : (
          <div className="mt-4 flex items-center">
            {LIFECYCLE_STEPS.map((step, index) => {
              const isDone = index < currentStepIndex;
              const isCurrent = index === currentStepIndex;
              return (
                <div key={step} className="flex flex-1 items-center last:flex-none">
                  <div className="flex flex-col items-center gap-1.5">
                    <div
                      className={`flex h-7 w-7 items-center justify-center rounded-full border-2 text-xs font-semibold ${
                        isDone
                          ? 'border-green-500 bg-green-500/20 text-green-400'
                          : isCurrent
                            ? 'border-blue-500 bg-blue-500/20 text-blue-300'
                            : 'border-slate-700 bg-slate-900 text-slate-600'
                      }`}
                    >
                      {isDone ? '✓' : index + 1}
                    </div>
                    <span className={`text-xs capitalize ${isCurrent ? 'font-medium text-slate-200' : 'text-slate-500'}`}>
                      {step}
                    </span>
                  </div>
                  {index < LIFECYCLE_STEPS.length - 1 && (
                    <div className={`mx-2 h-0.5 flex-1 rounded ${isDone ? 'bg-green-500/60' : 'bg-slate-800'}`} />
                  )}
                </div>
              );
            })}
          </div>
        )}

        <div className="mt-5 flex flex-wrap gap-2">
          {availableTransitions.length === 0 ? (
            <p className="text-sm text-slate-500">This incident is closed — no further transitions are allowed.</p>
          ) : (
            availableTransitions.map((toStatus) => (
              <button
                key={toStatus}
                type="button"
                onClick={() => handleTransition(toStatus)}
                className={`rounded-lg px-3.5 py-2 text-sm font-medium transition-colors ${
                  toStatus === 'false_positive'
                    ? 'border border-slate-700 text-slate-300 hover:bg-slate-800'
                    : 'bg-blue-600 text-white hover:bg-blue-500'
                }`}
              >
                {toStatus === 'false_positive' ? 'Classify as false positive' : `Move to ${toStatus.replace('_', ' ')}`}
              </button>
            ))
          )}
        </div>
      </section>

      {/* SOAR response — playbook runs, action execution timeline, human approval */}
      {incidentId && <SoarResponsePanel incidentId={incidentId} />}

      {/* Tags */}
      <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="text-sm font-semibold text-slate-200">Tags</h2>
        <div className="mt-3 flex flex-wrap gap-2">
          {incident.tags.length === 0 ? (
            <p className="text-sm text-slate-500">No tags yet.</p>
          ) : (
            incident.tags.map((tag) => (
              <span
                key={tag}
                className="flex items-center gap-1.5 rounded-full bg-slate-800 px-2.5 py-1 text-xs text-slate-300"
              >
                {tag}
                <button
                  type="button"
                  onClick={() => handleRemoveTag(tag)}
                  className="text-slate-500 hover:text-slate-200"
                  aria-label={`Remove tag ${tag}`}
                >
                  ×
                </button>
              </span>
            ))
          )}
        </div>
        <form onSubmit={handleAddTag} className="mt-3 flex gap-2">
          <input
            id="newTag"
            type="text"
            placeholder="Add a tag"
            value={newTag}
            onChange={(e) => setNewTag(e.target.value)}
            className={inputClasses}
          />
          <button
            type="submit"
            disabled={!newTag.trim()}
            className="rounded-lg bg-slate-800 px-3.5 py-2 text-sm text-slate-200 transition-colors hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Add tag
          </button>
        </form>
      </section>

      {/* Timeline */}
      <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="text-sm font-semibold text-slate-200">Investigation Timeline</h2>
        <div className="mt-3">
          <IncidentTimeline entries={timeline} />
        </div>
      </section>

      {/* Evidence explorer */}
      <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="text-sm font-semibold text-slate-200">Evidence</h2>
        <div className="mt-3">{evidence && <EvidenceExplorer evidence={evidence} />}</div>
      </section>

      {/* Attack-chain graph */}
      <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="text-sm font-semibold text-slate-200">Attack Chain</h2>
        <div className="mt-3">{graph && <AttackChainGraphView graph={graph} />}</div>
        {graph && graph.edges.length > 0 && (
          <details className="mt-3 group">
            <summary className="cursor-pointer text-xs text-slate-500 hover:text-slate-300">
              Show as timeline ({graph.edges.length} connection{graph.edges.length === 1 ? '' : 's'})
            </summary>
            <div className="mt-3">
              <AttackChainGraph graph={graph} />
            </div>
          </details>
        )}
      </section>

      {/* Linked alerts */}
      <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="text-sm font-semibold text-slate-200">Linked Alerts ({incident.alert_ids.length})</h2>
        <ul className="mt-3 space-y-1.5">
          {incident.alert_ids.map((alertId) => {
            const resolved = lookup?.alerts.find((a) => a.alert_id === alertId);
            const mitre = lookup?.mitreForAlert.get(alertId);
            return (
              <li
                key={alertId}
                className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-800/80 bg-slate-950/50 px-3 py-2 text-sm"
              >
                {resolved ? (
                  <>
                    <LevelBadge level={resolved.severity} />
                    <span className="font-mono text-slate-300">{resolved.host_id}</span>
                    <span className="text-slate-500">{resolved.action}</span>
                    {mitre && <MitreBadge technique={mitre.technique} tactic={mitre.tactic} />}
                    <span className="ml-auto font-mono text-xs text-slate-600">{alertId.slice(0, 8)}</span>
                  </>
                ) : (
                  <span className="font-mono text-slate-400">{alertId}</span>
                )}
              </li>
            );
          })}
        </ul>
        <form onSubmit={handleLinkAlert} className="mt-3 flex gap-2">
          <input
            id="linkAlertId"
            type="text"
            placeholder="Alert ID to link (comma-separated for multiple)"
            value={newAlertId}
            onChange={(e) => setNewAlertId(e.target.value)}
            className={inputClasses}
          />
          <button
            type="submit"
            disabled={isSubmitting || !newAlertId.trim()}
            className="rounded-lg bg-slate-800 px-3.5 py-2 text-sm text-slate-200 transition-colors hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Link alert
          </button>
        </form>
      </section>

      {/* Notes */}
      <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="text-sm font-semibold text-slate-200">Investigation Notes</h2>
        {notes.length === 0 ? (
          <p className="mt-3 text-sm text-slate-500">No notes yet — document findings as you investigate.</p>
        ) : (
          <ol className="mt-3 space-y-0">
            {notes.map((note, index) => (
              <li key={note.id} className="relative flex gap-3 pb-4 last:pb-0">
                <div className="flex flex-col items-center">
                  <span className="mt-1 h-2 w-2 shrink-0 rounded-full bg-blue-500" />
                  {index < notes.length - 1 && <span className="mt-1 w-px flex-1 bg-slate-800" />}
                </div>
                <div className="flex-1 rounded-lg border border-slate-800/80 bg-slate-950/50 p-3">
                  <p className="text-sm text-slate-200">{note.body}</p>
                  <p className="mt-1.5 text-xs text-slate-500" title={formatDateTime(note.created_at)}>
                    {formatRelativeTime(note.created_at)}
                  </p>
                </div>
              </li>
            ))}
          </ol>
        )}
        <form onSubmit={handleAddNote} className="mt-3 flex gap-2">
          <input
            id="newNoteBody"
            type="text"
            placeholder="Add an investigation note"
            value={newNoteBody}
            onChange={(e) => setNewNoteBody(e.target.value)}
            className={inputClasses}
          />
          <button
            type="submit"
            disabled={isSubmitting || !newNoteBody.trim()}
            className="rounded-lg bg-blue-600 px-3.5 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Add note
          </button>
        </form>
      </section>
    </Layout>
  );
}
