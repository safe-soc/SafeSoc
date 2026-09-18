/**
 * SafeSOC — Incident Investigation Panel
 * Persistent, incident-scoped investigation memory
 * (/api/v1/incidents/{id}/investigation/...) — distinct from the
 * one-shot "AI Attack-Chain Summary" above (untouched) and from the
 * general Investigate page's ephemeral, Redis-backed chat session.
 * A session survives a page refresh or a return days later; "New
 * investigation" always starts clean (never inherits a prior
 * session's findings/turns/notes).
 *
 * Evidence shown here is always freshly retrieved from the same
 * backend aggregation the Attack-Chain Summary uses — never a stored
 * snapshot. Findings only become "Confirmed" via the explicit button
 * below; the AI can never mark its own answer as established fact.
 */

import { useCallback, useEffect, useState, type FormEvent } from 'react';
import Spinner from './Spinner';
import { BotIcon } from './icons';
import { api } from '../lib/api';
import { formatDateTime, formatRelativeTime } from '../lib/format';
import type {
  AskQuestionResponse,
  FindingCategory,
  InvestigationAction,
  InvestigationActionStatus,
  InvestigationFinding,
  InvestigationSessionDetail,
  InvestigationSessionSummary,
} from '../lib/types';

const inputClasses =
  'flex-1 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500';
const smallButtonClasses =
  'rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-300 transition-colors hover:border-blue-500 hover:text-blue-300 disabled:cursor-not-allowed disabled:opacity-40';

const FINDING_CATEGORY_LABELS: Record<FindingCategory, string> = {
  confirmed: 'Confirmed',
  hypothesis: 'Hypothesis',
  open_question: 'Open Question',
};
const FINDING_CATEGORY_STYLES: Record<FindingCategory, string> = {
  confirmed: 'border-green-700/50 bg-green-500/10 text-green-300',
  hypothesis: 'border-purple-700/50 bg-purple-500/10 text-purple-300',
  open_question: 'border-amber-700/50 bg-amber-500/10 text-amber-300',
};

function FindingBadge({ category }: { category: FindingCategory }) {
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${FINDING_CATEGORY_STYLES[category]}`}>
      {FINDING_CATEGORY_LABELS[category]}
    </span>
  );
}

export default function IncidentInvestigationPanel({ incidentId }: { incidentId: string }) {
  const [sessions, setSessions] = useState<InvestigationSessionSummary[] | null>(null);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [detail, setDetail] = useState<InvestigationSessionDetail | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isStarting, setIsStarting] = useState(false);

  const [question, setQuestion] = useState('');
  const [isAsking, setIsAsking] = useState(false);

  const [noteBody, setNoteBody] = useState('');
  const [findingText, setFindingText] = useState('');
  const [findingCategory, setFindingCategory] = useState<FindingCategory>('hypothesis');
  const [actionDescription, setActionDescription] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setSessions(null);
    setActiveSessionId(null);
    setDetail(null);
    setError(null);

    api
      .get<InvestigationSessionSummary[]>(`/api/v1/incidents/${incidentId}/investigation/sessions`)
      .then((response) => {
        if (cancelled) return;
        setSessions(response.data);
        if (response.data.length > 0) setActiveSessionId(response.data[0].id); // newest first -> "continue"
      })
      .catch(() => {
        if (!cancelled) setError('Failed to load investigation sessions.');
      });

    return () => {
      cancelled = true;
    };
  }, [incidentId]);

  const loadDetail = useCallback(() => {
    if (!activeSessionId) return;
    setIsLoadingDetail(true);
    api
      .get<InvestigationSessionDetail>(`/api/v1/incidents/${incidentId}/investigation/sessions/${activeSessionId}`)
      .then((response) => setDetail(response.data))
      .catch(() => setError('Failed to load the investigation state.'))
      .finally(() => setIsLoadingDetail(false));
  }, [incidentId, activeSessionId]);

  useEffect(() => {
    loadDetail();
  }, [loadDetail]);

  const handleStart = async () => {
    setIsStarting(true);
    setError(null);
    try {
      const response = await api.post<InvestigationSessionSummary>(`/api/v1/incidents/${incidentId}/investigation/sessions`);
      setSessions((prev) => [response.data, ...(prev ?? [])]);
      setActiveSessionId(response.data.id);
    } catch {
      setError('Failed to start an investigation session.');
    } finally {
      setIsStarting(false);
    }
  };

  const handleAsk = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = question.trim();
    if (!trimmed || !activeSessionId || isAsking) return;
    setIsAsking(true);
    setError(null);
    try {
      await api.post<AskQuestionResponse>(`/api/v1/incidents/${incidentId}/investigation/sessions/${activeSessionId}/ask`, { question: trimmed });
      setQuestion('');
      loadDetail();
    } catch {
      setError('Failed to reach the investigation assistant.');
    } finally {
      setIsAsking(false);
    }
  };

  const handleAddNote = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = noteBody.trim();
    if (!trimmed || !activeSessionId || isSubmitting) return;
    setIsSubmitting(true);
    try {
      await api.post(`/api/v1/incidents/${incidentId}/investigation/sessions/${activeSessionId}/notes`, { body: trimmed });
      setNoteBody('');
      loadDetail();
    } catch {
      setError('Failed to add that note.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleAddFinding = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = findingText.trim();
    if (!trimmed || !activeSessionId || isSubmitting) return;
    setIsSubmitting(true);
    try {
      await api.post(`/api/v1/incidents/${incidentId}/investigation/sessions/${activeSessionId}/findings`, { text: trimmed, category: findingCategory });
      setFindingText('');
      loadDetail();
    } catch {
      setError('Failed to add that finding.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSetFindingCategory = async (finding: InvestigationFinding, category: FindingCategory) => {
    if (!activeSessionId) return;
    setError(null);
    try {
      await api.patch(`/api/v1/incidents/${incidentId}/investigation/sessions/${activeSessionId}/findings/${finding.id}`, { category });
      loadDetail();
    } catch {
      setError('Failed to update that finding.');
    }
  };

  const handleAddAction = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = actionDescription.trim();
    if (!trimmed || !activeSessionId || isSubmitting) return;
    setIsSubmitting(true);
    try {
      await api.post(`/api/v1/incidents/${incidentId}/investigation/sessions/${activeSessionId}/actions`, { description: trimmed });
      setActionDescription('');
      loadDetail();
    } catch {
      setError('Failed to add that action.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSetActionStatus = async (action: InvestigationAction, status: InvestigationActionStatus) => {
    if (!activeSessionId) return;
    setError(null);
    try {
      await api.patch(`/api/v1/incidents/${incidentId}/investigation/sessions/${activeSessionId}/actions/${action.id}`, { status });
      loadDetail();
    } catch {
      setError('Failed to update that action.');
    }
  };

  if (sessions === null) {
    return (
      <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="text-sm font-semibold text-slate-200">Investigation</h2>
        <div className="mt-3 flex items-center gap-2 text-sm text-slate-500">
          <Spinner className="h-4 w-4" />
          Loading…
        </div>
      </section>
    );
  }

  if (sessions.length === 0 || !activeSessionId) {
    return (
      <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="text-sm font-semibold text-slate-200">Investigation</h2>
        <p className="mt-1 text-xs text-slate-500">
          Start a persistent investigation session for this incident — questions, findings, and notes are saved and still here if you leave and come back.
        </p>
        {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
        <button
          type="button"
          onClick={handleStart}
          disabled={isStarting}
          className="mt-3 rounded-lg bg-blue-600 px-3.5 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {isStarting ? 'Starting…' : 'Start Investigation'}
        </button>
      </section>
    );
  }

  const confirmed = detail?.findings.filter((f) => f.category === 'confirmed') ?? [];
  const hypotheses = detail?.findings.filter((f) => f.category === 'hypothesis') ?? [];
  const openQuestions = detail?.findings.filter((f) => f.category === 'open_question') ?? [];

  return (
    <section className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-slate-200">Investigation</h2>
          {detail && (
            <p className="text-xs text-slate-500">
              Session started {formatRelativeTime(detail.created_at)}
              {sessions.length > 1 && ` · ${sessions.length} session(s) for this incident`}
            </p>
          )}
        </div>
        <button
          type="button"
          onClick={handleStart}
          disabled={isStarting}
          className={smallButtonClasses}
          title="Start a fresh session — does not inherit this one's findings or notes"
        >
          {isStarting ? 'Starting…' : 'New Investigation'}
        </button>
      </div>

      {error && <p className="mt-3 text-sm text-red-400">{error}</p>}

      {isLoadingDetail && !detail ? (
        <div className="mt-4 flex items-center gap-2 text-sm text-slate-500">
          <Spinner className="h-4 w-4" />
          Loading investigation state…
        </div>
      ) : detail ? (
        <div className="mt-4 space-y-4">
          {/* Evidence — always live, never a stored snapshot */}
          <div className="rounded-lg border border-slate-800/80 bg-slate-950/50 p-3">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Known (live evidence)</p>
            <dl className="mt-2 grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
              <div>
                <dt className="text-slate-500">Hosts</dt>
                <dd className="mt-0.5 font-mono text-slate-200">{detail.evidence.hosts.join(', ') || '—'}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Users</dt>
                <dd className="mt-0.5 font-mono text-slate-200">{detail.evidence.users.join(', ') || '—'}</dd>
              </div>
              <div>
                <dt className="text-slate-500">MITRE Techniques</dt>
                <dd className="mt-0.5 font-mono text-slate-200">{detail.evidence.mitre_techniques.join(', ') || '—'}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Linked Alerts</dt>
                <dd className="mt-0.5 text-slate-200">{detail.evidence.alert_count}</dd>
              </div>
            </dl>
          </div>

          {/* Conversation */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Conversation</p>
            {detail.turns.length === 0 ? (
              <p className="mt-2 text-sm text-slate-500">No questions asked yet in this session.</p>
            ) : (
              <ul className="mt-2 space-y-2.5">
                {detail.turns.map((turn) => (
                  <li key={turn.id} className="rounded-lg border border-slate-800/80 bg-slate-950/50 p-3">
                    <p className="text-sm font-medium text-slate-200">{turn.question}</p>
                    <div className="mt-1.5 flex items-start gap-2">
                      <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-blue-500/15 text-blue-300">
                        <BotIcon className="h-3 w-3" />
                      </span>
                      <p className="whitespace-pre-wrap text-sm text-slate-300">{turn.answer}</p>
                    </div>
                    <div className="mt-1.5 flex items-center gap-2 pl-7">
                      {turn.is_fallback && (
                        <span className="rounded-full border border-amber-700/40 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-400">
                          Automated summary
                        </span>
                      )}
                      <span className="text-[11px] text-slate-600" title={formatDateTime(turn.created_at)}>
                        {formatRelativeTime(turn.created_at)}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
            <form onSubmit={handleAsk} className="mt-2.5 flex gap-2">
              <input
                type="text"
                placeholder="Ask about this incident — e.g. what did we establish earlier?"
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                disabled={isAsking}
                className={inputClasses}
              />
              <button
                type="submit"
                disabled={isAsking || !question.trim()}
                className="rounded-lg bg-blue-600 px-3.5 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {isAsking ? 'Asking…' : 'Ask'}
              </button>
            </form>
          </div>

          {/* Findings */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Findings</p>
            {detail.findings.length === 0 ? (
              <p className="mt-2 text-sm text-slate-500">No findings recorded yet.</p>
            ) : (
              <ul className="mt-2 space-y-2">
                {[...confirmed, ...hypotheses, ...openQuestions].map((finding) => (
                  <li key={finding.id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800/80 bg-slate-950/50 px-3 py-2">
                    <div className="flex items-center gap-2">
                      <FindingBadge category={finding.category} />
                      <span className="text-sm text-slate-200">{finding.text}</span>
                      {finding.origin === 'ai_suggested' && (
                        <span className="text-[11px] text-slate-600" title="Proposed by the AI — not yet confirmed by an analyst">
                          AI-suggested
                        </span>
                      )}
                    </div>
                    <div className="flex gap-1.5">
                      {finding.category !== 'confirmed' && (
                        <button type="button" onClick={() => handleSetFindingCategory(finding, 'confirmed')} className={smallButtonClasses}>
                          Mark confirmed
                        </button>
                      )}
                      {finding.category !== 'hypothesis' && (
                        <button type="button" onClick={() => handleSetFindingCategory(finding, 'hypothesis')} className={smallButtonClasses}>
                          Mark hypothesis
                        </button>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
            <form onSubmit={handleAddFinding} className="mt-2.5 flex flex-wrap gap-2">
              <input
                type="text"
                placeholder="Record a finding, hypothesis, or open question"
                value={findingText}
                onChange={(e) => setFindingText(e.target.value)}
                className={inputClasses}
              />
              <select
                value={findingCategory}
                onChange={(e) => setFindingCategory(e.target.value as FindingCategory)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-2 text-sm text-slate-100 focus:border-blue-500 focus:outline-none"
              >
                <option value="hypothesis">Hypothesis</option>
                <option value="confirmed">Confirmed</option>
                <option value="open_question">Open Question</option>
              </select>
              <button
                type="submit"
                disabled={isSubmitting || !findingText.trim()}
                className="rounded-lg bg-slate-800 px-3.5 py-2 text-sm text-slate-200 transition-colors hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Add
              </button>
            </form>
          </div>

          {/* Investigative actions */}
          <details className="group">
            <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-slate-500 hover:text-slate-300">
              Investigative Actions {detail.actions.length > 0 && `(${detail.actions.filter((a) => a.status !== 'completed').length} open)`}
            </summary>
            <div className="mt-2">
              {detail.actions.length === 0 ? (
                <p className="text-sm text-slate-500">No follow-up actions recorded yet.</p>
              ) : (
                <ul className="space-y-2">
                  {detail.actions.map((action) => (
                    <li key={action.id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800/80 bg-slate-950/50 px-3 py-2">
                      <span className={`text-sm ${action.status === 'completed' ? 'text-slate-500 line-through' : 'text-slate-200'}`}>{action.description}</span>
                      {action.status !== 'completed' ? (
                        <div className="flex gap-1.5">
                          {action.status === 'open' && (
                            <button type="button" onClick={() => handleSetActionStatus(action, 'in_progress')} className={smallButtonClasses}>
                              Start
                            </button>
                          )}
                          <button type="button" onClick={() => handleSetActionStatus(action, 'completed')} className={smallButtonClasses}>
                            Complete
                          </button>
                        </div>
                      ) : (
                        <span className="text-[11px] text-slate-600">Completed {formatRelativeTime(action.completed_at ?? action.created_at)}</span>
                      )}
                    </li>
                  ))}
                </ul>
              )}
              <form onSubmit={handleAddAction} className="mt-2.5 flex gap-2">
                <input
                  type="text"
                  placeholder="e.g. Pull DNS logs for DEMO-CRITICAL-01"
                  value={actionDescription}
                  onChange={(e) => setActionDescription(e.target.value)}
                  className={inputClasses}
                />
                <button
                  type="submit"
                  disabled={isSubmitting || !actionDescription.trim()}
                  className="rounded-lg bg-slate-800 px-3.5 py-2 text-sm text-slate-200 transition-colors hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Add
                </button>
              </form>
            </div>
          </details>

          {/* Analyst notes */}
          <details className="group">
            <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-slate-500 hover:text-slate-300">
              Analyst Notes {detail.notes.length > 0 && `(${detail.notes.length})`}
            </summary>
            <div className="mt-2">
              {detail.notes.length === 0 ? (
                <p className="text-sm text-slate-500">No notes yet.</p>
              ) : (
                <ul className="space-y-2">
                  {detail.notes.map((note) => (
                    <li key={note.id} className="rounded-lg border border-slate-800/80 bg-slate-950/50 px-3 py-2">
                      <p className="text-sm text-slate-200">{note.body}</p>
                      <p className="mt-1 text-[11px] text-slate-600" title={formatDateTime(note.created_at)}>
                        {formatRelativeTime(note.created_at)}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
              <form onSubmit={handleAddNote} className="mt-2.5 flex gap-2">
                <input
                  type="text"
                  placeholder="Add an analyst note"
                  value={noteBody}
                  onChange={(e) => setNoteBody(e.target.value)}
                  className={inputClasses}
                />
                <button
                  type="submit"
                  disabled={isSubmitting || !noteBody.trim()}
                  className="rounded-lg bg-slate-800 px-3.5 py-2 text-sm text-slate-200 transition-colors hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Add
                </button>
              </form>
            </div>
          </details>
        </div>
      ) : null}
    </section>
  );
}
