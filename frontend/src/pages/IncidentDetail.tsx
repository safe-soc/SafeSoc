/**
 * SafeSOC — Incident Detail View (SS-061)
 * Transitions, alert linking, and notes for one incident (SS-036/037).
 * Only transition buttons the backend's own state machine allows for
 * the incident's CURRENT status are ever rendered (AC) — driven by
 * ALLOWED_TRANSITIONS, the same map services/incidents.py enforces.
 */

import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Link, useParams } from 'react-router-dom';
import Layout from '../components/Layout';
import StatusBadge from '../components/StatusBadge';
import { api } from '../lib/api';
import { ALLOWED_TRANSITIONS, type Incident, type IncidentNote, type IncidentStatus } from '../lib/types';

export default function IncidentDetail() {
  const { incidentId } = useParams<{ incidentId: string }>();

  const [incident, setIncident] = useState<Incident | null>(null);
  const [notes, setNotes] = useState<IncidentNote[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const [newAlertId, setNewAlertId] = useState('');
  const [newNoteBody, setNewNoteBody] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const load = useCallback(() => {
    if (!incidentId) return;
    setIsLoading(true);
    setError(null);
    Promise.all([
      api.get<Incident>(`/api/v1/incidents/${incidentId}`),
      api.get<IncidentNote[]>(`/api/v1/incidents/${incidentId}/notes`),
    ])
      .then(([incidentResponse, notesResponse]) => {
        setIncident(incidentResponse.data);
        setNotes(notesResponse.data);
      })
      .catch(() => setError('Failed to load this incident.'))
      .finally(() => setIsLoading(false));
  }, [incidentId]);

  useEffect(() => {
    load();
  }, [load]);

  const handleTransition = async (toStatus: IncidentStatus) => {
    if (!incidentId) return;
    setActionError(null);
    try {
      const response = await api.post<Incident>(`/api/v1/incidents/${incidentId}/transitions`, {
        to_status: toStatus,
      });
      setIncident(response.data);
    } catch {
      setActionError('Failed to transition this incident.');
    }
  };

  const handleLinkAlert = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!incidentId || !newAlertId.trim()) return;
    setActionError(null);
    setIsSubmitting(true);
    try {
      const response = await api.post<Incident>(`/api/v1/incidents/${incidentId}/alerts`, {
        alert_id: newAlertId.trim(),
      });
      setIncident(response.data);
      setNewAlertId('');
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
    } catch {
      setActionError('Failed to add that note.');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading) {
    return (
      <Layout>
        <p className="text-slate-500">Loading…</p>
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

  return (
    <Layout>
      <Link to="/incidents" className="text-sm text-blue-400 hover:underline">
        ← Back to incidents
      </Link>

      <div className="mt-2 flex items-center gap-3">
        <h1 className="font-mono text-xl font-semibold">{incident.id}</h1>
        <StatusBadge status={incident.status} />
      </div>
      <p className="mt-1 text-sm text-slate-400">
        Created {new Date(incident.created_at).toLocaleString()} · Updated{' '}
        {new Date(incident.updated_at).toLocaleString()}
      </p>

      {actionError && <p className="mt-3 text-sm text-red-400">{actionError}</p>}

      <section className="mt-6">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Lifecycle</h2>
        <div className="mt-2 flex gap-2">
          {availableTransitions.length === 0 ? (
            <p className="text-sm text-slate-500">This incident is closed — no further transitions are allowed.</p>
          ) : (
            availableTransitions.map((toStatus) => (
              <button
                key={toStatus}
                type="button"
                onClick={() => handleTransition(toStatus)}
                className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-500"
              >
                Move to {toStatus.replace('_', ' ')}
              </button>
            ))
          )}
        </div>
      </section>

      <section className="mt-6">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
          Linked Alerts ({incident.alert_ids.length})
        </h2>
        <ul className="mt-2 space-y-1">
          {incident.alert_ids.map((alertId) => (
            <li key={alertId} className="font-mono text-sm text-slate-300">
              {alertId}
            </li>
          ))}
        </ul>
        <form onSubmit={handleLinkAlert} className="mt-3 flex gap-2">
          <input
            id="linkAlertId"
            type="text"
            placeholder="Alert ID to link"
            value={newAlertId}
            onChange={(e) => setNewAlertId(e.target.value)}
            className="flex-1 rounded border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm text-slate-100"
          />
          <button
            type="submit"
            disabled={isSubmitting || !newAlertId.trim()}
            className="rounded bg-slate-800 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-700 disabled:opacity-40"
          >
            Link alert
          </button>
        </form>
      </section>

      <section className="mt-6">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Notes</h2>
        <ul className="mt-2 space-y-2">
          {notes.length === 0 ? (
            <li className="text-sm text-slate-500">No notes yet.</li>
          ) : (
            notes.map((note) => (
              <li key={note.id} className="rounded border border-slate-800 bg-slate-900 p-3 text-sm">
                <p className="text-slate-200">{note.body}</p>
                <p className="mt-1 text-xs text-slate-500">{new Date(note.created_at).toLocaleString()}</p>
              </li>
            ))
          )}
        </ul>
        <form onSubmit={handleAddNote} className="mt-3 flex gap-2">
          <input
            id="newNoteBody"
            type="text"
            placeholder="Add an investigation note"
            value={newNoteBody}
            onChange={(e) => setNewNoteBody(e.target.value)}
            className="flex-1 rounded border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm text-slate-100"
          />
          <button
            type="submit"
            disabled={isSubmitting || !newNoteBody.trim()}
            className="rounded bg-slate-800 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-700 disabled:opacity-40"
          >
            Add note
          </button>
        </form>
      </section>
    </Layout>
  );
}
