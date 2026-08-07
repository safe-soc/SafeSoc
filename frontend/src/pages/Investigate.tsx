/**
 * SafeSOC — Investigation Chat UI (SS-062)
 * Backed by POST /api/v1/investigate (SS-047). The session_id from
 * each response is sent back on the next request, so follow-up
 * questions resolve against the prior turn's context (SS-046) — the
 * conversation transcript itself is the visible proof (AC): a
 * follow-up's answer keeps referencing what was already discussed
 * without the user having to restate it.
 */

import { useState, type FormEvent } from 'react';
import Layout from '../components/Layout';
import { api } from '../lib/api';
import type { InvestigateResponse } from '../lib/types';

interface Message {
  role: 'user' | 'assistant';
  text: string;
  intent?: string;
}

export default function Investigate() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = query.trim();
    if (!trimmed) return;

    setError(null);
    setMessages((prev) => [...prev, { role: 'user', text: trimmed }]);
    setQuery('');
    setIsSending(true);

    try {
      const response = await api.post<InvestigateResponse>('/api/v1/investigate', {
        query: trimmed,
        session_id: sessionId,
      });
      setSessionId(response.data.session_id);
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', text: response.data.answer, intent: response.data.intent },
      ]);
    } catch {
      setError('Failed to reach the investigation assistant.');
    } finally {
      setIsSending(false);
    }
  };

  return (
    <Layout>
      <h1 className="text-xl font-semibold">Investigate</h1>
      <p className="mt-1 text-sm text-slate-400">
        Ask about failed logins, IP activity, endpoint status, top alerts, and more. Follow-up questions carry
        context forward automatically.
      </p>

      <div className="mt-4 flex h-[60vh] flex-col rounded border border-slate-800">
        <div className="flex-1 space-y-3 overflow-y-auto p-4">
          {messages.length === 0 ? (
            <p className="text-sm text-slate-500">No messages yet — ask a question below.</p>
          ) : (
            messages.map((message, index) => (
              <div key={index} className={message.role === 'user' ? 'text-right' : 'text-left'}>
                <div
                  className={`inline-block max-w-[80%] rounded-lg px-3 py-2 text-sm ${
                    message.role === 'user' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-100'
                  }`}
                >
                  {message.text}
                </div>
                {message.intent && (
                  <div className="mt-1 text-xs text-slate-500">intent: {message.intent}</div>
                )}
              </div>
            ))
          )}
          {isSending && <p className="text-sm text-slate-500">Thinking…</p>}
        </div>

        {error && <p className="px-4 text-sm text-red-400">{error}</p>}

        <form onSubmit={handleSubmit} className="flex gap-2 border-t border-slate-800 p-3">
          <input
            id="chatQuery"
            type="text"
            placeholder="Ask a question…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1 rounded border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-100"
          />
          <button
            type="submit"
            disabled={isSending || !query.trim()}
            className="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-40"
          >
            Send
          </button>
        </form>
      </div>
    </Layout>
  );
}
