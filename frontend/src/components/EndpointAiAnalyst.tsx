/**
 * SafeSOC — AI Endpoint Analyst
 * A compact embedded chat scoped to one endpoint, reusing
 * POST /api/v1/investigate (SS-047) exactly as the Investigate page
 * does — no new backend endpoint. Scoping works the same way a typed
 * "host DESKTOP-037" query already does there: the first message seeds
 * a fresh conversation with the host id in its text, so
 * resolve_query()'s existing host-id extraction (services/investigation.py)
 * carries it forward into every follow-up in this session via the same
 * SS-046 context-inheritance this page never modifies.
 *
 * Session-only: a fresh session_id is created on mount and never
 * persisted (no localStorage, no cross-visit memory) — reloading this
 * page or navigating away and back starts a new conversation, same as
 * the main Investigate page. Nothing here claims to remember anything
 * beyond the current session.
 */

import { useEffect, useRef, useState, type FormEvent } from 'react';
import EvidencePanel from './EvidencePanel';
import { BotIcon, SendIcon } from './icons';
import { api } from '../lib/api';
import { fallbackBadgeLabel, titleCase } from '../lib/format';
import type { FallbackReason, InvestigateResponse } from '../lib/types';

interface Message {
  role: 'user' | 'assistant';
  text: string;
  intent?: string;
  data?: Record<string, unknown>;
  isFallback?: boolean;
  fallbackReason?: FallbackReason | null;
}

export default function EndpointAiAnalyst({ hostId }: { hostId: string }) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scrollAnchorRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollAnchorRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, isSending]);

  // New endpoint -> fresh conversation; never carries context from a
  // previously-viewed host into this one.
  useEffect(() => {
    setMessages([]);
    setSessionId(null);
    setError(null);
  }, [hostId]);

  const send = async (rawText: string, { seedsHost }: { seedsHost: boolean } = { seedsHost: false }) => {
    const trimmed = rawText.trim();
    if (!trimmed || isSending) return;

    // Seed queries (the auto-sent first turn) establish host_id in the
    // session context but aren't shown as a user chat bubble — the
    // visible conversation starts with the assistant's own snapshot.
    const text = seedsHost ? `Give me a snapshot of host ${hostId}. ${trimmed}` : `${trimmed} (regarding host ${hostId})`;

    setError(null);
    if (!seedsHost) {
      setMessages((prev) => [...prev, { role: 'user', text: rawText.trim() }]);
    }
    setQuery('');
    setIsSending(true);

    try {
      const response = await api.post<InvestigateResponse>('/api/v1/investigate', {
        query: text,
        session_id: sessionId,
      });
      setSessionId(response.data.session_id);
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: response.data.answer,
          intent: response.data.intent,
          data: response.data.data,
          isFallback: response.data.is_fallback,
          fallbackReason: response.data.fallback_reason,
        },
      ]);
    } catch {
      setError('Failed to reach the investigation assistant.');
    } finally {
      setIsSending(false);
    }
  };

  const startConversation = () => send('What should I know about it?', { seedsHost: true });

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    send(query);
  };

  return (
    <div className="flex h-[420px] flex-col overflow-hidden rounded-lg border border-slate-800 bg-slate-950/40">
      <div className="flex-1 space-y-3 overflow-y-auto p-3">
        {messages.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-3 px-4 text-center">
            <span className="flex h-10 w-10 items-center justify-center rounded-full bg-blue-500/10 text-blue-400">
              <BotIcon className="h-5 w-5" />
            </span>
            <p className="text-sm text-slate-400">
              Ask about <span className="font-mono text-slate-300">{hostId}</span> specifically — its recent alerts, risk
              factors, or activity.
            </p>
            <button
              type="button"
              onClick={startConversation}
              disabled={isSending}
              className="rounded-full border border-slate-700 bg-slate-800 px-3.5 py-1.5 text-xs text-slate-200 transition-colors hover:border-blue-500 hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {isSending ? 'Loading…' : `Start: snapshot of ${hostId}`}
            </button>
          </div>
        ) : (
          messages.map((message, index) => (
            <div key={index} className={`flex gap-2 ${message.role === 'user' ? 'flex-row-reverse' : ''}`}>
              <span
                className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold ${
                  message.role === 'user' ? 'bg-slate-700 text-slate-200' : 'bg-blue-500/15 text-blue-300'
                }`}
              >
                {message.role === 'user' ? 'You' : <BotIcon className="h-3.5 w-3.5" />}
              </span>
              <div className={`flex max-w-[85%] flex-col gap-1 ${message.role === 'user' ? 'items-end' : 'items-start'}`}>
                <div
                  className={`whitespace-pre-wrap rounded-xl px-3 py-2 text-sm leading-relaxed ${
                    message.role === 'user' ? 'rounded-tr-sm bg-blue-600 text-white' : 'rounded-tl-sm bg-slate-800 text-slate-100'
                  }`}
                >
                  {message.text}
                </div>
                {message.intent && message.intent !== 'unknown' && (
                  <span className="px-1 text-[11px] text-slate-500">{titleCase(message.intent)}</span>
                )}
                {message.isFallback && (
                  <span className="rounded-full border border-amber-700/40 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-400">
                    {fallbackBadgeLabel(message.fallbackReason)}
                  </span>
                )}
                {message.data && Object.keys(message.data).length > 0 && <EvidencePanel data={message.data} />}
              </div>
            </div>
          ))
        )}
        {isSending && messages.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-blue-500/15 text-blue-300">
              <BotIcon className="h-3.5 w-3.5" />
            </span>
            <div className="flex items-center gap-1 rounded-xl rounded-tl-sm bg-slate-800 px-3 py-2.5">
              <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-slate-400 [animation-delay:-0.3s]" />
              <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-slate-400 [animation-delay:-0.15s]" />
              <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-slate-400" />
            </div>
          </div>
        )}
        <div ref={scrollAnchorRef} />
      </div>

      {error && <p className="px-3 pb-1.5 text-xs text-red-400">{error}</p>}

      <form onSubmit={handleSubmit} className="flex gap-2 border-t border-slate-800 p-2.5">
        <input
          type="text"
          placeholder={messages.length === 0 ? 'Start the conversation above first…' : `Ask about ${hostId}…`}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          disabled={messages.length === 0}
          className="flex-1 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={isSending || !query.trim() || messages.length === 0}
          className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <SendIcon className="h-4 w-4" />
        </button>
      </form>
    </div>
  );
}
