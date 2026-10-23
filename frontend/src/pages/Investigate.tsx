/**
 * SafeSOC — Investigation Chat UI (SS-062)
 * Backed by POST /api/v1/investigate (SS-047). The session_id from
 * each response is sent back on the next request, so follow-up
 * questions resolve against the prior turn's context (SS-046) — the
 * conversation transcript itself is the visible proof (AC): a
 * follow-up's answer keeps referencing what was already discussed
 * without the user having to restate it.
 */

import { useEffect, useRef, useState, type FormEvent } from 'react';
import EvidencePanel from '../components/EvidencePanel';
import Layout from '../components/Layout';
import PageHeader from '../components/PageHeader';
import { BotIcon, SendIcon } from '../components/icons';
import { MarkdownAnswer } from '../components/MarkdownAnswer';
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

const SUGGESTED_PROMPTS = ['Show failed logins', 'Highest risk endpoint', 'Active incidents', 'Attack chain summary'];

export default function Investigate() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scrollAnchorRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollAnchorRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, isSending]);

  const send = async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || isSending) return;

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

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    send(query);
  };

  return (
    <Layout>
      <PageHeader
        title="Investigate"
        description="Ask about failed logins, IP activity, endpoint status, top alerts, and more. Follow-up questions carry context forward automatically."
      />

      <div className="mt-4 flex h-[65vh] flex-col overflow-hidden rounded-xl border border-slate-800 bg-slate-900/40">
        <div className="flex-1 space-y-4 overflow-y-auto p-4">
          {messages.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-4 px-6 text-center">
              <span className="flex h-12 w-12 items-center justify-center rounded-full bg-blue-500/10 text-blue-400">
                <BotIcon className="h-6 w-6" />
              </span>
              <div>
                <p className="text-sm font-medium text-slate-300">Ask SafeSOC's investigation assistant anything</p>
                <p className="mt-1 text-sm text-slate-500">Try one of these to get started:</p>
              </div>
              <div className="flex flex-wrap justify-center gap-2">
                {SUGGESTED_PROMPTS.map((prompt) => (
                  <button
                    key={prompt}
                    type="button"
                    onClick={() => send(prompt)}
                    className="rounded-full border border-slate-700 bg-slate-800 px-3.5 py-1.5 text-sm text-slate-200 transition-colors hover:border-blue-500 hover:bg-slate-700"
                  >
                    {prompt}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <>
              {messages.map((message, index) => (
                <div key={index} className={`flex gap-2.5 ${message.role === 'user' ? 'flex-row-reverse' : ''}`}>
                  <span
                    className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-xs font-semibold ${
                      message.role === 'user' ? 'bg-slate-700 text-slate-200' : 'bg-blue-500/15 text-blue-300'
                    }`}
                  >
                    {message.role === 'user' ? 'You' : <BotIcon className="h-4 w-4" />}
                  </span>
                  <div className={`flex max-w-[75%] flex-col gap-1 ${message.role === 'user' ? 'items-end' : 'items-start'}`}>
                    {/* The analyst's own question stays plain text — only an
                        assistant answer is rendered as markdown. */}
                    {message.role === 'user' ? (
                      <div className="whitespace-pre-wrap rounded-2xl rounded-tr-sm bg-blue-600 px-3.5 py-2.5 text-sm leading-relaxed text-white">
                        {message.text}
                      </div>
                    ) : (
                      <MarkdownAnswer className="rounded-2xl rounded-tl-sm bg-slate-800 px-3.5 py-2.5 text-slate-100">
                        {message.text}
                      </MarkdownAnswer>
                    )}
                    {message.intent && message.intent !== 'unknown' && (
                      <span className="px-1 text-xs text-slate-500">{titleCase(message.intent)}</span>
                    )}
                    {message.isFallback && (
                      <span className="rounded-full border border-amber-700/40 bg-amber-500/10 px-2 py-0.5 text-[11px] text-amber-400">
                        {fallbackBadgeLabel(message.fallbackReason)}
                      </span>
                    )}
                    {message.data && Object.keys(message.data).length > 0 && (
                      <EvidencePanel data={message.data} />
                    )}
                  </div>
                </div>
              ))}
              {isSending && (
                <div className="flex items-center gap-2.5">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-blue-500/15 text-blue-300">
                    <BotIcon className="h-4 w-4" />
                  </span>
                  <div className="flex items-center gap-1 rounded-2xl rounded-tl-sm bg-slate-800 px-4 py-3">
                    <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-slate-400 [animation-delay:-0.3s]" />
                    <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-slate-400 [animation-delay:-0.15s]" />
                    <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-slate-400" />
                  </div>
                </div>
              )}
            </>
          )}
          <div ref={scrollAnchorRef} />
        </div>

        {error && <p className="px-4 pb-2 text-sm text-red-400">{error}</p>}

        <form onSubmit={handleSubmit} className="flex gap-2 border-t border-slate-800 p-3">
          <input
            id="chatQuery"
            type="text"
            placeholder="Ask a question…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1 rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-2.5 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
          <button
            type="submit"
            disabled={isSending || !query.trim()}
            className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <SendIcon className="h-4 w-4" />
            Send
          </button>
        </form>
      </div>
    </Layout>
  );
}
