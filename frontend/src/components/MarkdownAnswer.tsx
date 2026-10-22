/**
 * SafeSOC — Markdown Answer
 * Renders an LLM-written answer (incident narrative, investigation
 * conversation turn, Investigate page answer) as markdown instead of
 * raw text, so "**FACTS**", "- " bullets and pipe tables stop leaking
 * into the UI as literal characters.
 *
 * Raw HTML in model output is NEVER rendered: react-markdown escapes it
 * by default and rehype-raw is deliberately NOT installed. Model output
 * is untrusted text (it summarizes attacker-influenced log fields), so
 * markdown is the whole allowed vocabulary — do not add an HTML plugin
 * here.
 *
 * Templated fallback answers are plain sentences and pass through
 * unchanged. User-typed questions are rendered as plain text by their
 * own call sites, never through this component.
 */

import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

interface MarkdownAnswerProps {
  children: string;
  className?: string;
}

export function MarkdownAnswer({ children, className }: MarkdownAnswerProps) {
  return (
    <div className={className}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          p: ({ children }) => <p className="text-sm leading-relaxed text-slate-200 [&:not(:first-child)]:mt-2">{children}</p>,
          h1: ({ children }) => <h3 className="mt-3 text-sm font-semibold text-slate-100 first:mt-0">{children}</h3>,
          h2: ({ children }) => <h3 className="mt-3 text-sm font-semibold text-slate-100 first:mt-0">{children}</h3>,
          h3: ({ children }) => <h3 className="mt-3 text-sm font-semibold text-slate-100 first:mt-0">{children}</h3>,
          h4: ({ children }) => <h4 className="mt-2.5 text-sm font-semibold text-slate-100 first:mt-0">{children}</h4>,
          ul: ({ children }) => <ul className="mt-1.5 list-disc space-y-1 pl-5 text-sm text-slate-200">{children}</ul>,
          ol: ({ children }) => <ol className="mt-1.5 list-decimal space-y-1 pl-5 text-sm text-slate-200">{children}</ol>,
          li: ({ children }) => <li className="leading-relaxed">{children}</li>,
          strong: ({ children }) => <strong className="font-semibold text-slate-100">{children}</strong>,
          em: ({ children }) => <em className="italic">{children}</em>,
          code: ({ className: codeClassName, children }) => {
            // react-markdown gives a fenced block's <code> a
            // language-* class and an inline one none — the only way to
            // tell them apart from inside the `code` renderer.
            const isBlock = typeof codeClassName === 'string' && codeClassName.includes('language-');
            if (isBlock) {
              return <code className="font-mono text-xs text-slate-200">{children}</code>;
            }
            return <code className="rounded bg-slate-800 px-1 font-mono text-xs text-slate-100">{children}</code>;
          },
          pre: ({ children }) => (
            <pre className="mt-2 overflow-x-auto rounded bg-slate-950 p-2 text-xs">{children}</pre>
          ),
          blockquote: ({ children }) => (
            <blockquote className="mt-2 border-l-2 border-slate-700 pl-3 text-sm text-slate-300">{children}</blockquote>
          ),
          hr: () => <hr className="my-3 border-slate-800" />,
          // A wide table must scroll inside its own container rather
          // than widening the panel it sits in.
          table: ({ children }) => (
            <div className="mt-2 overflow-x-auto">
              <table className="w-full border-collapse text-xs">{children}</table>
            </div>
          ),
          thead: ({ children }) => <thead className="bg-slate-800/60">{children}</thead>,
          th: ({ children }) => (
            <th className="border border-slate-700 px-2 py-1 text-left font-semibold text-slate-100">{children}</th>
          ),
          td: ({ children }) => <td className="border border-slate-700 px-2 py-1 text-slate-200">{children}</td>,
          a: ({ href, children }) => (
            <a href={href} target="_blank" rel="noopener noreferrer" className="text-blue-400 underline hover:text-blue-300">
              {children}
            </a>
          ),
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
}
