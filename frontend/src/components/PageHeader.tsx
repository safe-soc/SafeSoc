/**
 * SafeSOC — Page Header
 * Consistent page title + optional description/actions, and sets the
 * browser tab title (useDocumentTitle) so every page doesn't repeat
 * that wiring.
 */

import type { ReactNode } from 'react';
import { useDocumentTitle } from '../hooks/useDocumentTitle';

export default function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  useDocumentTitle(title);

  return (
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        <h1 className="break-words text-2xl font-semibold tracking-tight text-slate-50">{title}</h1>
        {description && <p className="mt-1 text-sm text-slate-400">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}
