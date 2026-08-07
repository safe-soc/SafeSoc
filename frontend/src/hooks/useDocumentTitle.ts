/**
 * SafeSOC — Document Title Hook
 * Sets the browser tab title to "<page> — SafeSOC" for the lifetime of
 * the page that calls it, restoring the previous title on unmount.
 */

import { useEffect } from 'react';

export function useDocumentTitle(title: string): void {
  useEffect(() => {
    const previous = document.title;
    document.title = `${title} — SafeSOC`;
    return () => {
      document.title = previous;
    };
  }, [title]);
}
