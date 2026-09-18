/**
 * SafeSOC — Generate Report Button
 * Triggers the on-demand PDF investigation report for an incident or
 * endpoint (POST /api/v1/incidents/{id}/report or
 * /api/v1/endpoints/{hostId}/report), then offers "View Report" /
 * "Download PDF" against the returned download_url — the existing
 * tenant-scoped GET /api/v1/reports/{filename} route (SS-054),
 * unmodified. That route requires the caller's JWT like every other
 * API call, so the PDF is fetched as an authenticated blob (api.get
 * with responseType: 'blob') rather than a plain <a href> straight to
 * the backend, which would have no Authorization header.
 */

import { useEffect, useRef, useState } from 'react';
import Spinner from './Spinner';
import { api } from '../lib/api';
import type { InvestigationReportResponse } from '../lib/types';

interface Props {
  scope: 'incident' | 'endpoint';
  id: string;
}

type Status = 'idle' | 'generating' | 'success' | 'error';

export default function GenerateReportButton({ scope, id }: Props) {
  const [status, setStatus] = useState<Status>('idle');
  const [report, setReport] = useState<InvestigationReportResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const blobUrlRef = useRef<string | null>(null);

  // Revoke any object URL we created so the underlying blob memory
  // isn't held onto after this button (or the whole page) unmounts.
  useEffect(() => {
    return () => {
      if (blobUrlRef.current) URL.revokeObjectURL(blobUrlRef.current);
    };
  }, []);

  const generatePath =
    scope === 'incident' ? `/api/v1/incidents/${id}/report` : `/api/v1/endpoints/${encodeURIComponent(id)}/report`;

  const handleGenerate = async () => {
    setStatus('generating');
    setErrorMessage(null);
    try {
      const response = await api.post<InvestigationReportResponse>(generatePath);
      setReport(response.data);
      setStatus('success');
    } catch {
      setErrorMessage(`Failed to generate a report for this ${scope}.`);
      setStatus('error');
    }
  };

  const getBlobUrl = async (): Promise<string> => {
    if (blobUrlRef.current) return blobUrlRef.current;
    if (!report) throw new Error('No report generated yet.');
    const response = await api.get<Blob>(report.download_url, { responseType: 'blob' });
    const url = URL.createObjectURL(response.data);
    blobUrlRef.current = url;
    return url;
  };

  const handleView = async () => {
    try {
      const url = await getBlobUrl();
      window.open(url, '_blank', 'noopener,noreferrer');
    } catch {
      setErrorMessage('Failed to open the generated report.');
    }
  };

  const handleDownload = async () => {
    try {
      const url = await getBlobUrl();
      const link = document.createElement('a');
      link.href = url;
      link.download = report?.filename ?? 'investigation-report.pdf';
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch {
      setErrorMessage('Failed to download the generated report.');
    }
  };

  if (status === 'success' && report) {
    return (
      <div className="flex items-center gap-2">
        <span className="text-xs text-green-400">Report generated successfully</span>
        <button
          type="button"
          onClick={handleView}
          className="rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-1.5 text-sm text-slate-200 transition-colors hover:border-blue-500 hover:bg-slate-700"
        >
          View Report
        </button>
        <button
          type="button"
          onClick={handleDownload}
          className="rounded-lg bg-blue-600 px-3.5 py-1.5 text-sm font-medium text-white transition-colors hover:bg-blue-500"
        >
          Download PDF
        </button>
        <button
          type="button"
          onClick={handleGenerate}
          className="text-xs text-slate-500 hover:text-slate-300"
          title="Regenerate with the latest data"
        >
          Regenerate
        </button>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2">
      {errorMessage && <span className="text-xs text-red-400">{errorMessage}</span>}
      <button
        type="button"
        onClick={handleGenerate}
        disabled={status === 'generating'}
        className="flex items-center gap-2 rounded-lg bg-blue-600 px-3.5 py-1.5 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {status === 'generating' && <Spinner className="h-3.5 w-3.5" />}
        {status === 'generating' ? 'Generating security investigation report…' : 'Generate Report'}
      </button>
    </div>
  );
}
