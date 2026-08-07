/**
 * SafeSOC — Table Loading Skeleton
 * Replaces bare "Loading…" table rows with pulsing placeholder bars,
 * shared across every paginated table page.
 */

export default function TableSkeleton({ rows = 6, columns = 5 }: { rows?: number; columns?: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <tr key={rowIndex} className="border-t border-slate-800/60">
          {Array.from({ length: columns }).map((_, colIndex) => (
            <td key={colIndex} className="px-3 py-3">
              <div
                className="h-3 animate-pulse rounded bg-slate-800"
                style={{ width: `${55 + ((rowIndex * 7 + colIndex * 13) % 35)}%` }}
              />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}
