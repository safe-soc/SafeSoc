/**
 * SafeSOC — Priority Elevated Badge
 * Incident has no priority column; SOAR's increase_incident_priority
 * action marks an incident with the 'priority:elevated' tag instead
 * (services/soar_execution.py). Renders nothing for any other incident.
 */

export const PRIORITY_ELEVATED_TAG = 'priority:elevated';

export default function PriorityElevatedBadge({ tags }: { tags: string[] }) {
  if (!tags.includes(PRIORITY_ELEVATED_TAG)) return null;
  return (
    <span className="inline-flex items-center whitespace-nowrap rounded-full bg-orange-500/10 px-2.5 py-0.5 text-xs font-medium text-orange-300 ring-1 ring-inset ring-orange-500/30">
      Priority elevated
    </span>
  );
}
