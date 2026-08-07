import Layout from '../components/Layout';
import { useAuth } from '../hooks/useAuth';
import { useRealtimeEvents, type RealtimeEvent } from '../hooks/useRealtimeEvents';

function describeEvent(event: RealtimeEvent): string {
  if (event.type === 'new_alert') {
    return `Critical alert on ${event.host_id}: ${event.description}`;
  }
  if (event.type === 'chain_detected') {
    const confidence = typeof event.confidence === 'number' ? Math.round(event.confidence * 100) : '?';
    return `Attack chain detected on ${event.host_id}: ${event.pattern} (${confidence}% confidence)`;
  }
  return JSON.stringify(event);
}

export default function Dashboard() {
  const { claims } = useAuth();
  const { events, isConnected } = useRealtimeEvents();

  return (
    <Layout>
      <h1 className="text-xl font-semibold">Dashboard</h1>
      <p className="mt-2 text-slate-400">
        Signed in as <span className="text-slate-200">{claims?.role}</span> for tenant{' '}
        <span className="font-mono text-slate-200">{claims?.tenant_id}</span>.
      </p>

      <section className="mt-6">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Live Activity</h2>
          <span
            className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs ${
              isConnected ? 'bg-green-600/20 text-green-400' : 'bg-slate-700 text-slate-400'
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${isConnected ? 'bg-green-400' : 'bg-slate-500'}`} />
            {isConnected ? 'Live' : 'Reconnecting…'}
          </span>
        </div>

        <ul className="mt-2 space-y-1">
          {events.length === 0 ? (
            <li className="text-sm text-slate-500">
              No real-time events yet — new critical alerts and detected attack chains will appear here.
            </li>
          ) : (
            [...events].reverse().map((event, index) => (
              <li key={index} className="rounded border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-200">
                {describeEvent(event)}
              </li>
            ))
          )}
        </ul>
      </section>
    </Layout>
  );
}
