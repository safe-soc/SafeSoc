import Layout from '../components/Layout';
import { useAuth } from '../hooks/useAuth';

export default function Dashboard() {
  const { claims } = useAuth();

  return (
    <Layout>
      <h1 className="text-xl font-semibold">Dashboard</h1>
      <p className="mt-2 text-slate-400">
        Signed in as <span className="text-slate-200">{claims?.role}</span> for tenant{' '}
        <span className="font-mono text-slate-200">{claims?.tenant_id}</span>.
      </p>
    </Layout>
  );
}
