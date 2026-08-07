/**
 * SafeSOC — Login Page
 * Authenticates against POST /api/v1/auth/login (SS-014), which
 * requires tenant_id + email + password (SafeSOC has no
 * "look up tenant by email" endpoint, so all three are real,
 * necessary fields — not an invented UX shortcut).
 */

import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();

  const [tenantId, setTenantId] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      await login(tenantId, email, password);
      navigate('/dashboard', { replace: true });
    } catch {
      setError('Invalid tenant ID, email, or password.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm space-y-4 rounded-lg border border-slate-800 bg-slate-900 p-8"
      >
        <h1 className="text-2xl font-bold text-slate-100">SafeSOC</h1>
        <p className="text-sm text-slate-400">Sign in to your organization's SOC dashboard.</p>

        <div>
          <label htmlFor="tenantId" className="mb-1 block text-sm text-slate-300">
            Tenant ID
          </label>
          <input
            id="tenantId"
            type="text"
            required
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            className="w-full rounded border border-slate-700 bg-slate-800 px-3 py-2 text-slate-100"
          />
        </div>

        <div>
          <label htmlFor="email" className="mb-1 block text-sm text-slate-300">
            Email
          </label>
          <input
            id="email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded border border-slate-700 bg-slate-800 px-3 py-2 text-slate-100"
          />
        </div>

        <div>
          <label htmlFor="password" className="mb-1 block text-sm text-slate-300">
            Password
          </label>
          <input
            id="password"
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded border border-slate-700 bg-slate-800 px-3 py-2 text-slate-100"
          />
        </div>

        {error && (
          <p role="alert" className="text-sm text-red-400">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={isSubmitting}
          className="w-full rounded bg-blue-600 px-3 py-2 font-medium text-white hover:bg-blue-500 disabled:opacity-50"
        >
          {isSubmitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}
