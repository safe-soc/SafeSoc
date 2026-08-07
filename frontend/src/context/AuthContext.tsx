/**
 * SafeSOC — Auth Provider
 * Wraps auth-storage.ts's plain token storage in React state, so
 * components re-render on login/logout. login() calls the real
 * backend (POST /api/v1/auth/login, SS-014) and throws on invalid
 * credentials — callers (Login.tsx) decide how to display that.
 *
 * Auto-refresh (SS-058): schedules a POST /api/v1/auth/refresh call
 * shortly before the current token's exp claim, so a session doesn't
 * silently drop mid-use. A failed refresh (token genuinely expired or
 * rejected server-side) logs out — ProtectedRoute then sends the user
 * back to /login, same as any other unauthenticated state.
 */

import { useEffect, useState, type ReactNode } from 'react';
import { api } from '../lib/api';
import { clearToken, decodeToken, getToken, setToken } from '../lib/auth-storage';
import { AuthContext, type AuthContextValue } from './auth-context';

interface TokenResponse {
  access_token: string;
  token_type: string;
}

// Refresh this long before the token's actual expiry, so the call has
// time to complete before the old token would stop working.
const REFRESH_BEFORE_EXPIRY_MS = 60_000;

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setTokenState] = useState<string | null>(() => getToken());

  const login = async (tenantId: string, email: string, password: string): Promise<void> => {
    const response = await api.post<TokenResponse>('/api/v1/auth/login', {
      tenant_id: tenantId,
      email,
      password,
    });
    setToken(response.data.access_token);
    setTokenState(response.data.access_token);
  };

  const logout = (): void => {
    clearToken();
    setTokenState(null);
  };

  useEffect(() => {
    if (!token) return;
    const claims = decodeToken(token);
    if (!claims) return;

    const msUntilExpiry = claims.exp * 1000 - Date.now();
    const refreshInMs = Math.max(0, msUntilExpiry - REFRESH_BEFORE_EXPIRY_MS);

    const timer = setTimeout(() => {
      api
        .post<TokenResponse>('/api/v1/auth/refresh', { token })
        .then((response) => {
          setToken(response.data.access_token);
          setTokenState(response.data.access_token);
        })
        .catch(() => {
          clearToken();
          setTokenState(null);
        });
    }, refreshInMs);

    return () => clearTimeout(timer);
  }, [token]);

  const claims = token ? decodeToken(token) : null;

  const value: AuthContextValue = {
    token,
    claims,
    isAuthenticated: token !== null,
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
