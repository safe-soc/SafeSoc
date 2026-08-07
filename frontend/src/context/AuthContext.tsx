/**
 * SafeSOC — Auth Provider
 * Wraps auth-storage.ts's plain token storage in React state, so
 * components re-render on login/logout. login() calls the real
 * backend (POST /api/v1/auth/login, SS-014) and throws on invalid
 * credentials — callers (Login.tsx) decide how to display that.
 */

import { useState, type ReactNode } from 'react';
import { api } from '../lib/api';
import { clearToken, decodeToken, getToken, setToken } from '../lib/auth-storage';
import { AuthContext, type AuthContextValue } from './auth-context';

interface TokenResponse {
  access_token: string;
  token_type: string;
}

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
