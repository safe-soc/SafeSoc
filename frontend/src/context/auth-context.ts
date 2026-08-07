import { createContext } from 'react';
import type { JwtClaims } from '../lib/auth-storage';

export interface AuthContextValue {
  token: string | null;
  claims: JwtClaims | null;
  isAuthenticated: boolean;
  login: (tenantId: string, email: string, password: string) => Promise<void>;
  logout: () => void;
}

export const AuthContext = createContext<AuthContextValue | undefined>(undefined);
