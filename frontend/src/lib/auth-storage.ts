/**
 * SafeSOC — Auth Token Storage
 * A plain module (not a React hook) so both the axios interceptor
 * (lib/api.ts) and AuthContext can read/write the current token
 * without needing React context available at axios-setup time.
 */

const TOKEN_KEY = 'safesoc_token';

export interface JwtClaims {
  tenant_id: string;
  user_id: string;
  role: string;
  exp: number;
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

/** Decodes a JWT's payload without verifying its signature — verification is the backend's job; this is purely for reading claims client-side. */
export function decodeToken(token: string): JwtClaims | null {
  try {
    const payload = token.split('.')[1];
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(json) as JwtClaims;
  } catch {
    return null;
  }
}

export function isTokenExpired(token: string): boolean {
  const claims = decodeToken(token);
  if (!claims) return true;
  return claims.exp * 1000 <= Date.now();
}
