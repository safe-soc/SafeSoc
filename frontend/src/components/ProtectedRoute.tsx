/**
 * SafeSOC — Protected Route Wrapper (SS-058)
 * Guards every authenticated route: an unauthenticated visitor is
 * redirected to /login instead of ever seeing route content.
 */

import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

export default function ProtectedRoute() {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? <Outlet /> : <Navigate to="/login" replace />;
}
