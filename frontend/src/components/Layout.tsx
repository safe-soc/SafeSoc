/**
 * SafeSOC — Dashboard Layout
 * Persistent chrome (header + nav + logout + version footer) wrapping
 * every authenticated page.
 */

import type { ReactNode } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import {
  AlertIcon,
  DashboardIcon,
  EndpointIcon,
  IncidentIcon,
  InvestigateIcon,
  TrendingIcon,
} from './icons';

const APP_VERSION = '1.0.0';

const NAV_LINKS = [
  { to: '/dashboard', label: 'Dashboard', icon: DashboardIcon },
  { to: '/alerts', label: 'Alerts', icon: AlertIcon },
  { to: '/endpoints', label: 'Endpoints', icon: EndpointIcon },
  { to: '/incidents', label: 'Incidents', icon: IncidentIcon },
  { to: '/investigate', label: 'Investigate', icon: InvestigateIcon },
  { to: '/threat-analytics', label: 'Threat Analytics', icon: TrendingIcon },
];

export default function Layout({ children }: { children: ReactNode }) {
  const { logout, claims } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="flex min-h-screen flex-col bg-slate-950 text-slate-100">
      <header className="sticky top-0 z-20 border-b border-slate-800/80 bg-slate-950/95 backdrop-blur supports-[backdrop-filter]:bg-slate-950/75">
        <div className="flex items-center justify-between px-6 py-3">
          <div className="flex items-center gap-8">
            <div className="flex items-center gap-2">
              <span className="flex h-7 w-7 items-center justify-center rounded-md bg-blue-600 text-sm font-bold text-white">
                S
              </span>
              <span className="text-base font-semibold tracking-tight">SafeSOC</span>
            </div>
            <nav className="flex items-center gap-1">
              {NAV_LINKS.map((link) => (
                <NavLink
                  key={link.to}
                  to={link.to}
                  className={({ isActive }) =>
                    `flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                      isActive
                        ? 'bg-slate-800 text-white'
                        : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                    }`
                  }
                >
                  <link.icon className="h-4 w-4" />
                  {link.label}
                </NavLink>
              ))}
            </nav>
          </div>
          <div className="flex items-center gap-3">
            {claims && (
              <span className="hidden text-xs text-slate-500 sm:inline">
                <span className="rounded bg-slate-900 px-1.5 py-0.5 font-medium capitalize text-slate-300">
                  {claims.role}
                </span>
              </span>
            )}
            <button
              type="button"
              onClick={handleLogout}
              className="rounded-md border border-slate-800 bg-slate-900 px-3 py-1.5 text-sm text-slate-300 transition-colors hover:border-slate-700 hover:bg-slate-800 hover:text-white"
            >
              Log out
            </button>
          </div>
        </div>
      </header>

      <main className="flex-1 px-6 py-6">
        <div className="mx-auto w-full max-w-7xl">{children}</div>
      </main>

      <footer className="border-t border-slate-800/80 px-6 py-3 text-center text-xs text-slate-600">
        SafeSOC v{APP_VERSION} — AI-Assisted Multi-Tenant Security Operations Platform
      </footer>
    </div>
  );
}
