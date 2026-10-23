/**
 * SafeSOC — Real-Time Dashboard Events Hook (SS-063)
 * Connects to GET /ws?token=<JWT>, appending each received event to a
 * bounded list. A closed connection (network blip, server restart)
 * reconnects automatically after a fixed delay — handled here so no
 * page using this hook has to think about it (AC: "Connection drop/
 * reconnect handled gracefully").
 */

import { useEffect, useRef, useState } from 'react';
import { useAuth } from './useAuth';
import { clearToken } from '../lib/auth-storage';

export interface RealtimeEvent {
  type: string;
  [key: string]: unknown;
}

const WS_BASE_URL: string = import.meta.env.VITE_WS_BASE_URL ?? 'ws://localhost:8000';
const RECONNECT_DELAY_MS = 3000;
const MAX_EVENTS = 20;

export function useRealtimeEvents(): { events: RealtimeEvent[]; isConnected: boolean } {
  const { token, isAuthenticated } = useAuth();
  const [events, setEvents] = useState<RealtimeEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!isAuthenticated || !token) return;

    let cancelled = false;
    let socket: WebSocket | null = null;

    const connect = () => {
      if (cancelled) return;
      socket = new WebSocket(`${WS_BASE_URL}/ws?token=${token}`);

      socket.onopen = () => setIsConnected(true);

      socket.onmessage = (event: MessageEvent<string>) => {
        try {
          const parsed = JSON.parse(event.data) as RealtimeEvent;
          setEvents((prev) => [...prev.slice(-(MAX_EVENTS - 1)), parsed]);
        } catch {
          // Malformed message — ignore rather than crash the dashboard.
        }
      };

      socket.onclose = (event: CloseEvent) => {
        setIsConnected(false);
        // 1008 = the server refused the token (expired, or its user no
        // longer exists): same as an HTTP 401 in lib/api.ts — clear the
        // session and sign in again instead of retrying forever.
        if (event.code === 1008 && !cancelled) {
          cancelled = true;
          clearToken();
          window.location.href = '/login';
          return;
        }
        if (!cancelled) {
          reconnectTimerRef.current = setTimeout(connect, RECONNECT_DELAY_MS);
        }
      };

      socket.onerror = () => {
        socket?.close();
      };
    };

    connect();

    return () => {
      cancelled = true;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      socket?.close();
    };
  }, [token, isAuthenticated]);

  return { events, isConnected };
}
