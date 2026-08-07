/**
 * SafeSOC — API Client
 * A single axios instance shared by every page: injects the stored
 * JWT (auth-storage.ts) on every request, and clears it + bounces to
 * /login on a 401 (expired/invalid token), so no page needs its own
 * auth-failure handling.
 */

import axios from 'axios';
import { clearToken, getToken } from './auth-storage';

export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_BASE_URL,
});

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (axios.isAxiosError(error) && error.response?.status === 401 && window.location.pathname !== '/login') {
      clearToken();
      window.location.href = '/login';
    }
    return Promise.reject(error);
  },
);
