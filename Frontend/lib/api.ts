/**
 * Centralized API client for NIGRAANI frontend.
 * Provides timeout control, base URL configuration, and graceful error handling.
 */

import {
  DashboardSummary,
  InvestigationTrail,
  MLBehaviorData,
  SecurityEventsResponse,
  SystemHealth,
  ThreatIntelligenceData,
  TrafficData,
} from "./types";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/+$/, "") || "http://localhost:8000";

export class ApiError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function fetchWithTimeout<T>(
  endpoint: string,
  options: RequestInit = {},
  timeoutMs = 8000
): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...options.headers,
      },
      // Avoid browser cache during live polling
      cache: "no-store",
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      let errorDetail = `HTTP ${res.status} ${res.statusText}`;
      try {
        const body = await res.json();
        if (body.detail) errorDetail = body.detail;
      } catch {
        // ignore json parse error
      }
      throw new ApiError(errorDetail, res.status);
    }

    return await res.json();
  } catch (err: any) {
    clearTimeout(timeoutId);
    if (err.name === "AbortError") {
      throw new ApiError(`Request timeout after ${timeoutMs}ms to ${url}`);
    }
    if (err instanceof ApiError) {
      throw err;
    }
    throw new ApiError(
      `Cannot connect to NIGRAANI backend at ${API_BASE_URL}. (${err.message})`
    );
  }
}

export const api = {
  getHealth: () => fetchWithTimeout<SystemHealth>("/api/dashboard/health"),

  getSummary: () => fetchWithTimeout<DashboardSummary>("/api/dashboard/summary"),

  getTraffic: () => fetchWithTimeout<TrafficData>("/api/dashboard/traffic"),

  getThreats: () =>
    fetchWithTimeout<ThreatIntelligenceData>("/api/dashboard/threats"),

  getML: () => fetchWithTimeout<MLBehaviorData>("/api/dashboard/ml"),

  getEvents: (params?: {
    search?: string;
    ip?: string;
    endpoint?: string;
    method?: string;
    statusCode?: number;
    limit?: number;
    offset?: number;
  }) => {
    const q = new URLSearchParams();
    if (params?.search) q.set("search", params.search);
    if (params?.ip) q.set("ip", params.ip);
    if (params?.endpoint) q.set("endpoint", params.endpoint);
    if (params?.method) q.set("method", params.method);
    if (params?.statusCode !== undefined)
      q.set("status_code", String(params.statusCode));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.offset) q.set("offset", String(params.offset));

    const qs = q.toString() ? `?${q.toString()}` : "";
    return fetchWithTimeout<SecurityEventsResponse>(
      `/api/dashboard/events${qs}`
    );
  },

  getInvestigation: (eventId: number | string) =>
    fetchWithTimeout<InvestigationTrail>(
      `/api/dashboard/investigate/${encodeURIComponent(eventId)}`
    ),
};
