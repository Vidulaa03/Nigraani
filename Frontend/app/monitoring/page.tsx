"use client";

import React, { useEffect, useState } from "react";
import {
  Server,
  Database,
  Brain,
  Activity,
  CheckCircle,
  AlertTriangle,
  Layers,
  LineChart,
} from "lucide-react";
import { AppLayout } from "@/components/layout/AppLayout";
import { api } from "@/lib/api";
import { SystemHealth } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";
import { useVisibilityInterval } from "@/lib/useVisibilityInterval";

export default function MonitoringPage() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  const loadHealth = async () => {
    try {
      const res = await api.getHealth();
      setHealth(res);
    } catch {
      // handled
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadHealth();
  }, []);
  useVisibilityInterval(loadHealth, 30000);

  const handleRefresh = () => {
    setRefreshing(true);
    loadHealth();
  };

  const isBackendOk = health?.backend?.status === "online";
  const isDbOk = health?.database?.status === "connected";
  const isMlOk = health?.ml_engine?.status === "healthy";
  const isAnalyzerOk = health?.analyzer?.status === "active";

  return (
    <AppLayout
      title="SYSTEM MONITORING & HEALTH"
      subtitle="Component Lifecycle Diagnostics, Database Integrity & Observability Stack"
      onRefresh={handleRefresh}
      isRefreshing={refreshing}
    >
      <div className="space-y-6">
        {/* System Health Status Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Backend Status */}
          <div className="p-5 rounded-none bg-[#ffffff] border border-[#e5e0d5] flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-sans uppercase tracking-wider text-[#716c60]">
                  FastAPI Backend
                </span>
                <Server className="w-4 h-4 text-amber-800" />
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={`w-2.5 h-2.5 rounded-none ${
                    isBackendOk
                      ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]"
                      : "bg-red-400"
                  }`}
                />
                <span className="font-sans text-xl font-bold text-[#27251f] uppercase">
                  {isBackendOk ? "Online" : "Offline"}
                </span>
              </div>
            </div>
            <div className="mt-4 pt-3 border-t border-[#e5e0d5] text-[11px] font-sans text-[#716c60]">
              <div>Engine: {health?.backend?.name || "NIGRAANI API"}</div>
              <div>Version: {health?.backend?.version || "1.0.0"}</div>
            </div>
          </div>

          {/* Database Status */}
          <div className="p-5 rounded-none bg-[#ffffff] border border-[#e5e0d5] flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-sans uppercase tracking-wider text-[#716c60]">
                  SQLite Telemetry DB
                </span>
                <Database className="w-4 h-4 text-purple-800" />
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={`w-2.5 h-2.5 rounded-none ${
                    isDbOk
                      ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]"
                      : "bg-red-400"
                  }`}
                />
                <span className="font-sans text-xl font-bold text-[#27251f] uppercase">
                  {isDbOk ? "Connected" : "Error"}
                </span>
              </div>
            </div>
            <div className="mt-4 pt-3 border-t border-[#e5e0d5] text-[11px] font-sans text-[#716c60]">
              <div>Database: {health?.database?.path || "demo.db"}</div>
              <div>Events: {health?.database?.counts?.security_events ?? "—"} rows</div>
            </div>
          </div>

          {/* ML Engine Status */}
          <div className="p-5 rounded-none bg-[#ffffff] border border-[#e5e0d5] flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-sans uppercase tracking-wider text-[#716c60]">
                  Isolation Forest ML
                </span>
                <Brain className="w-4 h-4 text-amber-800" />
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={`w-2.5 h-2.5 rounded-none ${
                    isMlOk
                      ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]"
                      : "bg-amber-400"
                  }`}
                />
                <span className="font-sans text-xl font-bold text-[#27251f] uppercase">
                  {isMlOk ? "Healthy" : "Unavailable"}
                </span>
              </div>
            </div>
            <div className="mt-4 pt-3 border-t border-[#e5e0d5] text-[11px] font-sans text-[#716c60]">
              <div>Model: {health?.ml_engine?.model || "Isolation Forest"}</div>
              <div>Features: 8 contract variables</div>
            </div>
          </div>

          {/* Analyzer Status */}
          <div className="p-5 rounded-none bg-[#ffffff] border border-[#e5e0d5] flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-sans uppercase tracking-wider text-[#716c60]">
                  Analyzer Engine
                </span>
                <Activity className="w-4 h-4 text-emerald-700" />
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={`w-2.5 h-2.5 rounded-none ${
                    isAnalyzerOk
                      ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]"
                      : "bg-amber-400"
                  }`}
                />
                <span className="font-sans text-xl font-bold text-[#27251f] uppercase">
                  {isAnalyzerOk ? "Active" : "Idle"}
                </span>
              </div>
            </div>
            <div className="mt-4 pt-3 border-t border-[#e5e0d5] text-[11px] font-sans text-[#716c60]">
              <div>Total Decisions: {health?.analyzer?.total_decisions ?? 0}</div>
              <div>Total Detections: {health?.analyzer?.total_detections ?? 0}</div>
            </div>
          </div>
        </div>

        {/* Database Rows & Pipeline Telemetry */}
        <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
          <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f] mb-3 flex items-center gap-2">
            <Layers className="w-4 h-4 text-amber-800" />
            Database Entity Inventory
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="p-3 rounded-none bg-[#ffffff] border border-[#e5e0d5]">
              <div className="text-[10px] font-sans text-[#716c60] uppercase">
                Security Events
              </div>
              <div className="font-sans text-lg font-bold text-amber-800 mt-1">
                {health?.database?.counts?.security_events?.toLocaleString() ?? "—"}
              </div>
            </div>

            <div className="p-3 rounded-none bg-[#ffffff] border border-[#e5e0d5]">
              <div className="text-[10px] font-sans text-[#716c60] uppercase">
                Detections
              </div>
              <div className="font-sans text-lg font-bold text-orange-700 mt-1">
                {health?.database?.counts?.detections?.toLocaleString() ?? "—"}
              </div>
            </div>

            <div className="p-3 rounded-none bg-[#ffffff] border border-[#e5e0d5]">
              <div className="text-[10px] font-sans text-[#716c60] uppercase">
                Risk Decisions
              </div>
              <div className="font-sans text-lg font-bold text-purple-800 mt-1">
                {health?.database?.counts?.decisions?.toLocaleString() ?? "—"}
              </div>
            </div>

            <div className="p-3 rounded-none bg-[#ffffff] border border-[#e5e0d5]">
              <div className="text-[10px] font-sans text-[#716c60] uppercase">
                Users Table
              </div>
              <div className="font-sans text-lg font-bold text-emerald-700 mt-1">
                {health?.database?.counts?.users ?? "—"}
              </div>
            </div>

            <div className="p-3 rounded-none bg-[#ffffff] border border-[#e5e0d5]">
              <div className="text-[10px] font-sans text-[#716c60] uppercase">
                Orders Table
              </div>
              <div className="font-sans text-lg font-bold text-[#27251f] mt-1">
                {health?.database?.counts?.orders ?? "—"}
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-[#e5e0d5] text-xs font-sans text-[#716c60] flex justify-between">
            <span>Last Logged Event Timestamp:</span>
            <span className="text-[#5d584d]">
              {formatDateTime(health?.database?.last_event_timestamp)}
            </span>
          </div>
        </div>

        {/* Future Observability Layer Section */}
        <div className="bg-[#ffffff] border border-dashed border-[#e5e0d5] rounded-none p-8 text-center">
          <div className="w-12 h-12 rounded-none bg-[#ffffff] border border-[#e5e0d5] flex items-center justify-center text-amber-800 mx-auto mb-3">
            <LineChart className="w-6 h-6" />
          </div>
          <div className="text-xs font-sans uppercase tracking-widest text-amber-800 font-bold mb-1">
            OBSERVABILITY
          </div>
          <h4 className="text-sm font-sans text-[#27251f] font-medium mb-1">
            Grafana monitoring will be connected here.
          </h4>
          <p className="text-xs text-[#716c60] max-w-md mx-auto font-sans">
            This module is reserved for the enterprise Grafana dashboard layer. Operational telemetry and Prometheus scrape endpoints will connect directly to this monitoring pane.
          </p>
        </div>
      </div>
    </AppLayout>
  );
}
