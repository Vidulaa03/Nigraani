"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Gauge,
  Activity,
  Layers,
  Filter,
  AlertTriangle,
  Info,
  Clock,
  ExternalLink,
  ShieldAlert,
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import { AppLayout } from "@/components/layout/AppLayout";
import { KpiCard } from "@/components/cards/KpiCard";
import { api } from "@/lib/api";
import { useVisibilityInterval } from "@/lib/useVisibilityInterval";
import { SecurityDetection, ThreatIntelligenceData, TrafficData } from "@/lib/types";

export default function MultiDimensionalRateAnalysisPage() {
  const [traffic, setTraffic] = useState<TrafficData | null>(null);
  const [threats, setThreats] = useState<ThreatIntelligenceData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  // Filters
  const [selectedDimension, setSelectedDimension] = useState<
    "ip" | "endpoint" | "user" | "api_key" | "tenant"
  >("ip");
  const [statusFilter, setStatusFilter] = useState<"ALL" | "BURSTS_ONLY">("ALL");

  const loadData = async () => {
    try {
      const [trafRes, threatRes] = await Promise.allSettled([
        api.getTraffic(),
        api.getThreats(),
      ]);
      if (trafRes.status === "fulfilled") setTraffic(trafRes.value);
      if (threatRes.status === "fulfilled") setThreats(threatRes.value);
    } catch {
      // Handled
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);
  useVisibilityInterval(loadData, 15000);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
  };

  // Extract real rate detections from threats
  const allDetections = threats?.detections || [];
  const rateDetections = allDetections.filter(
    (d) => d.detector === "rate_detector" || d.attack_type.toLowerCase().includes("rate")
  );

  const displayedDetections = statusFilter === "BURSTS_ONLY" ? rateDetections : allDetections;

  // Chart data from real traffic timeline
  const timelineData = (traffic?.timeline || []).map((bin) => ({
    time: bin.timestamp ? new Date(bin.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "",
    requests: bin.requests,
    errors: bin.errors,
    latency: bin.avg_latency,
  }));

  // Dimension breakdown from real data
  const isPendingDimension = selectedDimension === "api_key" || selectedDimension === "tenant";

  let dimensionBreakdown: { key: string; count: number; suspicious: boolean }[] = [];
  if (selectedDimension === "ip") {
    const ipCounts: Record<string, number> = {};
    (threats?.top_source_ips || []).forEach((item) => {
      ipCounts[item.ip] = item.count;
    });
    dimensionBreakdown = Object.entries(ipCounts).map(([key, count]) => ({
      key,
      count,
      suspicious: rateDetections.some((r) => r.ip === key),
    }));
  } else if (selectedDimension === "endpoint") {
    const epCounts: Record<string, number> = {};
    (traffic?.endpoints || []).forEach((item) => {
      epCounts[item.endpoint] = item.count;
    });
    dimensionBreakdown = Object.entries(epCounts).map(([key, count]) => ({
      key,
      count,
      suspicious: rateDetections.some((r) => r.linked_endpoint === key),
    }));
  } else if (selectedDimension === "user") {
    // User dimension from detections where user_id exists
    const userCounts: Record<string, number> = {};
    allDetections.forEach((d) => {
      if (d.user_id !== null && d.user_id !== undefined) {
        const ukey = `User #${d.user_id}`;
        userCounts[ukey] = (userCounts[ukey] || 0) + 1;
      }
    });
    dimensionBreakdown = Object.entries(userCounts).map(([key, count]) => ({
      key,
      count,
      suspicious: true,
    }));
  }

  return (
    <AppLayout
      title="MULTI-DIMENSIONAL RATE ANALYSIS"
      subtitle="Rolling-Window Request Frequency, Threshold Violation Diagnostics & Dimension Correlation"
      onRefresh={handleRefresh}
      isRefreshing={refreshing}
    >
      <div className="space-y-6">
        {/* KPI Row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
          <KpiCard
            title="Total Request Volume"
            value={traffic?.summary?.request_volume}
            subtext="Across monitored endpoints"
            icon={Activity}
            color="cyan"
          />
          <KpiCard
            title="Rate Spike Incidents"
            value={rateDetections.length}
            subtext="Threshold: >=30 reqs / 10s"
            icon={Gauge}
            color="red"
          />
          <KpiCard
            title="Unique Origin IPs"
            value={traffic?.summary?.unique_ips}
            subtext="Tracked source addresses"
            icon={Layers}
            color="purple"
          />
          <KpiCard
            title="Error Rate"
            value={traffic?.summary?.error_rate_pct !== undefined ? `${traffic.summary.error_rate_pct}%` : null}
            subtext="HTTP 4xx / 5xx responses"
            icon={AlertTriangle}
            color="amber"
          />
        </div>

        {/* Observation Windows Chart */}
        <div className="bg-white border border-[#D5EAE5] rounded-[4px] p-5 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 mb-4 border-b border-[#D5EAE5] gap-2">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#02353C]">
                Request Activity Across Observation Windows (Time-Series)
              </h3>
              <p className="text-[11px] text-[#486966] mt-0.5">
                Rolling telemetry bins tracking incoming volume and latency trends
              </p>
            </div>
            <div className="flex items-center gap-3 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-[#02353C]">
                <span className="w-2.5 h-2.5 bg-[#2EAF7D] rounded-[2px]" /> Requests
              </span>
              <span className="flex items-center gap-1.5 text-[#02353C]">
                <span className="w-2.5 h-2.5 bg-[#3FD0C9] rounded-[2px]" /> Errors
              </span>
            </div>
          </div>

          <div className="h-64 w-full">
            {timelineData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-[#486966]">
                No traffic observations recorded yet. Run a traffic simulation to populate.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#D5EAE5" vertical={false} />
                  <XAxis dataKey="time" stroke="#486966" fontSize={10} tickLine={false} />
                  <YAxis stroke="#486966" fontSize={10} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#FFFFFF",
                      borderColor: "#D5EAE5",
                      fontSize: "11px",
                      borderRadius: "2px",
                      color: "#02353C",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="requests"
                    stroke="#2EAF7D"
                    fill="#2EAF7D"
                    fillOpacity={0.2}
                    name="Requests"
                  />
                  <Area
                    type="monotone"
                    dataKey="errors"
                    stroke="#3FD0C9"
                    fill="#3FD0C9"
                    fillOpacity={0.3}
                    name="Errors (>=400)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Dimension Breakdown & Filter Toolbar */}
        <div className="bg-white border border-[#D5EAE5] rounded-[4px] p-5 shadow-sm">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-[#D5EAE5]">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#02353C]">
                Suspicious Traffic Breakdown by Dimension
              </h3>
              <p className="text-[11px] text-[#486966] mt-0.5">
                Evaluate request concentration across IP, Endpoint, User, API Key, and Tenant
              </p>
            </div>

            {/* Dimension Selection */}
            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              <span className="text-xs font-semibold text-[#486966] mr-1">Dimension:</span>
              <button
                onClick={() => setSelectedDimension("ip")}
                className={`px-2.5 py-1 text-xs font-medium rounded-[2px] transition-colors ${
                  selectedDimension === "ip"
                    ? "bg-[#02353C] text-white"
                    : "bg-[#F2FBF9] text-[#486966] hover:text-[#02353C] border border-[#D5EAE5]"
                }`}
              >
                Client IP
              </button>
              <button
                onClick={() => setSelectedDimension("endpoint")}
                className={`px-2.5 py-1 text-xs font-medium rounded-[2px] transition-colors ${
                  selectedDimension === "endpoint"
                    ? "bg-[#02353C] text-white"
                    : "bg-[#F2FBF9] text-[#486966] hover:text-[#02353C] border border-[#D5EAE5]"
                }`}
              >
                Endpoint
              </button>
              <button
                onClick={() => setSelectedDimension("user")}
                className={`px-2.5 py-1 text-xs font-medium rounded-[2px] transition-colors ${
                  selectedDimension === "user"
                    ? "bg-[#02353C] text-white"
                    : "bg-[#F2FBF9] text-[#486966] hover:text-[#02353C] border border-[#D5EAE5]"
                }`}
              >
                User ID
              </button>
              <button
                onClick={() => setSelectedDimension("api_key")}
                className={`px-2.5 py-1 text-xs font-medium rounded-[2px] transition-colors ${
                  selectedDimension === "api_key"
                    ? "bg-[#02353C] text-white"
                    : "bg-[#F2FBF9] text-[#486966] hover:text-[#02353C] border border-[#D5EAE5]"
                }`}
              >
                API Key (Pending)
              </button>
              <button
                onClick={() => setSelectedDimension("tenant")}
                className={`px-2.5 py-1 text-xs font-medium rounded-[2px] transition-colors ${
                  selectedDimension === "tenant"
                    ? "bg-[#02353C] text-white"
                    : "bg-[#F2FBF9] text-[#486966] hover:text-[#02353C] border border-[#D5EAE5]"
                }`}
              >
                Tenant ID (Pending)
              </button>
            </div>
          </div>

          {/* Pending Integration Banner for API Key / Tenant */}
          {isPendingDimension ? (
            <div className="p-8 my-4 text-center bg-[#F2FBF9] border border-dashed border-[#D5EAE5] rounded-[2px]">
              <Info className="w-6 h-6 text-[#2EAF7D] mx-auto mb-2" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-[#02353C]">
                Data Integration Pending
              </h4>
              <p className="text-xs text-[#486966] mt-1 max-w-md mx-auto">
                The current backend logging schema tracks HTTP endpoints, client IP addresses, and user IDs. The{" "}
                <strong>{selectedDimension === "api_key" ? "API Key" : "Tenant ID"}</strong> dimension is not yet emitted by the backend pipeline.
              </p>
              <span className="inline-block mt-3 px-2 py-0.5 text-[10px] font-mono text-[#02353C] bg-white border border-[#D5EAE5] rounded-[2px]">
                Active dimensions: Client IP · Endpoint · User ID
              </span>
            </div>
          ) : dimensionBreakdown.length === 0 ? (
            <div className="py-8 text-center text-xs text-[#486966]">
              No observations recorded for the selected dimension.
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 mt-4">
              {dimensionBreakdown.map((item) => (
                <div
                  key={item.key}
                  className={`p-3 border rounded-[2px] flex items-center justify-between ${
                    item.suspicious
                      ? "bg-[#F8FEFD] border-[#2EAF7D]/60"
                      : "bg-[#F2FBF9] border-[#D5EAE5]"
                  }`}
                >
                  <div className="min-w-0">
                    <div className="text-xs font-mono font-semibold text-[#02353C] truncate">
                      {item.key}
                    </div>
                    <div className="text-[10px] text-[#486966] mt-0.5">
                      {item.suspicious ? "Rate spike flagged" : "Normal traffic"}
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-sm font-bold font-mono text-[#02353C]">
                      {item.count}
                    </span>
                    <span className="text-[10px] text-[#486966] block">events</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Rate Spike Detections & Threshold Log */}
        <div className="bg-white border border-[#D5EAE5] rounded-[4px] overflow-hidden shadow-sm">
          <div className="p-4 border-b border-[#D5EAE5] bg-[#F2FBF9] flex items-center justify-between">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#02353C]">
                Observed Rate Violations & Pattern Diagnostics
              </h3>
              <p className="text-[11px] text-[#486966] mt-0.5">
                Threshold: &ge;30 requests within a rolling 10-second observation window
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setStatusFilter("ALL")}
                className={`px-2 py-1 text-[11px] font-medium rounded-[2px] ${
                  statusFilter === "ALL"
                    ? "bg-[#02353C] text-white"
                    : "bg-white text-[#486966] border border-[#D5EAE5]"
                }`}
              >
                All Detections ({allDetections.length})
              </button>
              <button
                onClick={() => setStatusFilter("BURSTS_ONLY")}
                className={`px-2 py-1 text-[11px] font-medium rounded-[2px] ${
                  statusFilter === "BURSTS_ONLY"
                    ? "bg-[#02353C] text-white"
                    : "bg-white text-[#486966] border border-[#D5EAE5]"
                }`}
              >
                Rate Bursts Only ({rateDetections.length})
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#D5EAE5] bg-[#F8FEFD] text-[11px] font-semibold text-[#486966] uppercase tracking-wider">
                  <th className="py-2.5 px-4">Pattern / Detector</th>
                  <th className="py-2.5 px-4">Client IP</th>
                  <th className="py-2.5 px-4">Time Window</th>
                  <th className="py-2.5 px-4">Trigger Threshold</th>
                  <th className="py-2.5 px-4">Observed Evidence</th>
                  <th className="py-2.5 px-4">Severity</th>
                  <th className="py-2.5 px-4 text-right">Investigation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#D5EAE5]">
                {displayedDetections.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center">
                      <Gauge className="w-7 h-7 text-[#2EAF7D]/50 mx-auto mb-2" />
                      <p className="text-xs font-semibold text-[#02353C]">No rate violations observed</p>
                      <p className="text-[11px] text-[#486966] mt-0.5">
                        Run the burst traffic generator (<code>python -m simulation.attacks.rate_spike</code>) to demonstrate the 30-request rule.
                      </p>
                    </td>
                  </tr>
                ) : (
                  displayedDetections.map((det) => (
                    <tr key={det.detection_id} className="hover:bg-[#F2FBF9] transition-colors">
                      <td className="py-3 px-4 font-semibold text-[#02353C]">
                        {det.attack_type}
                        <div className="text-[10px] text-[#486966] font-mono font-normal">
                          {det.detector}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-[#02353C]">
                        {det.ip}
                      </td>
                      <td className="py-3 px-4 text-[#486966]">
                        {det.detector === "rate_detector" ? "10s rolling window" : "30s sliding window"}
                      </td>
                      <td className="py-3 px-4 text-[#486966]">
                        {det.detector === "rate_detector" ? ">=30 requests / 10s" : "Rule threshold"}
                      </td>
                      <td className="py-3 px-4 text-[#486966] max-w-xs truncate" title={det.evidence}>
                        {det.evidence}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex px-1.5 py-0.5 text-[10px] font-bold font-mono rounded-[2px] ${
                          det.severity >= 80
                            ? "bg-red-50 text-red-800 border border-red-200"
                            : det.severity >= 60
                            ? "bg-amber-50 text-amber-800 border border-amber-200"
                            : "bg-emerald-50 text-emerald-800 border border-emerald-200"
                        }`}>
                          {det.severity_band} ({det.severity})
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <Link
                          href="/threats"
                          className="inline-flex items-center gap-1 text-[11px] font-semibold text-[#2EAF7D] hover:text-[#02353C] transition-colors"
                        >
                          <span>Trace</span>
                          <ExternalLink className="w-3 h-3" />
                        </Link>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
