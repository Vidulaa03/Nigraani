"use client";

import React, { useEffect, useState } from "react";
import {
  Activity,
  Globe,
  Radio,
  Server,
  Clock,
  AlertTriangle,
  Search,
} from "lucide-react";
import { AppLayout } from "@/components/layout/AppLayout";
import { KpiCard } from "@/components/cards/KpiCard";
import { TrafficTimelineChart } from "@/components/charts/TrafficTimelineChart";
import { EventsTable } from "@/components/tables/EventsTable";
import { api } from "@/lib/api";
import { useVisibilityInterval } from "@/lib/useVisibilityInterval";
import { SecurityEvent, TrafficData } from "@/lib/types";

export default function TrafficPage() {
  const [traffic, setTraffic] = useState<TrafficData | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  const loadData = async (query = "") => {
    try {
      const [trafRes, evRes] = await Promise.allSettled([
        api.getTraffic(),
        api.getEvents({ search: query, limit: 100 }),
      ]);

      if (trafRes.status === "fulfilled") setTraffic(trafRes.value);
      if (evRes.status === "fulfilled") setEvents(evRes.value.events);
    } catch {
      // handled
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);
  useVisibilityInterval(() => loadData(searchQuery), 30000);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData(searchQuery);
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    loadData(searchQuery);
  };

  const summary = traffic?.summary;

  return (
    <AppLayout
      title="API TRAFFIC TELEMETRY"
      subtitle="Comprehensive Endpoint Volume, Status Code Analytics & Latency Profiles"
      onRefresh={handleRefresh}
      isRefreshing={refreshing}
    >
      <div className="space-y-6">
        {/* KPI Row */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
          <KpiCard
            title="Total Requests"
            value={summary?.request_volume}
            subtext="Logged API events"
            icon={Activity}
            color="cyan"
          />
          <KpiCard
            title="Unique Clients"
            value={summary?.unique_ips}
            subtext="Distinct IP addresses"
            icon={Globe}
            color="purple"
          />
          <KpiCard
            title="Target Endpoints"
            value={summary?.unique_endpoints}
            subtext="Active route paths"
            icon={Server}
            color="cyan"
          />
          <KpiCard
            title="HTTP Methods"
            value={summary?.http_methods}
            subtext="GET, POST, etc."
            icon={Radio}
            color="green"
          />
          <KpiCard
            title="Error Rate"
            value={summary ? `${summary.error_rate_pct}%` : null}
            subtext="HTTP 4xx / 5xx responses"
            icon={AlertTriangle}
            color={summary && summary.error_rate_pct > 10 ? "red" : "amber"}
          />
          <KpiCard
            title="Avg Latency"
            value={summary ? `${summary.avg_latency_ms} ms` : null}
            subtext="Mean response duration"
            icon={Clock}
            color="green"
          />
        </div>

        {/* Traffic Timeline */}
        <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
          <div className="flex items-center justify-between mb-2">
            <div>
              <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f]">
                Request Volume & Failure Spikes
              </h3>
              <p className="text-[11px] text-[#716c60] font-sans mt-0.5">
                Timeline across 30-second epoch intervals
              </p>
            </div>
          </div>
          <TrafficTimelineChart data={traffic?.timeline || []} height={230} />
        </div>

        {/* 3-Column Distributions Row: Methods, Status Codes, Latencies */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Method Distribution */}
          <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
            <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f] mb-2">
              HTTP Methods
            </h3>
            <p className="text-[11px] text-[#716c60] font-sans mb-3">
              Distribution of request verbs
            </p>
            <div className="space-y-2">
              {(traffic?.methods || []).map((m) => (
                <div
                  key={m.method}
                  className="p-3 rounded-none bg-[#ffffff] border border-[#e5e0d5] flex items-center justify-between"
                >
                  <span className="font-sans text-xs font-bold text-amber-800">
                    {m.method}
                  </span>
                  <span className="font-sans text-xs font-bold text-[#27251f]">
                    {m.count.toLocaleString()} requests
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Status Code Distribution */}
          <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
            <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f] mb-2">
              Status Codes
            </h3>
            <p className="text-[11px] text-[#716c60] font-sans mb-3">
              Response codes recorded
            </p>
            <div className="space-y-2">
              {(traffic?.status_codes || []).map((s) => {
                const is2xx = s.status_code.startsWith("2");
                const is4xx = s.status_code.startsWith("4");

                return (
                  <div
                    key={s.status_code}
                    className="p-3 rounded-none bg-[#ffffff] border border-[#e5e0d5] flex items-center justify-between"
                  >
                    <span
                      className={`font-sans text-xs font-bold px-2 py-0.5 rounded-none ${
                        is2xx
                          ? "bg-emerald-500/10 text-emerald-700 border border-emerald-500/20"
                          : is4xx
                          ? "bg-amber-500/10 text-amber-800 border border-amber-500/20"
                          : "bg-red-500/10 text-red-700 border border-red-500/20"
                      }`}
                    >
                      HTTP {s.status_code}
                    </span>
                    <span className="font-sans text-xs font-bold text-[#27251f]">
                      {s.count.toLocaleString()}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Latency Histogram */}
          <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
            <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f] mb-2">
              Response Latencies
            </h3>
            <p className="text-[11px] text-[#716c60] font-sans mb-3">
              Duration performance distribution
            </p>
            <div className="space-y-2">
              {(traffic?.latency_distribution || []).map((l) => (
                <div
                  key={l.range}
                  className="p-3 rounded-none bg-[#ffffff] border border-[#e5e0d5] flex items-center justify-between"
                >
                  <span className="font-sans text-xs text-[#716c60]">
                    {l.range}
                  </span>
                  <span className="font-sans text-xs font-bold text-[#27251f]">
                    {l.count} requests
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Most Active Endpoints Table */}
        <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
          <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f] mb-3">
            Endpoint Traffic & Failure Breakdown
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-sans">
              <thead className="bg-[#ffffff] border-b border-[#e5e0d5] text-[#716c60] uppercase text-[11px]">
                <tr>
                  <th className="py-2.5 px-4">Endpoint</th>
                  <th className="py-2.5 px-4">Volume</th>
                  <th className="py-2.5 px-4">Error Rate</th>
                  <th className="py-2.5 px-4">Avg Latency</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#eeeae1] text-[#464238]">
                {(traffic?.endpoints || []).map((ep) => (
                  <tr key={ep.endpoint} className="hover:bg-[#ffffff]">
                    <td className="py-2.5 px-4 font-semibold text-[#27251f]">
                      {ep.endpoint}
                    </td>
                    <td className="py-2.5 px-4 text-amber-800 font-bold">
                      {ep.count.toLocaleString()}
                    </td>
                    <td className="py-2.5 px-4">
                      <span
                        className={
                          ep.error_rate > 20
                            ? "text-red-700 font-bold"
                            : ep.error_rate > 0
                            ? "text-amber-800 font-bold"
                            : "text-emerald-700"
                        }
                      >
                        {ep.error_rate}%
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-[#635d51]">
                      {ep.avg_latency} ms
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Raw Searchable Events Log */}
        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f]">
                Live HTTP Requests Feed
              </h3>
              <p className="text-[11px] text-[#716c60] font-sans">
                Search and inspect individual raw events recorded by security logging middleware
              </p>
            </div>

            <form onSubmit={handleSearchSubmit} className="flex items-center gap-2">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-[#716c60] absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Search IP, route, or ID..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-8 pr-3 py-1.5 rounded-none bg-[#ffffff] border border-[#e5e0d5] text-xs font-sans text-[#27251f] placeholder-[#716c60] focus:outline-none focus:border-amber-500/50 w-56"
                />
              </div>
              <button
                type="submit"
                className="px-3 py-1.5 rounded-none bg-[#ffffff] hover:bg-amber-500/20 text-amber-900 border border-[#e5e0d5] text-xs font-sans"
              >
                Filter
              </button>
            </form>
          </div>

          <EventsTable events={events} isLoading={loading} />
        </div>
      </div>
    </AppLayout>
  );
}
