"use client";

import React, { useEffect, useState } from "react";
import {
  ShieldAlert,
  Flame,
  Globe,
  Target,
  Filter,
} from "lucide-react";
import { AppLayout } from "@/components/layout/AppLayout";
import { KpiCard } from "@/components/cards/KpiCard";
import { SeverityBreakdownChart } from "@/components/charts/SeverityBreakdownChart";
import { ActiveThreatsTable } from "@/components/tables/ActiveThreatsTable";
import { api } from "@/lib/api";
import { useVisibilityInterval } from "@/lib/useVisibilityInterval";
import { ThreatIntelligenceData } from "@/lib/types";

export default function ThreatIntelligencePage() {
  const [data, setData] = useState<ThreatIntelligenceData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [selectedType, setSelectedType] = useState<string>("ALL");

  const loadData = async () => {
    try {
      const res = await api.getThreats();
      setData(res);
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
  useVisibilityInterval(loadData, 30000);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
  };

  const summary = data?.summary;

  // Filter detections by attack type if selected
  const filteredDetections = (data?.detections || []).filter((d) => {
    if (selectedType === "ALL") return true;
    return d.attack_type === selectedType;
  });

  return (
    <AppLayout
      title="THREAT INTELLIGENCE"
      subtitle="API Exploits, Attack Surface Targeting & OWASP Risk Categorization"
      onRefresh={handleRefresh}
      isRefreshing={refreshing}
    >
      <div className="space-y-6">
        {/* Top KPI row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <KpiCard
            title="Total Detections"
            value={summary?.total_detections}
            subtext="Persisted rule detections"
            icon={ShieldAlert}
            color="orange"
          />
          <KpiCard
            title="Unique Attack Types"
            value={summary?.unique_attack_types}
            subtext="BOLA, Brute Force, Rate Spike, Enum"
            icon={Flame}
            color="red"
          />
          <KpiCard
            title="Threat Origin IPs"
            value={summary?.unique_source_ips}
            subtext="Distinct attacker addresses"
            icon={Globe}
            color="cyan"
          />
          <KpiCard
            title="Peak Severity"
            value={summary?.highest_severity ? `${summary.highest_severity} / 100` : null}
            subtext="Highest rule severity recorded"
            icon={Target}
            color="red"
          />
        </div>

        {/* Intelligence Charts Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Attack Types Breakdown */}
          <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f]">
                Attack Type Breakdown
              </h3>
              <span className="text-[10px] font-sans px-2 py-0.5 rounded-none bg-amber-500/10 text-amber-800 border border-amber-500/30">
                OWASP API Top 10
              </span>
            </div>
            <p className="text-[11px] text-[#716c60] font-sans mb-4">
              Detections by specific exploit category
            </p>

            <div className="space-y-3">
              {(data?.attack_types || []).map((item) => {
                const total = summary?.total_detections || 1;
                const pct = Math.round((item.count / total) * 100);

                return (
                  <div
                    key={item.attack_type}
                    role="button"
                    tabIndex={0}
                    aria-pressed={selectedType === item.attack_type}
                    onClick={() =>
                      setSelectedType(
                        selectedType === item.attack_type
                          ? "ALL"
                          : item.attack_type
                      )
                    }
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setSelectedType(selectedType === item.attack_type ? "ALL" : item.attack_type);
                      }
                    }}
                    className={`p-3 rounded-none border transition-all cursor-pointer ${
                      selectedType === item.attack_type
                        ? "bg-[#ffffff] border-amber-500/50"
                        : "bg-[#ffffff] border-[#e5e0d5] hover:border-amber-500/30"
                    }`}
                  >
                    <div className="flex justify-between items-center text-xs font-sans mb-1.5">
                      <span className="font-semibold text-[#27251f]">
                        {item.attack_type}
                      </span>
                      <span className="text-amber-800 font-bold">
                        {item.count}{" "}
                        <span className="text-[#716c60] text-[10px]">
                          ({pct}%)
                        </span>
                      </span>
                    </div>
                    <div className="w-full bg-[#ffffff] rounded-none h-1.5 overflow-hidden">
                      <div
                        className="bg-amber-400 h-1.5 rounded-none"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Severity Distribution */}
          <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f]">
                Severity Distribution
              </h3>
              <span className="text-[10px] font-sans px-2 py-0.5 rounded-none bg-orange-500/10 text-orange-700 border border-orange-500/30">
                Risk Rating
              </span>
            </div>
            <p className="text-[11px] text-[#716c60] font-sans mb-4">
              Relative proportion of threat severities
            </p>

            <SeverityBreakdownChart
              distribution={{
                CRITICAL:
                  data?.severities.find((s) => s.band === "CRITICAL")?.count || 0,
                HIGH:
                  data?.severities.find((s) => s.band === "HIGH")?.count || 0,
                MEDIUM:
                  data?.severities.find((s) => s.band === "MEDIUM")?.count || 0,
                LOW:
                  data?.severities.find((s) => s.band === "LOW")?.count || 0,
              }}
              height={230}
            />
          </div>

          {/* Most Active Threat Source IPs */}
          <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f]">
                Top Attacking IPs
              </h3>
              <span className="text-[10px] font-sans px-2 py-0.5 rounded-none bg-red-500/10 text-red-700 border border-red-500/30">
                Perpetrators
              </span>
            </div>
            <p className="text-[11px] text-[#716c60] font-sans mb-4">
              Source addresses generating the highest detection count
            </p>

            <div className="space-y-2">
              {(data?.top_source_ips || []).slice(0, 6).map((ipItem) => (
                <div
                  key={ipItem.ip}
                  className="p-2.5 rounded-none bg-[#ffffff] border border-[#e5e0d5] flex items-center justify-between text-xs font-sans"
                >
                  <div>
                    <div className="font-semibold text-amber-800">{ipItem.ip}</div>
                    <div className="text-[10px] text-[#716c60] mt-0.5">
                      Severity: {ipItem.highest_severity} | Action:{" "}
                      <span className="text-red-700 font-bold">
                        {ipItem.action}
                      </span>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded-none bg-[#ffffff] text-[#27251f] font-bold text-xs border border-[#e5e0d5]">
                    {ipItem.count} hits
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Most Targeted Endpoints */}
        <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f]">
              Most Targeted Endpoints
            </h3>
            <span className="text-[10px] font-sans text-[#716c60]">
              Linked from detection telemetry
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 mt-4">
            {(data?.top_endpoints || []).slice(0, 8).map((ep) => (
              <div
                key={ep.endpoint}
                className="p-3 rounded-none bg-[#ffffff] border border-[#e5e0d5] flex items-center justify-between"
              >
                <div className="text-xs font-sans text-[#27251f] truncate max-w-[200px]" title={ep.endpoint}>
                  {ep.endpoint}
                </div>
                <span className="text-xs font-sans px-2 py-0.5 rounded-none bg-amber-500/10 text-amber-800 border border-amber-500/20 font-bold">
                  {ep.count}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Detections Records Table */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f]">
                Detailed Security Detections Register
              </h3>
              <p className="text-[11px] text-[#716c60] font-sans">
                {selectedType === "ALL"
                  ? `Showing all ${data?.detections.length || 0} detections`
                  : `Filtered by ${selectedType} (${filteredDetections.length} detections)`}
              </p>
            </div>

            {selectedType !== "ALL" && (
              <button
                onClick={() => setSelectedType("ALL")}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-none bg-[#ffffff] text-amber-800 border border-[#e5e0d5] text-xs font-sans hover:bg-[#ffffff]"
              >
                <Filter className="w-3 h-3" />
                Clear filter ({selectedType})
              </button>
            )}
          </div>

          <ActiveThreatsTable detections={filteredDetections} />
        </div>
      </div>
    </AppLayout>
  );
}
