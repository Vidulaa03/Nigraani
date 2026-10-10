"use client";

import React, { useEffect, useState } from "react";
import {
  Activity,
  Brain,
  ShieldAlert,
  ShieldCheck,
  Ban,
  Radio,
  Sliders,
} from "lucide-react";
import { AppLayout } from "@/components/layout/AppLayout";
import { KpiCard } from "@/components/cards/KpiCard";
import { ThreatPostureCard } from "@/components/cards/ThreatPostureCard";
import { TrafficTimelineChart } from "@/components/charts/TrafficTimelineChart";
import { SeverityBreakdownChart } from "@/components/charts/SeverityBreakdownChart";
import { DecisionDistributionChart } from "@/components/charts/DecisionDistributionChart";
import { MLAnomalyTimelineChart } from "@/components/charts/MLAnomalyTimelineChart";
import { ActiveThreatsTable } from "@/components/tables/ActiveThreatsTable";
import { api } from "@/lib/api";
import { useVisibilityInterval } from "@/lib/useVisibilityInterval";
import {
  DashboardSummary,
  MLBehaviorData,
  TrafficData,
} from "@/lib/types";

export default function CommandCenterPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [traffic, setTraffic] = useState<TrafficData | null>(null);
  const [ml, setMl] = useState<MLBehaviorData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  const loadData = async () => {
    try {
      const [sumData, trafData, mlData] = await Promise.allSettled([
        api.getSummary(),
        api.getTraffic(),
        api.getML(),
      ]);

      if (sumData.status === "fulfilled") setSummary(sumData.value);
      if (trafData.status === "fulfilled") setTraffic(trafData.value);
      if (mlData.status === "fulfilled") setMl(mlData.value);
    } catch {
      // Individual widgets handle null states gracefully
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);
  useVisibilityInterval(loadData, 30000);

  const handleManualRefresh = () => {
    setRefreshing(true);
    loadData();
  };

  const kpis = summary?.kpis;
  const posture = summary?.threat_posture;

  return (
    <AppLayout
      title="COMMAND CENTER"
      subtitle="Autonomous API Abuse Detection & Dynamic Risk Orchestration"
      onRefresh={handleManualRefresh}
      isRefreshing={refreshing}
    >
      <div className="space-y-6">
        {/* Top 6 KPI Row */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
          <KpiCard
            title="API Requests"
            value={kpis?.api_requests}
            subtext="Total logged events"
            icon={Activity}
            color="cyan"
          />
          <KpiCard
            title="ML Windows"
            value={kpis?.ml_windows}
            subtext="30s epoch windows"
            icon={Brain}
            color="purple"
          />
          <KpiCard
            title="ML Anomalies"
            value={kpis?.ml_anomalies}
            subtext="Isolation Forest flags"
            icon={Radio}
            color="amber"
          />
          <KpiCard
            title="Detections"
            value={kpis?.security_detections}
            subtext="Rule/OWASP matches"
            icon={ShieldAlert}
            color="orange"
          />
          <KpiCard
            title="Critical Threats"
            value={
              kpis
                ? `${kpis.high_threats} High / ${kpis.critical_threats} Crit`
                : null
            }
            subtext="Severity ≥ 60"
            icon={ShieldCheck}
            color="red"
          />
          <KpiCard
            title="BLOCK Recommendations"
            value={kpis?.blocked_requests}
            subtext="Latest recommendation per IP"
            icon={Ban}
            color="red"
          />
        </div>

        {/* Row 2: Live Traffic Timeline & Threat Posture Card */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 bg-[#FFFFFF] border border-[#D5EAE5] rounded-sm p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#02353C]">
                  Live API Traffic Timeline
                </h3>
                <p className="text-[11px] text-[#486966] font-sans mt-0.5">
                  Request volume & error spikes across 30-second epoch intervals
                </p>
              </div>
              <div className="flex items-center gap-3 text-[11px] font-sans text-[#486966]">
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-[#2EAF7D]" /> Requests
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-[#DC2626]" /> Errors
                </span>
              </div>
            </div>

            <TrafficTimelineChart
              data={traffic?.timeline || []}
              height={220}
            />
          </div>

          <div>
            <ThreatPostureCard posture={posture} className="h-full" />
          </div>
        </div>

        {/* Row 3: ML Anomaly Timeline, Severity Mix, Decision Distribution */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* ML Anomaly Timeline */}
          <div className="bg-[#FFFFFF] border border-[#D5EAE5] rounded-sm p-5">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#02353C]">
                ML Anomaly Trajectory
              </h3>
              <span className="text-[10px] font-sans px-2 py-0.5 rounded-sm bg-[#3FD0C9]/15 text-[#02353C] border border-[#3FD0C9]/40 font-semibold">
                Isolation Forest
              </span>
            </div>
            <p className="text-[11px] text-[#486966] font-sans mb-3">
              Per-window ML scores with 50.0 threshold marker
            </p>
            <MLAnomalyTimelineChart
              timeline={ml?.timeline || []}
              height={220}
            />
          </div>

          {/* Severity Distribution */}
          <div className="bg-[#FFFFFF] border border-[#D5EAE5] rounded-sm p-5">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#02353C]">
                Detection Severity Mix
              </h3>
              <span className="text-[10px] font-sans px-2 py-0.5 rounded-sm bg-[#2EAF7D]/15 text-[#02353C] border border-[#2EAF7D]/40 font-semibold">
                Rule Engine
              </span>
            </div>
            <p className="text-[11px] text-[#486966] font-sans mb-3">
              Categorization by detection severity cutoff
            </p>
            <SeverityBreakdownChart
              distribution={
                summary?.severity_distribution || {
                  CRITICAL: 0,
                  HIGH: 0,
                  MEDIUM: 0,
                  LOW: 0,
                }
              }
              height={220}
            />
          </div>

          {/* Decision Distribution */}
          <div className="bg-[#FFFFFF] border border-[#D5EAE5] rounded-sm p-5">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#02353C]">
                Latest Risk Recommendations
              </h3>
              <span className="text-[10px] font-sans px-2 py-0.5 rounded-sm bg-[#2EAF7D]/15 text-[#02353C] border border-[#2EAF7D]/40 font-semibold">
                Risk Engine
              </span>
            </div>
            <p className="text-[11px] text-[#486966] font-sans mb-3">
              Latest per-IP recommendation: ALLOW, MONITOR, THROTTLE, or BLOCK
            </p>
            <DecisionDistributionChart
              distribution={
                summary?.decision_distribution || {
                  ALLOW: 0,
                  MONITOR: 0,
                  THROTTLE: 0,
                  BLOCK: 0,
                }
              }
              height={220}
            />
          </div>
        </div>

        {/* Row 4: Recent Security Activity Table */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#02353C]">
                Active Security Threat Feed
              </h3>
              <p className="text-[11px] text-[#486966] font-sans">
                Persisted detections correlated with ML scores and risk decisions
              </p>
            </div>
            <span className="text-xs font-sans text-[#486966]">
              Showing {summary?.recent_detections?.length || 0} latest detections
            </span>
          </div>

          <ActiveThreatsTable
            detections={summary?.recent_detections || []}
            limit={8}
            showAllLink={true}
          />
        </div>
      </div>
    </AppLayout>
  );
}
