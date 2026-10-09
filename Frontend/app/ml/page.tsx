"use client";

import React, { useEffect, useState } from "react";
import {
  Brain,
  Cpu,
  AlertTriangle,
  CheckCircle,
  Sliders,
  TrendingUp,
} from "lucide-react";
import { AppLayout } from "@/components/layout/AppLayout";
import { KpiCard } from "@/components/cards/KpiCard";
import { MLAnomalyTimelineChart } from "@/components/charts/MLAnomalyTimelineChart";
import { ScoreDistributionChart } from "@/components/charts/ScoreDistributionChart";
import { FeatureImportanceChart } from "@/components/charts/FeatureImportanceChart";
import { MLWindowsTable } from "@/components/tables/MLWindowsTable";
import { api } from "@/lib/api";
import { useVisibilityInterval } from "@/lib/useVisibilityInterval";
import { MLBehaviorData, MLWindow } from "@/lib/types";

export default function MLBehaviorPage() {
  const [data, setData] = useState<MLBehaviorData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [selectedWindow, setSelectedWindow] = useState<MLWindow | null>(null);

  const loadData = async () => {
    try {
      const res = await api.getML();
      setData(res);
      if (res.windows && res.windows.length > 0 && !selectedWindow) {
        setSelectedWindow(res.windows[0]);
      }
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
  const normalVsAnomaly = data?.normal_vs_anomaly;

  return (
    <AppLayout
      title="ML BEHAVIOR CENTER"
      subtitle="Isolation Forest High-Dimensional Anomaly Detection & Behavioral Baselines"
      onRefresh={handleRefresh}
      isRefreshing={refreshing}
    >
      <div className="space-y-6">
        {/* Top KPI Row */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <KpiCard
            title="Total ML Windows"
            value={summary?.total_windows}
            subtext="30s epoch windows (≥3 reqs)"
            icon={Brain}
            color="purple"
          />
          <KpiCard
            title="Anomaly Count"
            value={summary?.anomaly_count}
            subtext="Raw IF score < 0 (Score > 50)"
            icon={AlertTriangle}
            color="red"
          />
          <KpiCard
            title="Anomaly Rate"
            value={summary ? `${summary.anomaly_rate_pct}%` : null}
            subtext="Percentage of windows flagged"
            icon={TrendingUp}
            color="amber"
          />
          <KpiCard
            title="Peak Anomaly Score"
            value={summary ? `${summary.max_score} / 100` : null}
            subtext="Worst behavioral deviation"
            icon={Cpu}
            color="red"
          />
          <KpiCard
            title="Mean Anomaly Score"
            value={summary ? `${summary.avg_score} / 100` : null}
            subtext="Average baseline score"
            icon={Sliders}
            color="cyan"
          />
        </div>

        {/* Explainability Banner for Judges */}
        <div className="bg-[#ffffff] border border-purple-500/30 rounded-none p-5 shadow-[0_0_25px_rgba(168,85,247,0.06)]">
          <div className="flex items-start gap-4">
            <div className="w-10 h-10 rounded-none bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-800 shrink-0">
              <Brain className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-sans font-bold text-[#27251f] uppercase tracking-wider">
                How NIGRAANI Uses Unsupervised Machine Learning
              </h3>
              <p className="text-xs text-[#716c60] font-sans mt-1 leading-relaxed">
                Rather than relying solely on static signature rules, NIGRAANI groups API traffic into{" "}
                <span className="text-purple-800 font-sans">30-second sliding windows</span> per source IP and extracts{" "}
                <span className="text-purple-800 font-sans">8 behavioral features</span>. An{" "}
                <span className="text-[#27251f] font-sans font-semibold">Isolation Forest</span> model computes the degree of isolation in high-dimensional feature space. Windows with raw score &lt; 0 are flagged as anomalous (mapped to an ML score &gt; 50). This score is fused at a 60% weight with rule detections into the final Risk Engine.
              </p>
            </div>
          </div>
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Anomaly Timeline */}
          <div className="lg:col-span-2 bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
            <div className="flex items-center justify-between mb-2">
              <div>
                <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f]">
                  Anomaly Score Trajectory
                </h3>
                <p className="text-[11px] text-[#716c60] font-sans mt-0.5">
                  Timeline of scores across chronological traffic windows
                </p>
              </div>
              <span className="text-[10px] font-sans px-2 py-0.5 rounded-none bg-purple-500/10 text-purple-800 border border-purple-500/30 font-bold">
                Threshold: 50.0
              </span>
            </div>

            <MLAnomalyTimelineChart
              timeline={data?.timeline || []}
              height={250}
            />
          </div>

          {/* Normal vs Anomaly & Score Distribution */}
          <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f]">
                  Score Distribution
                </h3>
                <span className="text-[10px] font-sans text-[#716c60]">
                  Bins (0–100)
                </span>
              </div>
              <p className="text-[11px] text-[#716c60] font-sans mb-2">
                Frequency histogram of window scores
              </p>
            </div>

            <ScoreDistributionChart
              distribution={data?.score_distribution || []}
              height={180}
              barColor="#7058a3"
            />

            <div className="mt-4 pt-3 border-t border-[#e5e0d5] flex items-center justify-around text-xs font-sans">
              <div className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-emerald-700" />
                <div>
                  <div className="text-[10px] text-[#716c60] uppercase">Normal</div>
                  <div className="font-bold text-emerald-700">
                    {normalVsAnomaly?.normal || 0} windows
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-700" />
                <div>
                  <div className="text-[10px] text-[#716c60] uppercase">Anomalous</div>
                  <div className="font-bold text-red-700">
                    {normalVsAnomaly?.anomaly || 0} windows
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Feature Inspection Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Selected Window Feature Profile */}
          <div className="lg:col-span-2 bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
            <div className="flex items-center justify-between mb-2">
              <div>
                <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f]">
                  8-Feature Inspection Profile
                </h3>
                <p className="text-[11px] text-[#716c60] font-sans mt-0.5">
                  Actual feature values for IP:{" "}
                  <span className="text-amber-800 font-bold">
                    {selectedWindow?.ip || "None selected"}
                  </span>
                </p>
              </div>

              {selectedWindow && (
                <div className="flex items-center gap-2">
                  <span className="text-xs font-sans text-[#716c60]">Score:</span>
                  <span
                    className={`font-sans font-bold text-sm ${
                      selectedWindow.is_anomalous
                        ? "text-red-700"
                        : "text-emerald-700"
                    }`}
                  >
                    {selectedWindow.ml_score.toFixed(1)} / 100
                  </span>
                </div>
              )}
            </div>

            <FeatureImportanceChart
              features={selectedWindow?.features || {}}
              height={260}
            />
          </div>

          {/* Model Contract & Metadata */}
          <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f]">
                  Feature Contract
                </h3>
                <span className="text-[10px] font-sans text-purple-800">
                  features.py
                </span>
              </div>
              <p className="text-[11px] text-[#716c60] font-sans mb-3">
                Ordered contract fed to models/iforest.joblib
              </p>

              <div className="space-y-1.5 font-sans text-xs">
                {(data?.features_contract || []).map((feat, i) => (
                  <div
                    key={feat}
                    className="flex items-center justify-between py-1 px-2.5 rounded-none bg-[#ffffff] border border-[#e5e0d5]"
                  >
                    <span className="text-[#5d584d]">{feat}</span>
                    <span className="text-[10px] text-[#716c60] font-sans">
                      #{i + 1}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {data?.metadata && (
              <div className="mt-4 pt-3 border-t border-[#e5e0d5] text-[11px] font-sans text-[#716c60]">
                <div>Training windows: {data.metadata.n_training_windows || "N/A"}</div>
                <div>Algorithm: IsolationForest (n=100)</div>
              </div>
            )}
          </div>
        </div>

        {/* Windows Table */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#27251f]">
                Extracted Behavioral Windows (30-Second Slices)
              </h3>
              <p className="text-[11px] text-[#716c60] font-sans">
                Click any window to view its 8 extracted features in the chart above
              </p>
            </div>
            <span className="text-xs font-sans text-[#716c60]">
              {data?.windows.length || 0} windows analyzed
            </span>
          </div>

          <MLWindowsTable
            windows={data?.windows || []}
            onSelectWindow={setSelectedWindow}
            selectedWindow={selectedWindow}
          />
        </div>
      </div>
    </AppLayout>
  );
}
