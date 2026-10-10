"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  PhoneCall,
  PhoneForwarded,
  CheckCircle,
  AlertTriangle,
  Clock,
  PhoneOff,
  Radio,
  ExternalLink,
  ShieldCheck,
  RefreshCw,
} from "lucide-react";
import { AppLayout } from "@/components/layout/AppLayout";
import { KpiCard } from "@/components/cards/KpiCard";
import { api } from "@/lib/api";
import { useVisibilityInterval } from "@/lib/useVisibilityInterval";
import { CallAlert, VoiceConfigStatus } from "@/lib/types";
import { formatTimeAgo } from "@/lib/utils";

export default function CallAlertsPage() {
  const [config, setConfig] = useState<VoiceConfigStatus | null>(null);
  const [calls, setCalls] = useState<CallAlert[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [triggeringTest, setTriggeringTest] = useState<boolean>(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const loadData = async () => {
    try {
      const [confData, callData] = await Promise.allSettled([
        api.getVoiceConfig(),
        api.getCalls({ limit: 50 }),
      ]);

      if (confData.status === "fulfilled") setConfig(confData.value);
      if (callData.status === "fulfilled") {
        setCalls(callData.value.calls || []);
        setTotalCount(callData.value.total || 0);
      }
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
  useVisibilityInterval(loadData, 10000);

  const handleManualRefresh = () => {
    setRefreshing(true);
    loadData();
  };

  const handleTestCall = async () => {
    if (!config?.configured || !config?.enabled) return;
    setTriggeringTest(true);
    setTestResult(null);
    try {
      const res = await api.triggerTestCall();
      if (res.success) {
        setTestResult({
          success: true,
          message: `Test call initiated (SID: ${res.call_sid || "pending"}). Status: ${res.status}.`,
        });
      } else {
        setTestResult({
          success: false,
          message: res.reason || "Call request was not accepted by provider.",
        });
      }
      await loadData();
    } catch (err: any) {
      setTestResult({
        success: false,
        message: err.message || "Failed to trigger test call.",
      });
    } finally {
      setTriggeringTest(false);
    }
  };

  const getStatusBadge = (status: string) => {
    const s = status.toLowerCase();
    if (s === "completed") {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-semibold font-mono bg-emerald-50 text-emerald-800 border border-emerald-200 rounded-[2px]">
          <CheckCircle className="w-3 h-3 text-[#2EAF7D]" /> COMPLETED
        </span>
      );
    }
    if (s === "in-progress" || s === "ringing" || s === "initiated" || s === "queued") {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-semibold font-mono bg-cyan-50 text-cyan-800 border border-cyan-200 rounded-[2px]">
          <Radio className="w-3 h-3 text-cyan-600 animate-pulse" /> {status.toUpperCase()}
        </span>
      );
    }
    if (s === "failed" || s === "canceled" || s === "busy" || s === "no-answer") {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-semibold font-mono bg-red-50 text-red-800 border border-red-200 rounded-[2px]">
          <PhoneOff className="w-3 h-3 text-red-600" /> {status.toUpperCase()}
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-semibold font-mono bg-slate-50 text-slate-700 border border-slate-200 rounded-[2px]">
        {status.toUpperCase()}
      </span>
    );
  };

  const completedCalls = calls.filter((c) => c.status === "completed").length;
  const activeCalls = calls.filter((c) =>
    ["queued", "initiated", "ringing", "in-progress"].includes(c.status)
  ).length;

  return (
    <AppLayout
      title="VOICE CALL ALERTS"
      subtitle="Outbound Twilio Security Dispatch & Status Telemetry"
      onRefresh={handleManualRefresh}
      isRefreshing={refreshing}
    >
      <div className="space-y-6">
        {/* KPI Row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
          <KpiCard
            title="Total Call Attempts"
            value={totalCount}
            subtext="Persisted voice alerts"
            icon={PhoneCall}
            color="cyan"
          />
          <KpiCard
            title="Active / In-Flight"
            value={activeCalls}
            subtext="Queued, ringing, in-progress"
            icon={Radio}
            color="purple"
          />
          <KpiCard
            title="Completed Calls"
            value={completedCalls}
            subtext="Delivered & confirmed"
            icon={CheckCircle}
            color="emerald"
          />
          <KpiCard
            title="Voice Service Status"
            value={config?.enabled ? "ACTIVE" : config?.configured ? "DISABLED" : "UNCONFIGURED"}
            subtext={config?.configured ? `To: ${config.to_number_masked}` : "Credentials missing"}
            icon={ShieldCheck}
            color={config?.enabled ? "emerald" : "amber"}
          />
        </div>

        {/* Configuration & Controls Panel */}
        <div className="bg-white border border-[#D5EAE5] rounded-[4px] p-5">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold uppercase tracking-wider text-[#02353C]">
                  Twilio Voice Alerting Engine
                </h3>
                {config?.enabled ? (
                  <span className="px-2 py-0.5 text-[10px] font-bold font-mono bg-emerald-100 text-emerald-800 border border-emerald-300 rounded-[2px]">
                    ACTIVE PROVIDER
                  </span>
                ) : (
                  <span className="px-2 py-0.5 text-[10px] font-bold font-mono bg-amber-100 text-amber-800 border border-amber-300 rounded-[2px]">
                    STANDBY / SETUP REQUIRED
                  </span>
                )}
              </div>
              <p className="text-xs text-[#486966] mt-1 max-w-2xl leading-relaxed">
                Outbound voice briefing initiates automatically on critical incidents and threshold violations (such as 30 requests in 10s). Calls are routed exclusively to the configured authorized recipient.
              </p>
              <div className="mt-3 flex flex-wrap gap-4 text-xs font-mono text-[#02353C]">
                <div>
                  <span className="text-[#486966]">Caller ID: </span>
                  <strong>{config?.from_number_masked || "Not set"}</strong>
                </div>
                <div>
                  <span className="text-[#486966]">Recipient: </span>
                  <strong>{config?.to_number_masked || "Not set"}</strong>
                </div>
                <div>
                  <span className="text-[#486966]">Min Severity: </span>
                  <strong>{config?.min_severity ?? 80}/100</strong>
                </div>
                <div>
                  <span className="text-[#486966]">Cooldown: </span>
                  <strong>{config?.cooldown_seconds ?? 300}s</strong>
                </div>
              </div>
            </div>

            {/* Test Call Control */}
            <div className="shrink-0 flex flex-col items-end gap-2">
              <button
                onClick={handleTestCall}
                disabled={!config?.enabled || triggeringTest}
                className="flex items-center gap-2 px-4 py-2 bg-[#02353C] hover:bg-[#2EAF7D] text-white text-xs font-semibold rounded-[2px] transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
              >
                <PhoneForwarded className={`w-3.5 h-3.5 ${triggeringTest ? "animate-pulse" : ""}`} />
                <span>{triggeringTest ? "Initiating Call..." : "Trigger Operator Test Call"}</span>
              </button>
              <span className="text-[10px] text-[#486966]">
                Only calls authorized number ({config?.to_number_masked || "N/A"})
              </span>
            </div>
          </div>

          {/* Test call response alert */}
          {testResult && (
            <div
              className={`mt-4 p-3 border rounded-[2px] text-xs flex items-center justify-between ${
                testResult.success
                  ? "bg-emerald-50 border-emerald-300 text-emerald-900"
                  : "bg-red-50 border-red-300 text-red-900"
              }`}
            >
              <span>{testResult.message}</span>
              <button
                onClick={() => setTestResult(null)}
                className="font-bold ml-3 text-sm leading-none"
              >
                &times;
              </button>
            </div>
          )}
        </div>

        {/* Call History Table */}
        <div className="bg-white border border-[#D5EAE5] rounded-[4px] overflow-hidden shadow-sm">
          <div className="p-4 border-b border-[#D5EAE5] bg-[#F2FBF9] flex items-center justify-between">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#02353C]">
                Outbound Call Telemetry & Status Logs
              </h3>
              <p className="text-[11px] text-[#486966] mt-0.5">
                Real-time provider state updates delivered via Twilio webhook callbacks
              </p>
            </div>
            <span className="text-xs font-mono text-[#02353C]">
              {calls.length} of {totalCount} records
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#D5EAE5] bg-[#F8FEFD] text-[11px] font-semibold text-[#486966] uppercase tracking-wider">
                  <th className="py-2.5 px-4">Call SID</th>
                  <th className="py-2.5 px-4">Incident ID</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4">Trigger Reason</th>
                  <th className="py-2.5 px-4">Recipient</th>
                  <th className="py-2.5 px-4">Initiated</th>
                  <th className="py-2.5 px-4">Duration</th>
                  <th className="py-2.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#D5EAE5]">
                {loading ? (
                  <tr>
                    <td colSpan={8} className="py-12 text-center text-xs text-[#486966]">
                      Loading voice call records...
                    </td>
                  </tr>
                ) : calls.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-12 text-center">
                      <PhoneCall className="w-8 h-8 text-[#2EAF7D]/50 mx-auto mb-2" />
                      <p className="text-xs font-semibold text-[#02353C]">No call records found</p>
                      <p className="text-[11px] text-[#486966] mt-1">
                        Outbound voice alerts will appear here when high-severity incidents or burst limits trigger.
                      </p>
                    </td>
                  </tr>
                ) : (
                  calls.map((call) => (
                    <tr key={call.call_id} className="hover:bg-[#F2FBF9] transition-colors">
                      <td className="py-3 px-4 font-mono text-[11px] text-[#02353C] font-semibold">
                        {call.call_sid}
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-[#02353C]">
                        {call.incident_id}
                      </td>
                      <td className="py-3 px-4">
                        {getStatusBadge(call.status)}
                      </td>
                      <td className="py-3 px-4 text-[11px] text-[#486966] max-w-xs truncate" title={call.trigger_reason}>
                        {call.trigger_reason}
                        {call.error_message && (
                          <div className="text-[10px] text-red-600 font-mono mt-0.5 truncate" title={call.error_message}>
                            Error: {call.error_message}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-[#486966]">
                        {call.to_number}
                      </td>
                      <td className="py-3 px-4 text-[11px] text-[#486966] whitespace-nowrap">
                        {formatTimeAgo(new Date(call.initiated_at))}
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-[#486966]">
                        {call.duration !== null && call.duration !== undefined ? `${call.duration}s` : "—"}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <Link
                          href="/threats"
                          className="inline-flex items-center gap-1 text-[11px] font-semibold text-[#2EAF7D] hover:text-[#02353C] transition-colors"
                        >
                          <span>Incident</span>
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
