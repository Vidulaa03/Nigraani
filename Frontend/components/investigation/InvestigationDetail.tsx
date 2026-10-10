"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  Shield,
  Brain,
  Sliders,
  Code,
  Terminal,
  PhoneCall,
  CheckCircle2,
  Clock,
  AlertTriangle,
  Radio,
  PhoneOff,
} from "lucide-react";
import { InvestigationTrail, CallAlert } from "@/lib/types";
import { InvestigationStepper } from "./InvestigationStepper";
import { InvestigationReportPanel } from "./InvestigationReportPanel";
import { ActionBadge } from "../badges/ActionBadge";
import { SeverityBadge } from "../badges/SeverityBadge";
import { formatDateTime } from "@/lib/utils";
import { GeminiInvestigationPanel } from "./GeminiInvestigationPanel";

interface InvestigationDetailProps {
  data: InvestigationTrail;
}

export function InvestigationDetail({ data }: InvestigationDetailProps) {
  const [showRawJson, setShowRawJson] = useState(false);

  const { event, user, detections, ml_window, decision, lifecycle, calls } = data;

  const getCallStatusBadge = (status: string) => {
    const s = status.toLowerCase();
    if (s === "completed") {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-semibold font-mono bg-emerald-50 text-emerald-800 border border-emerald-200 rounded-[2px]">
          <CheckCircle2 className="w-3 h-3 text-[#2EAF7D]" /> COMPLETED
        </span>
      );
    }
    if (s === "in-progress" || s === "ringing" || s === "initiated" || s === "queued") {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-semibold font-mono bg-cyan-50 text-cyan-800 border border-cyan-200 rounded-[2px]">
          <Radio className="w-3 h-3 text-cyan-600 animate-pulse" /> {status.toUpperCase()}
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-semibold font-mono bg-red-50 text-red-800 border border-red-200 rounded-[2px]">
        <PhoneOff className="w-3 h-3 text-red-600" /> {status.toUpperCase()}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Back button and Header */}
      <div className="flex items-center justify-between">
        <Link
          href="/investigate"
          className="inline-flex items-center gap-2 text-xs font-sans text-[#2EAF7D] hover:text-[#02353C] font-medium transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Investigation Search</span>
        </Link>

        <div className="flex items-center gap-3">
          <span className="text-xs font-mono text-[#486966]">
            Event ID #{event.event_id}
          </span>
          {decision && <ActionBadge action={decision.action} size="sm" />}
        </div>
      </div>

      {/* Top 6-stage Stepper */}
      <InvestigationStepper lifecycle={lifecycle} />

      {/* LLM report prototype for supported enumeration and rate-spike incidents */}
      <InvestigationReportPanel trail={data} />

      {/* Grid of Investigation Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Panel 1: Request Details */}
        <div className="bg-[#FFFFFF] border border-[#D5EAE5] rounded-sm p-5 shadow-sm">
          <div className="flex items-center justify-between pb-3 border-b border-[#D5EAE5] mb-4">
            <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#02353C] flex items-center gap-2">
              <Terminal className="w-4 h-4 text-[#2EAF7D]" />
              1. HTTP Ingestion Details
            </h3>
            <span className="text-[11px] font-mono text-[#486966]">
              {formatDateTime(event.timestamp)}
            </span>
          </div>

          <div className="space-y-2.5 text-xs font-sans">
            <div className="flex justify-between py-1 border-b border-[#D5EAE5]">
              <span className="text-[#486966]">Method / Endpoint</span>
              <span className="font-bold text-[#02353C] text-right font-mono text-[11px]">
                <span className="text-[#2EAF7D] mr-2">{event.method}</span>
                {event.endpoint}
              </span>
            </div>

            <div className="flex justify-between py-1 border-b border-[#D5EAE5]">
              <span className="text-[#486966]">Endpoint Pattern</span>
              <span className="text-[#486966] font-mono text-[11px]">{event.endpoint_pattern}</span>
            </div>

            <div className="flex justify-between py-1 border-b border-[#D5EAE5]">
              <span className="text-[#486966]">Source IP</span>
              <span className="text-[#02353C] font-mono font-semibold">{event.ip}</span>
            </div>

            <div className="flex justify-between py-1 border-b border-[#D5EAE5]">
              <span className="text-[#486966]">HTTP Status Code</span>
              <span
                className={`font-bold font-mono ${
                  event.status_code >= 400 ? "text-[#DC2626]" : "text-[#449342]"
                }`}
              >
                {event.status_code}
              </span>
            </div>

            <div className="flex justify-between py-1 border-b border-[#D5EAE5]">
              <span className="text-[#486966]">Latency</span>
              <span className="text-[#02353C] font-mono">{event.response_time_ms.toFixed(1)} ms</span>
            </div>

            <div className="flex justify-between py-1 border-b border-[#D5EAE5]">
              <span className="text-[#486966]">Authenticated User</span>
              <span className="text-[#02353C]">
                {user ? (
                  <span>
                    {user.name} <span className="text-[#486966]">({user.email})</span>
                  </span>
                ) : event.user_id ? (
                  `User ID ${event.user_id}`
                ) : (
                  <span className="text-[#486966]">Anonymous / Unauthenticated</span>
                )}
              </span>
            </div>

            <div className="flex justify-between py-1 border-b border-[#D5EAE5]">
              <span className="text-[#486966]">Resource ID / Owner</span>
              <span className="text-[#02353C] font-mono text-[11px]">
                {event.resource_id !== null ? `#${event.resource_id}` : "None"}
                {event.resource_owner_id !== null && ` (Owner: User ${event.resource_owner_id})`}
              </span>
            </div>

            <div className="flex justify-between py-1">
              <span className="text-[#486966]">Traffic Simulation Tag</span>
              <span
                className={`uppercase font-semibold text-[10px] px-2 py-0.5 rounded-sm border ${
                  event.sim_label === "normal"
                    ? "bg-[#2EAF7D]/10 text-[#02353C] border-[#2EAF7D]/30"
                    : "bg-[#DC2626]/10 text-[#DC2626] border-[#DC2626]/30"
                }`}
              >
                {event.sim_label}
              </span>
            </div>
          </div>
        </div>

        {/* Panel 2: Detection Engine Results */}
        <div className="bg-[#FFFFFF] border border-[#D5EAE5] rounded-sm p-5 shadow-sm">
          <div className="flex items-center justify-between pb-3 border-b border-[#D5EAE5] mb-4">
            <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#02353C] flex items-center gap-2">
              <Shield className="w-4 h-4 text-[#EA580C]" />
              2. Detection Engine Results
            </h3>
            <span className="text-[11px] font-sans text-[#486966]">
              {detections.length} rule detections
            </span>
          </div>

          {detections.length === 0 ? (
            <div className="py-8 text-center text-xs font-sans text-[#486966]">
              No rule-based security detectors flagged this request.
            </div>
          ) : (
            <div className="space-y-3">
              {detections.map((d) => (
                <div
                  key={d.detection_id}
                  className="p-3 rounded-sm bg-[#FFFFFF] border border-[#D5EAE5]"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-sans text-xs font-bold text-[#02353C]">
                      {d.attack_type}
                    </span>
                    <SeverityBadge band={d.severity_band} score={d.severity} />
                  </div>
                  <div className="text-xs text-[#486966] mb-2 font-sans">
                    <span className="text-[#486966]">Detector:</span> {d.detector} |{" "}
                    <span className="text-[#486966]">OWASP:</span> {d.owasp}
                  </div>
                  <div className="p-2.5 rounded-sm bg-[#F2FBF9] border border-[#D5EAE5] text-xs font-mono text-[#02353C]">
                    <span className="text-[#486966] block text-[10px] uppercase font-sans font-bold mb-1">
                      Evidence:
                    </span>
                    {d.evidence}
                  </div>
                  <GeminiInvestigationPanel detectionId={d.detection_id} />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Panel 3: ML Behavior Window & Features */}
        <div className="bg-[#FFFFFF] border border-[#D5EAE5] rounded-sm p-5 shadow-sm">
          <div className="flex items-center justify-between pb-3 border-b border-[#D5EAE5] mb-4">
            <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#02353C] flex items-center gap-2">
              <Brain className="w-4 h-4 text-[#3FD0C9]" />
              3. Isolation Forest ML Analysis
            </h3>
            {ml_window && (
              <span
                className={`text-[10px] font-sans font-bold uppercase px-2 py-0.5 rounded-sm border ${
                  ml_window.is_anomalous
                    ? "bg-[#DC2626]/10 text-[#DC2626] border-[#DC2626]/30"
                    : "bg-[#2EAF7D]/10 text-[#02353C] border-[#2EAF7D]/30"
                }`}
              >
                {ml_window.prediction}
              </span>
            )}
          </div>

          {!ml_window ? (
            <div className="py-8 text-center text-xs font-sans text-[#486966]">
              This request was not part of an active scoreable 30s IP window (requires &ge; 3 requests in window).
            </div>
          ) : (
            <div>
              <div className="grid grid-cols-2 gap-3 mb-4">
                <div className="p-3 rounded-sm bg-[#F2FBF9] border border-[#D5EAE5]">
                  <div className="text-[10px] font-sans text-[#486966] uppercase">
                    ML Anomaly Score
                  </div>
                  <div className="font-sans text-2xl font-bold text-[#02353C] mt-1 font-mono">
                    {ml_window.ml_score.toFixed(1)}
                    <span className="text-xs text-[#486966] font-normal font-sans"> / 100</span>
                  </div>
                  <div className="text-[10px] text-[#486966] mt-0.5 font-sans">
                    Decision threshold: 50.0
                  </div>
                </div>

                <div className="p-3 rounded-sm bg-[#F2FBF9] border border-[#D5EAE5]">
                  <div className="text-[10px] font-sans text-[#486966] uppercase">
                    Raw IF Score
                  </div>
                  <div className="font-sans text-2xl font-bold text-[#02353C] mt-1 font-mono">
                    {ml_window.raw_score.toFixed(4)}
                  </div>
                  <div className="text-[10px] text-[#486966] mt-0.5 font-sans">
                    Negative = anomalous
                  </div>
                </div>
              </div>

              <div className="text-[11px] font-sans uppercase tracking-wider text-[#486966] mb-2 font-bold">
                Actual Features (backend/ml/features.py contract):
              </div>
              <div className="space-y-1.5 text-xs font-sans bg-[#F2FBF9] p-3 rounded-sm border border-[#D5EAE5]">
                {Object.entries(ml_window.features).map(([name, val]) => (
                  <div
                    key={name}
                    className="flex justify-between items-center py-0.5 border-b border-[#D5EAE5] last:border-0"
                  >
                    <span className="text-[#486966] font-mono text-[11px]">{name}</span>
                    <span className="font-bold text-[#02353C] font-mono text-[11px]">
                      {typeof val === "number" ? val.toFixed(2) : String(val)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Panel 4: Risk Engine Fusion & Decision */}
        <div className="bg-[#FFFFFF] border border-[#D5EAE5] rounded-sm p-5 shadow-sm">
          <div className="flex items-center justify-between pb-3 border-b border-[#D5EAE5] mb-4">
            <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#02353C] flex items-center gap-2">
              <Sliders className="w-4 h-4 text-[#2EAF7D]" />
              4. Risk Engine Fusion & Decision
            </h3>
            {decision && <ActionBadge action={decision.action} size="sm" />}
          </div>

          {!decision ? (
            <div className="py-8 text-center text-xs font-sans text-[#486966]">
              No risk decision has been recorded yet for IP {event.ip}.
            </div>
          ) : (
            <div>
              {/* Big Score Callout */}
              <div className="p-4 rounded-sm bg-[#F2FBF9] border border-[#D5EAE5] flex items-center justify-between mb-4">
                <div>
                  <div className="text-[10px] font-sans text-[#486966] uppercase">
                    Risk Engine Score (0–100)
                  </div>
                  <div className="font-sans text-3xl font-extrabold text-[#02353C] mt-1 font-mono">
                    {decision.risk_score}
                    <span className="text-sm text-[#486966] font-normal font-sans"> / 100</span>
                  </div>
                </div>
                <div className="text-right">
                  <ActionBadge action={decision.action} size="lg" />
                  <div className="text-[10px] font-sans text-[#486966] mt-1">
                    Level: {decision.risk_level}
                  </div>
                </div>
              </div>

              {/* Formula Explanation */}
              <div className="p-3 rounded-sm bg-[#FFFFFF] border border-[#D5EAE5] text-xs font-sans text-[#486966] mb-4 space-y-1.5">
                <div className="text-[10px] uppercase font-bold text-[#02353C] mb-1">
                  Preserved Risk Engine Logic:
                </div>
                <div>&bull; Detection/Rule severity contributes 40%</div>
                <div>&bull; ML anomaly score contributes 60%</div>
                <div>&bull; +15 bonus when both rule severity &ge; 30 and ML &ge; 60</div>
                <div>&bull; 0–29 ALLOW | 30–59 MONITOR | 60–79 THROTTLE | 80–100 BLOCK</div>
              </div>

              {/* Reasons */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-sans uppercase tracking-wider text-[#486966] font-bold">
                  Justification / Reasons:
                </div>
                {decision.reasons && decision.reasons.length > 0 ? (
                  decision.reasons.map((r, i) => (
                    <div
                      key={i}
                      className="p-2 rounded-sm bg-[#FFFFFF] border border-[#D5EAE5] text-xs font-sans text-[#02353C]"
                    >
                      &bull; {r}
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-[#486966] font-sans">No specific reasons stored.</div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Panel 5: Automated Voice Dispatch (Twilio) & Escalations */}
      <div className="bg-[#FFFFFF] border border-[#D5EAE5] rounded-sm p-5 shadow-sm">
        <div className="flex items-center justify-between pb-3 border-b border-[#D5EAE5] mb-4">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-sm bg-[#F2FBF9] border border-[#D5EAE5] flex items-center justify-center">
              <PhoneCall className="w-4 h-4 text-[#2EAF7D]" />
            </div>
            <div>
              <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-[#02353C]">
                5. Automated Voice Alerting & Escalations (Twilio)
              </h3>
              <p className="text-[11px] text-[#486966]">
                Outbound voice dispatch status and emergency phone notifications for this incident
              </p>
            </div>
          </div>
          <Link
            href="/calls"
            className="text-xs font-sans text-[#2EAF7D] hover:text-[#02353C] font-semibold"
          >
            Open Call Logs &rarr;
          </Link>
        </div>

        {calls && calls.length > 0 ? (
          <div className="space-y-3">
            {calls.map((c) => (
              <div
                key={c.call_id || c.call_sid}
                className="p-4 rounded-sm bg-[#F2FBF9] border border-[#D5EAE5] flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    {getCallStatusBadge(c.status)}
                    <span className="font-mono text-xs font-semibold text-[#02353C]">
                      {c.to_number}
                    </span>
                    <span className="text-[10px] font-mono text-[#486966]">
                      (from: {c.from_number})
                    </span>
                  </div>
                  <div className="text-xs text-[#486966]">
                    Trigger reason: <span className="text-[#02353C] font-medium">{c.trigger_reason}</span>
                  </div>
                  <div className="text-[11px] font-mono text-[#486966]">
                    Twilio SID: <span className="text-[#02353C]">{c.call_sid || "Pending"}</span> | Timestamp: {formatDateTime(c.initiated_at)}
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <div className="text-right">
                    <div className="text-[10px] uppercase font-bold text-[#486966]">Duration</div>
                    <div className="font-mono text-xs font-semibold text-[#02353C]">
                      {c.duration !== null && c.duration !== undefined
                        ? `${c.duration}s`
                        : "—"}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-6 text-center text-xs font-sans text-[#486966] bg-[#F2FBF9] rounded-sm border border-[#D5EAE5]">
            <p className="font-medium text-[#02353C] mb-1">No outbound voice alert recorded for this event</p>
            <p className="text-[11px] text-[#486966] max-w-md mx-auto">
              Twilio automated voice alerts trigger automatically on high-risk incidents (score &ge; 80) or when 30+ requests are received from the same client IP within 10 seconds.
            </p>
          </div>
        )}
      </div>

      {/* Raw Event JSON Inspector */}
      <div className="bg-[#FFFFFF] border border-[#D5EAE5] rounded-sm p-5 shadow-sm">
        <div className="flex items-center justify-between">
          <button
            onClick={() => setShowRawJson(!showRawJson)}
            className="flex items-center gap-2 text-xs font-sans text-[#486966] hover:text-[#02353C] transition-colors"
          >
            <Code className="w-4 h-4 text-[#2EAF7D]" />
            <span>{showRawJson ? "Hide" : "Show"} Raw Security Event Payload</span>
          </button>
          <span className="text-[11px] font-mono text-[#486966]">
            Database row: security_events.event_id={event.event_id}
          </span>
        </div>

        {showRawJson && (
          <div className="mt-4 p-4 rounded-sm bg-[#F2FBF9] border border-[#D5EAE5] overflow-x-auto">
            <pre className="text-xs font-mono text-[#02353C]">
              {JSON.stringify(event, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
