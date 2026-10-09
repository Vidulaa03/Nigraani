"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  Shield,
  Brain,
  Sliders,
  Code,
  AlertTriangle,
  User,
  Clock,
  Terminal,
} from "lucide-react";
import { InvestigationTrail } from "@/lib/types";
import { InvestigationStepper } from "./InvestigationStepper";
import { InvestigationReportPanel } from "./InvestigationReportPanel";
import { ActionBadge } from "../badges/ActionBadge";
import { SeverityBadge } from "../badges/SeverityBadge";
import { formatDateTime } from "@/lib/utils";

interface InvestigationDetailProps {
  data: InvestigationTrail;
}

export function InvestigationDetail({ data }: InvestigationDetailProps) {
  const [showRawJson, setShowRawJson] = useState(false);

  const { event, user, detections, ml_window, decision, lifecycle } = data;

  return (
    <div className="space-y-6">
      {/* Back button and Header */}
      <div className="flex items-center justify-between">
        <Link
          href="/investigate"
          className="inline-flex items-center gap-2 text-xs font-sans text-amber-800 hover:text-amber-900 transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Investigation Search</span>
        </Link>

        <div className="flex items-center gap-3">
          <span className="text-xs font-sans text-[#716c60]">
            Event ID #{event.event_id}
          </span>
          {decision && <ActionBadge action={decision.action} size="sm" />}
        </div>
      </div>

      {/* Top 5-stage Stepper */}
      <InvestigationStepper lifecycle={lifecycle} />

      {/* LLM report prototype for supported enumeration and rate-spike incidents */}
      <InvestigationReportPanel trail={data} />

      {/* Grid of Investigation Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Panel 1: Request Details */}
        <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
          <div className="flex items-center justify-between pb-3 border-b border-[#e5e0d5] mb-4">
            <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-amber-800 flex items-center gap-2">
              <Terminal className="w-4 h-4" />
              1. HTTP Ingestion Details
            </h3>
            <span className="text-[11px] font-sans text-[#716c60]">
              {formatDateTime(event.timestamp)}
            </span>
          </div>

          <div className="space-y-2.5 text-xs font-sans">
            <div className="flex justify-between py-1 border-b border-[#e5e0d5]">
              <span className="text-[#716c60]">Method / Endpoint</span>
              <span className="font-bold text-[#27251f] text-right">
                <span className="text-amber-800 mr-2">{event.method}</span>
                {event.endpoint}
              </span>
            </div>

            <div className="flex justify-between py-1 border-b border-[#e5e0d5]">
              <span className="text-[#716c60]">Endpoint Pattern</span>
              <span className="text-[#5d584d]">{event.endpoint_pattern}</span>
            </div>

            <div className="flex justify-between py-1 border-b border-[#e5e0d5]">
              <span className="text-[#716c60]">Source IP</span>
              <span className="text-amber-900 font-semibold">{event.ip}</span>
            </div>

            <div className="flex justify-between py-1 border-b border-[#e5e0d5]">
              <span className="text-[#716c60]">HTTP Status Code</span>
              <span
                className={`font-bold ${
                  event.status_code >= 400 ? "text-amber-800" : "text-emerald-700"
                }`}
              >
                {event.status_code}
              </span>
            </div>

            <div className="flex justify-between py-1 border-b border-[#e5e0d5]">
              <span className="text-[#716c60]">Latency</span>
              <span className="text-[#27251f]">{event.response_time_ms.toFixed(1)} ms</span>
            </div>

            <div className="flex justify-between py-1 border-b border-[#e5e0d5]">
              <span className="text-[#716c60]">Authenticated User</span>
              <span className="text-[#27251f]">
                {user ? (
                  <span>
                    {user.name} <span className="text-[#716c60]">({user.email})</span>
                  </span>
                ) : event.user_id ? (
                  `User ID ${event.user_id}`
                ) : (
                  <span className="text-[#716c60]">Anonymous / Unauthenticated</span>
                )}
              </span>
            </div>

            <div className="flex justify-between py-1 border-b border-[#e5e0d5]">
              <span className="text-[#716c60]">Resource ID / Owner</span>
              <span className="text-[#27251f]">
                {event.resource_id !== null ? `#${event.resource_id}` : "None"}
                {event.resource_owner_id !== null && ` (Owner: User ${event.resource_owner_id})`}
              </span>
            </div>

            <div className="flex justify-between py-1">
              <span className="text-[#716c60]">Traffic Simulation Tag</span>
              <span
                className={`uppercase font-bold text-[10px] px-2 py-0.5 rounded-none ${
                  event.sim_label === "normal"
                    ? "bg-emerald-500/10 text-emerald-700"
                    : "bg-red-500/10 text-red-700"
                }`}
              >
                {event.sim_label}
              </span>
            </div>
          </div>
        </div>

        {/* Panel 2: Detection Engine Results */}
        <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
          <div className="flex items-center justify-between pb-3 border-b border-[#e5e0d5] mb-4">
            <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-orange-700 flex items-center gap-2">
              <Shield className="w-4 h-4" />
              2. Detection Engine Results
            </h3>
            <span className="text-[11px] font-sans text-[#716c60]">
              {detections.length} rule detections
            </span>
          </div>

          {detections.length === 0 ? (
            <div className="py-8 text-center text-xs font-sans text-[#716c60]">
              No rule-based security detectors flagged this request.
            </div>
          ) : (
            <div className="space-y-3">
              {detections.map((d) => (
                <div
                  key={d.detection_id}
                  className="p-3 rounded-none bg-[#ffffff] border border-orange-500/20"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-sans text-xs font-bold text-[#27251f]">
                      {d.attack_type}
                    </span>
                    <SeverityBadge band={d.severity_band} score={d.severity} />
                  </div>
                  <div className="text-xs text-[#5d584d] mb-2 font-sans">
                    <span className="text-[#716c60]">Detector:</span> {d.detector} |{" "}
                    <span className="text-[#716c60]">OWASP:</span> {d.owasp}
                  </div>
                  <div className="p-2.5 rounded-none bg-[#ffffff] border border-[#e5e0d5] text-xs font-sans text-orange-800">
                    <span className="text-[#716c60] block text-[10px] uppercase font-bold mb-1">
                      Evidence:
                    </span>
                    {d.evidence}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Panel 3: ML Behavior Window & Features */}
        <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
          <div className="flex items-center justify-between pb-3 border-b border-[#e5e0d5] mb-4">
            <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-purple-800 flex items-center gap-2">
              <Brain className="w-4 h-4" />
              3. Isolation Forest ML Analysis
            </h3>
            {ml_window && (
              <span
                className={`text-[10px] font-sans font-bold uppercase px-2 py-0.5 rounded-none border ${
                  ml_window.is_anomalous
                    ? "bg-red-500/10 text-red-700 border-red-500/30"
                    : "bg-emerald-500/10 text-emerald-700 border-emerald-500/30"
                }`}
              >
                {ml_window.prediction}
              </span>
            )}
          </div>

          {!ml_window ? (
            <div className="py-8 text-center text-xs font-sans text-[#716c60]">
              This request was not part of an active scoreable 30s IP window (requires ≥3 requests in window).
            </div>
          ) : (
            <div>
              <div className="grid grid-cols-2 gap-3 mb-4">
                <div className="p-3 rounded-none bg-[#ffffff] border border-[#e5e0d5]">
                  <div className="text-[10px] font-sans text-[#716c60] uppercase">
                    ML Anomaly Score
                  </div>
                  <div className="font-sans text-2xl font-bold text-purple-800 mt-1">
                    {ml_window.ml_score.toFixed(1)}
                    <span className="text-xs text-[#716c60] font-normal"> / 100</span>
                  </div>
                  <div className="text-[10px] text-[#716c60] mt-0.5 font-sans">
                    Decision threshold: 50.0
                  </div>
                </div>

                <div className="p-3 rounded-none bg-[#ffffff] border border-[#e5e0d5]">
                  <div className="text-[10px] font-sans text-[#716c60] uppercase">
                    Raw IF Score
                  </div>
                  <div className="font-sans text-2xl font-bold text-[#27251f] mt-1">
                    {ml_window.raw_score.toFixed(4)}
                  </div>
                  <div className="text-[10px] text-[#716c60] mt-0.5 font-sans">
                    Negative = anomalous
                  </div>
                </div>
              </div>

              <div className="text-[11px] font-sans uppercase tracking-wider text-[#716c60] mb-2 font-bold">
                Actual Features (backend/ml/features.py contract):
              </div>
              <div className="space-y-1.5 text-xs font-sans bg-[#ffffff] p-3 rounded-none border border-[#e5e0d5]">
                {Object.entries(ml_window.features).map(([name, val]) => (
                  <div
                    key={name}
                    className="flex justify-between items-center py-0.5 border-b border-[#e5e0d5] last:border-0"
                  >
                    <span className="text-[#716c60]">{name}</span>
                    <span className="font-bold text-[#27251f]">
                      {typeof val === "number" ? val.toFixed(2) : String(val)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Panel 4: Risk Engine Fusion & Decision */}
        <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
          <div className="flex items-center justify-between pb-3 border-b border-[#e5e0d5] mb-4">
            <h3 className="text-xs font-sans font-bold uppercase tracking-wider text-amber-800 flex items-center gap-2">
              <Sliders className="w-4 h-4" />
              4. Risk Engine Fusion & Decision
            </h3>
            {decision && <ActionBadge action={decision.action} size="sm" />}
          </div>

          {!decision ? (
            <div className="py-8 text-center text-xs font-sans text-[#716c60]">
              No risk decision has been recorded yet for IP {event.ip}.
            </div>
          ) : (
            <div>
              {/* Big Score Callout */}
              <div className="p-4 rounded-none bg-[#ffffff] border border-[#e5e0d5] flex items-center justify-between mb-4">
                <div>
                  <div className="text-[10px] font-sans text-[#716c60] uppercase">
                    Risk Engine Score (0–100)
                  </div>
                  <div className="font-sans text-3xl font-extrabold text-[#27251f] mt-1">
                    {decision.risk_score}
                    <span className="text-sm text-[#716c60] font-normal"> / 100</span>
                  </div>
                </div>
                <div className="text-right">
                  <ActionBadge action={decision.action} size="lg" />
                  <div className="text-[10px] font-sans text-[#716c60] mt-1">
                    Level: {decision.risk_level}
                  </div>
                </div>
              </div>

              {/* Formula Explanation */}
              <div className="p-3 rounded-none bg-[#ffffff] border border-[#e5e0d5] text-xs font-sans text-[#716c60] mb-4 space-y-1.5">
                <div className="text-[10px] uppercase font-bold text-[#716c60] mb-1">
                  Preserved Risk Engine Logic:
                </div>
                <div>&bull; Detection/Rule severity contributes 40%</div>
                <div>&bull; ML anomaly score contributes 60%</div>
                <div>&bull; +15 bonus when both rule severity &ge; 30 and ML &ge; 60</div>
                <div>&bull; 0–29 ALLOW | 30–59 MONITOR | 60–79 THROTTLE | 80–100 BLOCK</div>
              </div>

              {/* Reasons */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-sans uppercase tracking-wider text-[#716c60] font-bold">
                  Justification / Reasons:
                </div>
                {decision.reasons && decision.reasons.length > 0 ? (
                  decision.reasons.map((r, i) => (
                    <div
                      key={i}
                      className="p-2 rounded-none bg-[#ffffff] border border-[#e5e0d5] text-xs font-sans text-amber-900"
                    >
                      &bull; {r}
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-[#716c60] font-sans">No specific reasons stored.</div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Raw Event JSON Inspector */}
      <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
        <div className="flex items-center justify-between">
          <button
            onClick={() => setShowRawJson(!showRawJson)}
            className="flex items-center gap-2 text-xs font-sans text-[#716c60] hover:text-[#27251f] transition-colors"
          >
            <Code className="w-4 h-4 text-amber-800" />
            <span>{showRawJson ? "Hide" : "Show"} Raw Security Event Payload</span>
          </button>
          <span className="text-[11px] font-sans text-[#716c60]">
            Database row: security_events.event_id={event.event_id}
          </span>
        </div>

        {showRawJson && (
          <div className="mt-4 p-4 rounded-none bg-[#ffffff] border border-[#e5e0d5] overflow-x-auto">
            <pre className="text-xs font-mono text-emerald-700">
              {JSON.stringify(event, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
