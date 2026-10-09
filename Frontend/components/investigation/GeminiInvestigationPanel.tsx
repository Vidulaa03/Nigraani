"use client";

import React, { useState } from "react";
import { Brain, LoaderCircle, Sparkles } from "lucide-react";
import { api } from "@/lib/api";
import { IncidentInvestigation } from "@/lib/types";

interface GeminiInvestigationPanelProps {
  detectionId: number;
}

const wait = (milliseconds: number) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

const investigationFailureMessage = (errorCode: string | null) => {
  if (errorCode === "gemini_rate_limited") {
    return "Gemini is rate-limited. Wait a little while, then retry.";
  }
  if (errorCode === "gemini_provider_504") {
    return "Gemini took too long to process this incident. You can retry.";
  }
  if (errorCode?.startsWith("gemini_provider_5")) {
    return "Gemini is temporarily unavailable. Please retry shortly.";
  }
  if (errorCode === "gemini_invalid_report") {
    return "Gemini returned a report that did not match the expected format.";
  }
  return "The investigation failed. Check the backend Gemini configuration.";
};

export function GeminiInvestigationPanel({
  detectionId,
}: GeminiInvestigationPanelProps) {
  const [investigation, setInvestigation] =
    useState<IncidentInvestigation | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const startInvestigation = async () => {
    if (busy) return;

    setBusy(true);
    setError(null);
    try {
      let result = await api.startIncidentInvestigation(detectionId);
      setInvestigation(result);

      for (
        let attempt = 0;
        attempt < 100 &&
        (result.status === "pending" || result.status === "in_progress");
        attempt += 1
      ) {
        await wait(1500);
        result = await api.getIncidentInvestigation(
          result.investigation_id
        );
        setInvestigation(result);
      }

      if (result.status === "failed") {
        setError(investigationFailureMessage(result.error_code));
      } else if (result.status !== "completed") {
        setError("The investigation is still running; try again shortly.");
      }
    } catch (requestError: unknown) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to request the investigation."
      );
    } finally {
      setBusy(false);
    }
  };

  const report = investigation?.result;

  return (
    <section className="mt-3 rounded-none border border-purple-500/30 bg-purple-500/5 p-3">
      <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase tracking-wide text-purple-800">
        <Brain className="h-4 w-4" />
        AI incident investigation
      </div>
      <button
        type="button"
        onClick={startInvestigation}
        disabled={busy}
        className="inline-flex items-center gap-2 rounded-none border border-purple-500/40 bg-purple-500/10 px-3 py-1.5 text-xs font-semibold text-purple-900 hover:bg-purple-500/20 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {busy ? (
          <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
        ) : (
          <Sparkles className="h-3.5 w-3.5" />
        )}
        {busy
          ? "Investigating…"
          : investigation?.status === "failed"
            ? "Retry investigation with Gemini"
            : "Investigate with Gemini"}
      </button>

      {investigation && (
        <div className="mt-3 text-xs text-[#464238]">
          <p>
            Status: <strong className="uppercase">{investigation.status}</strong>
            {" · "}Model: {investigation.model_id}
          </p>
          {report && (
            <div className="mt-3 space-y-3">
              <div>
                <p className="font-bold text-[#27251f]">
                  {report.incident_summary}
                </p>
                <p className="mt-1">
                  Likely category: {report.likely_attack_type} · Severity:{" "}
                  {report.severity} · Confidence: {report.confidence}%
                </p>
              </div>
              <div>
                <p className="font-semibold">Evidence observations</p>
                <ul className="list-disc space-y-1 pl-5">
                  {report.evidence.map((item, index) => (
                    <li key={`${index}-${item.observation}`}>
                      {item.observation} — {item.significance}
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <p className="font-semibold">Recommended actions</p>
                <ul className="list-disc space-y-1 pl-5">
                  {report.recommended_actions.map((item, index) => (
                    <li key={`${index}-${item}`}>{item}</li>
                  ))}
                </ul>
              </div>
              <div>
                <p className="font-semibold">Limitations</p>
                <ul className="list-disc space-y-1 pl-5">
                  {report.limitations.map((item, index) => (
                    <li key={`${index}-${item}`}>{item}</li>
                  ))}
                </ul>
              </div>
              <p className="text-[10px] text-[#716c60]">
                Created {new Date(investigation.created_at).toLocaleString()}
                {investigation.completed_at
                  ? ` · Completed ${new Date(investigation.completed_at).toLocaleString()}`
                  : ""}
              </p>
            </div>
          )}
          {investigation.status === "failed" && (
            <p role="alert" className="mt-2 text-amber-800">
              Error code: {investigation.error_code || "investigation_unavailable"}
            </p>
          )}
        </div>
      )}
      {error && (
        <p role="alert" className="mt-2 text-xs text-red-700">
          {error}
        </p>
      )}
    </section>
  );
}
