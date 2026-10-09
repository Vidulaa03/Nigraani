"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  AlertCircle,
  ClipboardCheck,
  FileSearch,
  LoaderCircle,
  RefreshCw,
  Sparkles,
} from "lucide-react";
import { EmptyState } from "@/components/cards/EmptyState";
import { SeverityBadge } from "@/components/badges/SeverityBadge";
import { InvestigationTrail } from "@/lib/types";
import {
  InvestigationReport,
  loadInvestigationReport,
} from "@/lib/investigationReport";
import { formatDateTime } from "@/lib/utils";

interface InvestigationReportPanelProps {
  trail: InvestigationTrail;
}

const SUPPORTED_DETECTORS = new Set(["enumeration_detector", "rate_detector"]);

function ReportList({ items }: { items: string[] }) {
  return (
    <ul className="space-y-2 text-xs leading-5 text-[#464238]">
      {items.map((item, index) => (
        <li key={`${index}-${item}`} className="flex gap-2">
          <span aria-hidden="true" className="mt-2 h-1.5 w-1.5 shrink-0 bg-amber-700" />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );
}

function ReportSection({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="border border-[#e5e0d5] bg-white p-4 sm:p-5">
      <h4 className="mb-3 text-xs font-bold uppercase tracking-wider text-[#27251f]">
        {title}
      </h4>
      {children}
    </section>
  );
}

function ReportBody({ report }: { report: InvestigationReport }) {
  return (
    <div className="space-y-4">
      <div className="border border-amber-500/30 bg-amber-500/5 p-4" role="note">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h4 className="text-xs font-bold uppercase tracking-wider text-amber-900">
            Incident summary
          </h4>
          <SeverityBadge band={report.severityBand} score={report.severity} />
        </div>
        <p className="text-sm leading-6 text-[#27251f]">{report.summary}</p>
      </div>

      <ReportSection title={`Related API events (${report.relatedEvents.length})`}>
        <ol className="divide-y divide-[#eeeae1]">
          {report.relatedEvents.map((event) => (
            <li key={event.eventId} className="py-3 first:pt-0 last:pb-0">
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="border border-[#e5e0d5] bg-[#faf9f6] px-2 py-1 font-mono font-semibold text-[#27251f]">
                  Event #{event.eventId}
                </span>
                {event.timestamp && (
                  <span className="text-[#716c60]">{formatDateTime(event.timestamp)}</span>
                )}
                {event.statusCode !== undefined && (
                  <span className={`font-semibold ${event.statusCode >= 400 ? "text-orange-800" : "text-emerald-800"}`}>
                    HTTP {event.statusCode}
                  </span>
                )}
              </div>
              {event.method && event.endpoint ? (
                <p className="mt-2 break-all font-mono text-xs text-[#464238]">
                  <span className="mr-2 font-bold text-amber-800">{event.method}</span>
                  {event.endpoint}
                  {event.responseTimeMs !== undefined && (
                    <span className="ml-2 font-sans text-[#716c60]">
                      {event.responseTimeMs.toFixed(1)} ms
                    </span>
                  )}
                </p>
              ) : (
                <p className="mt-2 text-xs text-[#716c60]">
                  Event details are outside the current event listing; this ID is referenced by detector evidence.
                </p>
              )}
              {event.detectorEvidence.length > 0 && (
                <p className="mt-2 border-l-2 border-amber-700/40 pl-2 text-xs leading-5 text-[#5d584d]">
                  {event.detectorEvidence.join(" ")}
                </p>
              )}
            </li>
          ))}
        </ol>
      </ReportSection>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <ReportSection title="Observed facts & supporting evidence">
          <ReportList items={report.observedFacts} />
        </ReportSection>
        <ReportSection title="Possible attack patterns">
          <ul className="space-y-3">
            {report.possiblePatterns.map((pattern) => (
              <li key={pattern.title}>
                <div className="mb-1 text-xs font-semibold text-[#27251f]">{pattern.title}</div>
                <p className="text-xs leading-5 text-[#5d584d]">{pattern.detail}</p>
              </li>
            ))}
          </ul>
        </ReportSection>
        <ReportSection title="Alternative benign explanations">
          <ReportList items={report.benignExplanations} />
        </ReportSection>
        <ReportSection title="Uncertainty & missing evidence">
          <ReportList items={report.uncertainty} />
        </ReportSection>
      </div>

      <ReportSection title="Recommended next steps · human approval required">
        <ol className="space-y-3">
          {report.nextSteps.map(({ recommendation }, index) => (
            <li key={recommendation} className="flex gap-3 text-xs leading-5 text-[#464238]">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center border border-[#e5e0d5] bg-[#faf9f6] font-mono text-[10px] text-[#716c60]">
                {index + 1}
              </span>
              <span>
                {recommendation}
                <span className="mt-1 flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide text-amber-800">
                  <ClipboardCheck className="h-3 w-3" /> Operator review and approval required
                </span>
              </span>
            </li>
          ))}
        </ol>
        <p className="mt-4 border-t border-[#e5e0d5] pt-3 text-[11px] text-[#716c60]">
          Recommendations are informational. This report does not block, throttle, or change access.
        </p>
      </ReportSection>
    </div>
  );
}

export function InvestigationReportPanel({ trail }: InvestigationReportPanelProps) {
  const supportsReport = trail.detections.some((detection) =>
    SUPPORTED_DETECTORS.has(detection.detector),
  );
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [loading, setLoading] = useState(supportsReport);
  const [error, setError] = useState<string | null>(null);

  const generateReport = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await loadInvestigationReport(trail);
      setReport(result);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The report could not be loaded.");
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, [trail]);

  useEffect(() => {
    if (supportsReport) void generateReport();
  }, [generateReport, supportsReport]);

  return (
    <section className="space-y-4 border border-[#e5e0d5] bg-[#f8f6f1] p-4 sm:p-5" aria-labelledby="investigation-report-title">
      <div className="flex flex-col gap-3 border-b border-[#e5e0d5] pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center border border-amber-500/30 bg-white text-amber-800">
            <FileSearch className="h-4 w-4" />
          </span>
          <div>
            <h3 id="investigation-report-title" className="text-sm font-bold uppercase tracking-wide text-[#27251f]">
              LLM Investigation Report
            </h3>
            <p className="mt-1 text-xs text-[#716c60]">
              Triage summary for API enumeration and rate-spike detections
            </p>
          </div>
        </div>
        {supportsReport && (
          <button
            type="button"
            onClick={() => void generateReport()}
            disabled={loading}
            className="inline-flex min-h-9 items-center justify-center gap-2 border border-[#ded7ca] bg-white px-3 py-2 text-xs font-medium text-[#464238] hover:bg-[#faf9f6] disabled:cursor-wait disabled:opacity-60"
          >
            {loading ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            {report ? "Refresh demo report" : "Generate demo report"}
          </button>
        )}
      </div>

      <div className="flex items-start gap-2 border border-violet-300 bg-violet-50 px-3 py-2.5 text-xs leading-5 text-violet-950" role="note">
        <Sparkles className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <p>
          <strong>Demo template · not an LLM response.</strong> Observed facts come from existing event and detector records; hypotheses and recommendations are deterministic examples. The report adapter is isolated for later backend/LLM integration.
        </p>
      </div>

      {!supportsReport ? (
        <EmptyState
          title="No supported incident for this report"
          message="This prototype currently covers linked API enumeration and rate-spike detections. Other events remain available in the investigation panels above."
          icon={FileSearch}
          className="bg-white"
        />
      ) : loading ? (
        <div className="flex min-h-32 items-center justify-center gap-3 border border-dashed border-[#ded7ca] bg-white p-6 text-xs text-[#716c60]" role="status" aria-live="polite">
          <LoaderCircle className="h-4 w-4 animate-spin text-amber-800" />
          Gathering linked event rows and preparing the demo template…
        </div>
      ) : error ? (
        <div className="flex flex-col items-start gap-3 border border-red-300 bg-red-50 p-4 text-xs text-red-900" role="alert">
          <div className="flex items-center gap-2 font-semibold">
            <AlertCircle className="h-4 w-4" /> Report unavailable
          </div>
          <p>{error}</p>
          <button type="button" onClick={() => void generateReport()} className="border border-red-300 bg-white px-3 py-2 font-medium hover:bg-red-50">
            Try again
          </button>
        </div>
      ) : report ? (
        <ReportBody report={report} />
      ) : (
        <EmptyState
          title="No report data available"
          message="The current investigation did not return a supported report scenario."
          icon={AlertCircle}
          className="bg-white"
        />
      )}
    </section>
  );
}
