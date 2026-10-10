"use client";

import React from "react";
import Link from "next/link";
import { ExternalLink, ShieldAlert } from "lucide-react";
import { SecurityDetection } from "@/lib/types";
import { SeverityBadge } from "../badges/SeverityBadge";
import { ActionBadge } from "../badges/ActionBadge";
import { formatDateTime } from "@/lib/utils";
import { EmptyState } from "../cards/EmptyState";

interface ActiveThreatsTableProps {
  detections: SecurityDetection[];
  limit?: number;
  showAllLink?: boolean;
}

export function ActiveThreatsTable({
  detections,
  limit,
  showAllLink = false,
}: ActiveThreatsTableProps) {
  if (!detections || detections.length === 0) {
    return (
      <EmptyState
        title="No active threats"
        message="No security threats or attacks currently detected in database."
        icon={ShieldAlert}
      />
    );
  }

  const items = limit ? detections.slice(0, limit) : detections;

  return (
    <div className="bg-[#FFFFFF] border border-[#D5EAE5] rounded-sm overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-sans">
          <thead className="bg-[#F2FBF9] border-b border-[#D5EAE5] text-[#486966] uppercase tracking-wider text-[11px] font-semibold">
            <tr>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Attack Type</th>
              <th className="py-3 px-4">Source IP</th>
              <th className="py-3 px-4">Target Endpoint</th>
              <th className="py-3 px-4">ML Score</th>
              <th className="py-3 px-4">Risk</th>
              <th className="py-3 px-4">Action</th>
              <th className="py-3 px-4">Timestamp</th>
              <th className="py-3 px-4 text-right">Investigate</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#D5EAE5] text-[#02353C]">
            {items.map((d) => {
              const firstEventId =
                d.event_ids && d.event_ids.length > 0
                  ? d.event_ids[0]
                  : null;

              return (
                <tr
                  key={d.detection_id}
                  className="hover:bg-[#F2FBF9] transition-colors"
                >
                  <td className="py-3 px-4 whitespace-nowrap">
                    <SeverityBadge band={d.severity_band} score={d.severity} />
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap font-medium text-[#02353C]">
                    {d.attack_type}
                    <div className="text-[10px] text-[#486966]">{d.owasp}</div>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap font-mono text-[#02353C] font-semibold">
                    {d.ip}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap max-w-[200px] truncate text-[#486966]">
                    {d.linked_endpoint || "—"}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    {d.ml_score !== null && d.ml_score !== undefined ? (
                      <span className="font-semibold text-[#02353C]">
                        {d.ml_score.toFixed(1)}
                      </span>
                    ) : (
                      <span className="text-[#486966]">N/A</span>
                    )}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap font-semibold">
                    {d.risk_score !== null && d.risk_score !== undefined ? (
                      <span
                        className={
                          d.risk_score >= 80
                            ? "text-[#DC2626] font-bold"
                            : d.risk_score >= 60
                            ? "text-[#EA580C] font-bold"
                            : d.risk_score >= 30
                            ? "text-[#D97706]"
                            : "text-[#2EAF7D]"
                        }
                      >
                        {d.risk_score}
                      </span>
                    ) : (
                      <span className="text-[#486966]">N/A</span>
                    )}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    {d.action ? (
                      <ActionBadge action={d.action} size="sm" />
                    ) : (
                      <span className="text-[#486966]">—</span>
                    )}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-[#486966] text-[11px]">
                    {formatDateTime(d.linked_timestamp)}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-right">
                    {firstEventId ? (
                      <Link
                        href={`/investigate/${firstEventId}`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-sm bg-[#FFFFFF] hover:bg-[#F2FBF9] text-[#02353C] border border-[#D5EAE5] hover:border-[#2EAF7D] text-[11px] font-medium transition-colors"
                      >
                        <span>Inspect</span>
                        <ExternalLink className="w-3 h-3 text-[#2EAF7D]" />
                      </Link>
                    ) : (
                      <span className="text-[#486966] text-[11px]">—</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {showAllLink && detections.length > (limit || 10) && (
        <div className="p-3 bg-[#F2FBF9] border-t border-[#D5EAE5] text-center">
          <Link
            href="/threats"
            className="text-xs font-sans text-[#2EAF7D] hover:text-[#02353C] font-semibold"
          >
            View all {detections.length} detections &rarr;
          </Link>
        </div>
      )}
    </div>
  );
}
