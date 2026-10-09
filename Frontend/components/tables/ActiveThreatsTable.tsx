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
    <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-sans">
          <thead className="bg-[#ffffff] border-b border-[#e5e0d5] text-[#716c60] uppercase tracking-wider text-[11px]">
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
          <tbody className="divide-y divide-[#eeeae1] text-[#464238]">
            {items.map((d) => {
              const firstEventId =
                d.event_ids && d.event_ids.length > 0
                  ? d.event_ids[0]
                  : null;

              return (
                <tr
                  key={d.detection_id}
                  className="hover:bg-[#f4f1e8] transition-colors"
                >
                  <td className="py-3 px-4 whitespace-nowrap">
                    <SeverityBadge band={d.severity_band} score={d.severity} />
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap font-medium text-[#27251f]">
                    {d.attack_type}
                    <div className="text-[10px] text-[#716c60]">{d.owasp}</div>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-amber-800">
                    {d.ip}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap max-w-[200px] truncate text-[#716c60]">
                    {d.linked_endpoint || "—"}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    {d.ml_score !== null && d.ml_score !== undefined ? (
                      <span className="font-semibold text-purple-800">
                        {d.ml_score.toFixed(1)}
                      </span>
                    ) : (
                      <span className="text-[#716c60]">N/A</span>
                    )}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap font-semibold">
                    {d.risk_score !== null && d.risk_score !== undefined ? (
                      <span
                        className={
                          d.risk_score >= 80
                            ? "text-red-700"
                            : d.risk_score >= 60
                            ? "text-orange-700"
                            : d.risk_score >= 30
                            ? "text-amber-800"
                            : "text-emerald-700"
                        }
                      >
                        {d.risk_score}
                      </span>
                    ) : (
                      <span className="text-[#716c60]">N/A</span>
                    )}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    {d.action ? (
                      <ActionBadge action={d.action} size="sm" />
                    ) : (
                      <span className="text-[#716c60]">—</span>
                    )}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-[#716c60] text-[11px]">
                    {formatDateTime(d.linked_timestamp)}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-right">
                    {firstEventId ? (
                      <Link
                        href={`/investigate/${firstEventId}`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-none bg-[#ffffff] hover:bg-amber-500/20 text-amber-900 border border-[#e5e0d5] hover:border-amber-500/40 text-[11px] transition-colors"
                      >
                        <span>Inspect</span>
                        <ExternalLink className="w-3 h-3" />
                      </Link>
                    ) : (
                      <span className="text-[#716c60] text-[11px]">—</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {showAllLink && detections.length > (limit || 10) && (
        <div className="p-3 bg-[#ffffff] border-t border-[#e5e0d5] text-center">
          <Link
            href="/threats"
            className="text-xs font-sans text-amber-800 hover:text-amber-900 font-semibold"
          >
            View all {detections.length} detections &rarr;
          </Link>
        </div>
      )}
    </div>
  );
}
