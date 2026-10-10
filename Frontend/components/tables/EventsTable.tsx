"use client";

import React from "react";
import Link from "next/link";
import { ExternalLink, Database } from "lucide-react";
import { SecurityEvent } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";
import { EmptyState } from "../cards/EmptyState";

interface EventsTableProps {
  events: SecurityEvent[];
  isLoading?: boolean;
  traceLabel?: string;
}

export function EventsTable({ events, isLoading = false, traceLabel = "Trace" }: EventsTableProps) {
  if (isLoading) {
    return (
      <div className="p-12 text-center text-xs font-sans text-[#486966] bg-[#FFFFFF] border border-[#D5EAE5] rounded-sm">
        Loading security events...
      </div>
    );
  }

  if (!events || events.length === 0) {
    return (
      <EmptyState
        title="No events found"
        message="No security events match the current filter or search criteria."
        icon={Database}
      />
    );
  }

  return (
    <div className="bg-[#FFFFFF] border border-[#D5EAE5] rounded-sm overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-sans">
          <thead className="bg-[#F2FBF9] border-b border-[#D5EAE5] text-[#486966] uppercase tracking-wider text-[11px] font-semibold">
            <tr>
              <th className="py-3 px-4">Event ID</th>
              <th className="py-3 px-4">Method</th>
              <th className="py-3 px-4">Endpoint</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Source IP</th>
              <th className="py-3 px-4">User</th>
              <th className="py-3 px-4">Latency</th>
              <th className="py-3 px-4">Simulation</th>
              <th className="py-3 px-4 text-right">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#D5EAE5] text-[#02353C]">
            {events.map((e) => {
              const statusColor =
                e.status_code < 300
                  ? "text-[#449342] bg-[#449342]/10 border-[#449342]/30"
                  : e.status_code === 401 || e.status_code === 403
                  ? "text-[#D97706] bg-[#D97706]/10 border-[#D97706]/30"
                  : e.status_code === 404
                  ? "text-[#EA580C] bg-[#EA580C]/10 border-[#EA580C]/30"
                  : "text-[#DC2626] bg-[#DC2626]/10 border-[#DC2626]/30";

              return (
                <tr
                  key={e.event_id}
                  className="hover:bg-[#F2FBF9] transition-colors"
                >
                  <td className="py-3 px-4 whitespace-nowrap font-mono text-[#486966]">
                    #{e.event_id}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span className="px-1.5 py-0.5 rounded-sm bg-[#F2FBF9] border border-[#D5EAE5] text-[#02353C] font-mono font-bold text-[10px]">
                      {e.method}
                    </span>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap font-medium text-[#02353C] max-w-[240px] truncate font-mono text-[11px]">
                    {e.endpoint}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span
                      className={`px-1.5 py-0.5 rounded-sm border text-[11px] font-bold font-mono ${statusColor}`}
                    >
                      {e.status_code}
                    </span>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap font-mono font-semibold text-[#02353C]">
                    {e.ip}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-[#486966]">
                    {e.user_name ? (
                      <span>
                        {e.user_name}{" "}
                        <span className="text-[#486966]">({e.user_id})</span>
                      </span>
                    ) : e.user_id ? (
                      `User ${e.user_id}`
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-[#486966] font-mono">
                    {e.response_time_ms.toFixed(1)} ms
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span
                      className={`uppercase text-[10px] px-2 py-0.5 rounded-sm font-semibold border ${
                        e.sim_label === "normal"
                          ? "bg-[#2EAF7D]/10 text-[#02353C] border-[#2EAF7D]/30"
                          : "bg-[#DC2626]/10 text-[#DC2626] border-[#DC2626]/30"
                      }`}
                    >
                      {e.sim_label}
                    </span>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-right">
                    <Link
                      href={`/investigate/${e.event_id}`}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-sm bg-[#FFFFFF] hover:bg-[#F2FBF9] text-[#02353C] border border-[#D5EAE5] hover:border-[#2EAF7D] text-[11px] font-medium transition-colors"
                    >
                      <span>{traceLabel}</span>
                      <ExternalLink className="w-3 h-3 text-[#2EAF7D]" />
                    </Link>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
