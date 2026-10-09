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
      <div className="p-12 text-center text-xs font-sans text-[#716c60] bg-[#ffffff] border border-[#e5e0d5] rounded-none">
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
    <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-sans">
          <thead className="bg-[#ffffff] border-b border-[#e5e0d5] text-[#716c60] uppercase tracking-wider text-[11px]">
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
          <tbody className="divide-y divide-[#eeeae1] text-[#464238]">
            {events.map((e) => {
              const statusColor =
                e.status_code < 300
                  ? "text-emerald-700 bg-emerald-500/10 border-emerald-500/20"
                  : e.status_code === 401 || e.status_code === 403
                  ? "text-amber-800 bg-amber-500/10 border-amber-500/20"
                  : e.status_code === 404
                  ? "text-amber-800 bg-amber-500/10 border-amber-500/20"
                  : "text-red-700 bg-red-500/10 border-red-500/20";

              return (
                <tr
                  key={e.event_id}
                  className="hover:bg-[#f4f1e8] transition-colors"
                >
                  <td className="py-3 px-4 whitespace-nowrap text-[#635d51]">
                    #{e.event_id}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span className="px-1.5 py-0.5 rounded-none bg-[#ffffff] border border-[#e5e0d5] text-[#bd7b12] font-bold text-[10px]">
                      {e.method}
                    </span>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap font-medium text-[#27251f] max-w-[240px] truncate">
                    {e.endpoint}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span
                      className={`px-1.5 py-0.5 rounded-none border text-[11px] font-bold ${statusColor}`}
                    >
                      {e.status_code}
                    </span>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-amber-800">
                    {e.ip}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-[#5d584d]">
                    {e.user_name ? (
                      <span>
                        {e.user_name}{" "}
                        <span className="text-[#716c60]">({e.user_id})</span>
                      </span>
                    ) : e.user_id ? (
                      `User ${e.user_id}`
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-[#635d51]">
                    {e.response_time_ms.toFixed(1)} ms
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded-none font-sans uppercase font-bold tracking-wider ${
                        e.sim_label === "normal"
                          ? "bg-emerald-500/10 text-emerald-700 border border-emerald-500/20"
                          : "bg-red-500/10 text-red-700 border border-red-500/20"
                      }`}
                    >
                      {e.sim_label}
                    </span>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-right">
                    <Link
                      href={`/investigate/${e.event_id}`}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-none bg-[#ffffff] hover:bg-amber-500/20 text-amber-900 border border-[#e5e0d5] hover:border-amber-500/40 text-[11px] transition-colors"
                    >
                      <span>{traceLabel}</span>
                      <ExternalLink className="w-3 h-3" />
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
