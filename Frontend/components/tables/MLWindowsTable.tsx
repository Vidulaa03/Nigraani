"use client";

import React, { useState } from "react";
import { MLWindow } from "@/lib/types";
import { EmptyState } from "../cards/EmptyState";
import { Brain, ChevronRight, Sliders } from "lucide-react";
import { formatDateTime } from "@/lib/utils";

interface MLWindowsTableProps {
  windows: MLWindow[];
  onSelectWindow?: (window: MLWindow) => void;
  selectedWindow?: MLWindow | null;
}

export function MLWindowsTable({
  windows,
  onSelectWindow,
  selectedWindow,
}: MLWindowsTableProps) {
  if (!windows || windows.length === 0) {
    return (
      <EmptyState
        title="No ML Windows"
        message="No 30-second IP windows available for scoring."
        icon={Brain}
      />
    );
  }

  return (
    <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-sans">
          <thead className="bg-[#ffffff] border-b border-[#e5e0d5] text-[#716c60] uppercase tracking-wider text-[11px]">
            <tr>
              <th className="py-3 px-4">Verdict</th>
              <th className="py-3 px-4">ML Score</th>
              <th className="py-3 px-4">Raw IF Score</th>
              <th className="py-3 px-4">Source IP</th>
              <th className="py-3 px-4">Window Start</th>
              <th className="py-3 px-4">Requests in 30s</th>
              <th className="py-3 px-4">Ground Truth</th>
              <th className="py-3 px-4 text-right">Inspect Features</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#eeeae1] text-[#464238]">
            {windows.map((w, idx) => {
              const isSelected =
                selectedWindow &&
                selectedWindow.ip === w.ip &&
                selectedWindow.window_start === w.window_start;

              const isAnomaly = w.is_anomalous;
              const reqCount = w.features?.request_count || w.event_ids?.length || 0;

              return (
                <tr
                  key={`${w.ip}-${w.window_start}-${idx}`}
                  onClick={() => onSelectWindow && onSelectWindow(w)}
                  onKeyDown={(event) => {
                    if ((event.key === "Enter" || event.key === " ") && onSelectWindow) {
                      event.preventDefault();
                      onSelectWindow(w);
                    }
                  }}
                  tabIndex={onSelectWindow ? 0 : undefined}
                  aria-selected={Boolean(isSelected)}
                  className={`cursor-pointer transition-colors ${
                    isSelected
                      ? "bg-purple-100/70 border-l-2 border-purple-500"
                      : "hover:bg-[#f4f1e8]"
                  }`}
                >
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span
                      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-none text-[11px] font-bold tracking-wider uppercase border ${
                        isAnomaly
                          ? "bg-red-500/10 text-red-700 border-red-500/30"
                          : "bg-emerald-500/10 text-emerald-700 border-emerald-500/30"
                      }`}
                    >
                      <span
                        className={`w-1.5 h-1.5 rounded-none ${
                          isAnomaly ? "bg-red-400" : "bg-emerald-400"
                        }`}
                      />
                      {w.prediction}
                    </span>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap font-bold text-sm">
                    <span
                      className={
                        w.ml_score >= 80
                          ? "text-red-700"
                          : w.ml_score >= 60
                          ? "text-orange-700"
                          : w.ml_score >= 50
                          ? "text-amber-800"
                          : "text-purple-800"
                      }
                    >
                      {w.ml_score.toFixed(1)}
                    </span>
                    <span className="text-[10px] text-[#716c60] font-normal">
                      {" "}
                      / 100
                    </span>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-[#635d51]">
                    {w.raw_score.toFixed(4)}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-amber-800 font-semibold">
                    {w.ip}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-[#716c60] text-[11px]">
                    {formatDateTime(w.window_start)}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-[#464238]">
                    {reqCount}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded-none font-sans uppercase font-bold tracking-wider ${
                        w.ground_truth === "NORMAL"
                          ? "text-emerald-700 bg-emerald-500/10"
                          : "text-amber-800 bg-amber-500/10"
                      }`}
                    >
                      {w.ground_truth}
                    </span>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        if (onSelectWindow) onSelectWindow(w);
                      }}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-none bg-[#ffffff] hover:bg-purple-500/20 text-purple-800 border border-[#e5e0d5] hover:border-purple-500/40 text-[11px] transition-colors"
                    >
                      <Sliders className="w-3 h-3" />
                      <span>Features</span>
                    </button>
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
