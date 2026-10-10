"use client";

import React, { useEffect, useState } from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { EmptyState } from "../cards/EmptyState";
import { ShieldAlert } from "lucide-react";

interface SeverityBreakdownChartProps {
  distribution: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  height?: number;
}

const COLORS: Record<string, string> = {
  CRITICAL: "#DC2626",
  HIGH: "#D97706",
  MEDIUM: "#3FD0C9",
  LOW: "#2EAF7D",
};

export function SeverityBreakdownChart({
  distribution,
  height = 240,
}: SeverityBreakdownChartProps) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const data = [
    { name: "CRITICAL", value: distribution?.CRITICAL || 0 },
    { name: "HIGH", value: distribution?.HIGH || 0 },
    { name: "MEDIUM", value: distribution?.MEDIUM || 0 },
    { name: "LOW", value: distribution?.LOW || 0 },
  ].filter((item) => item.value > 0);

  if (!data || data.length === 0) {
    return (
      <EmptyState
        title="No security detections"
        message="No security detection severities to visualize."
        icon={ShieldAlert}
      />
    );
  }

  if (!mounted) {
    return (
      <div
        style={{ height }}
        className="w-full bg-white rounded-[4px] flex items-center justify-center text-xs font-sans text-[#486966]"
      >
        Loading breakdown...
      </div>
    );
  }

  return (
    <div className="w-full h-full min-h-[200px]" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            innerRadius="55%"
            outerRadius="80%"
            paddingAngle={3}
            dataKey="value"
          >
            {data.map((entry) => (
              <Cell
                key={`cell-${entry.name}`}
                fill={COLORS[entry.name] || "#2EAF7D"}
                stroke="#FFFFFF"
                strokeWidth={2}
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: "#FFFFFF",
              borderColor: "#D5EAE5",
              borderRadius: "2px",
              fontSize: "12px",
              fontFamily: "monospace",
              color: "#02353C",
              boxShadow: "0 4px 12px rgba(2, 53, 60, 0.08)",
            }}
          />
          <Legend
            verticalAlign="bottom"
            height={36}
            formatter={(value) => (
              <span className="text-[11px] font-sans text-[#02353C] uppercase font-semibold mr-2">
                {value}
              </span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

