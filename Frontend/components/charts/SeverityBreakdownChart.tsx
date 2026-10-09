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
  CRITICAL: "#ef4444",
  HIGH: "#ab4f0b",
  MEDIUM: "#9b6208",
  LOW: "#22c55e",
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
        className="w-full bg-[#ffffff] rounded-none flex items-center justify-center text-xs font-sans text-[#716c60]"
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
                fill={COLORS[entry.name] || "#bd7b12"}
                stroke="#716c60"
                strokeWidth={2}
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: "#27251f",
              borderColor: "#ded7ca",
              borderRadius: "0",
              fontSize: "12px",
              fontFamily: "monospace",
              color: "#27251f",
            }}
          />
          <Legend
            verticalAlign="bottom"
            height={36}
            formatter={(value) => (
              <span className="text-xs font-sans text-[#716c60] mr-2">
                {value}
              </span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
