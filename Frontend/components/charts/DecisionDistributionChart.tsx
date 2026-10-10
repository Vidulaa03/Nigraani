"use client";

import React, { useEffect, useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  CartesianGrid,
} from "recharts";
import { EmptyState } from "../cards/EmptyState";
import { Shield } from "lucide-react";

interface DecisionDistributionChartProps {
  distribution: {
    ALLOW: number;
    MONITOR: number;
    THROTTLE: number;
    BLOCK: number;
  };
  height?: number;
}

const ACTION_COLORS: Record<string, string> = {
  ALLOW: "#2EAF7D",
  MONITOR: "#3FD0C9",
  THROTTLE: "#D97706",
  BLOCK: "#DC2626",
};

export function DecisionDistributionChart({
  distribution,
  height = 240,
}: DecisionDistributionChartProps) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const data = [
    { name: "ALLOW", count: distribution?.ALLOW || 0 },
    { name: "MONITOR", count: distribution?.MONITOR || 0 },
    { name: "THROTTLE", count: distribution?.THROTTLE || 0 },
    { name: "BLOCK", count: distribution?.BLOCK || 0 },
  ];

  const total = data.reduce((acc, cur) => acc + cur.count, 0);

  if (total === 0) {
    return (
      <EmptyState
        title="No risk recommendations"
        message="Waiting for analyzer risk output."
        icon={Shield}
      />
    );
  }

  if (!mounted) {
    return (
      <div
        style={{ height }}
        className="w-full bg-[#FFFFFF] rounded-sm flex items-center justify-center text-xs font-sans text-[#486966]"
      >
        Loading decisions...
      </div>
    );
  }

  return (
    <div className="w-full h-full min-h-[200px]" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#D5EAE5" vertical={false} />
          <XAxis
            dataKey="name"
            stroke="#486966"
            fontSize={11}
            tickLine={false}
            axisLine={{ stroke: "#D5EAE5" }}
          />
          <YAxis
            stroke="#486966"
            fontSize={10}
            tickLine={false}
            axisLine={{ stroke: "#D5EAE5" }}
            allowDecimals={false}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "#FFFFFF",
              borderColor: "#D5EAE5",
              borderRadius: "4px",
              fontSize: "12px",
              fontFamily: "var(--font-geist-mono), monospace",
              color: "#02353C",
              boxShadow: "0 2px 8px rgba(2, 53, 60, 0.08)",
            }}
          />
          <Bar dataKey="count" radius={[3, 3, 0, 0]}>
            {data.map((entry) => (
              <Cell
                key={`bar-${entry.name}`}
                fill={ACTION_COLORS[entry.name] || "#2EAF7D"}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
