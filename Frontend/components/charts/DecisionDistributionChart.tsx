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
  ALLOW: "#22c55e",
  MONITOR: "#9b6208",
  THROTTLE: "#ab4f0b",
  BLOCK: "#ef4444",
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
        className="w-full bg-[#ffffff] rounded-none flex items-center justify-center text-xs font-sans text-[#716c60]"
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
          <CartesianGrid strokeDasharray="3 3" stroke="#716c60" vertical={false} />
          <XAxis
            dataKey="name"
            stroke="#716c60"
            fontSize={11}
            tickLine={false}
            axisLine={{ stroke: "#716c60" }}
          />
          <YAxis
            stroke="#716c60"
            fontSize={10}
            tickLine={false}
            axisLine={{ stroke: "#716c60" }}
            allowDecimals={false}
          />
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
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {data.map((entry) => (
              <Cell
                key={`bar-${entry.name}`}
                fill={ACTION_COLORS[entry.name] || "#bd7b12"}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
