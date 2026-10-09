"use client";

import React, { useEffect, useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";
import { EmptyState } from "../cards/EmptyState";
import { BarChart3 } from "lucide-react";

interface ScoreDistributionChartProps {
  distribution: { range: string; count: number }[];
  height?: number;
  barColor?: string;
}

export function ScoreDistributionChart({
  distribution,
  height = 240,
  barColor = "#bd7b12",
}: ScoreDistributionChartProps) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  if (!distribution || distribution.length === 0) {
    return (
      <EmptyState
        title="No distribution data"
        message="Waiting for scored items."
        icon={BarChart3}
      />
    );
  }

  if (!mounted) {
    return (
      <div
        style={{ height }}
        className="w-full bg-[#ffffff] rounded-none flex items-center justify-center text-xs font-sans text-[#716c60]"
      >
        Loading distribution...
      </div>
    );
  }

  return (
    <div className="w-full h-full min-h-[200px]" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={distribution}
          margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#716c60" vertical={false} />
          <XAxis
            dataKey="range"
            stroke="#716c60"
            fontSize={10}
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
          <Bar dataKey="count" fill={barColor} radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
