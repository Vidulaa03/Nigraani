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
import { Sliders } from "lucide-react";

interface FeatureImportanceChartProps {
  features: Record<string, number>;
  height?: number;
}

export function FeatureImportanceChart({
  features,
  height = 260,
}: FeatureImportanceChartProps) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  if (!features || Object.keys(features).length === 0) {
    return (
      <EmptyState
        title="No features available"
        message="Select a behavioral window to inspect its 8 features."
        icon={Sliders}
      />
    );
  }

  const data = Object.entries(features).map(([name, val]) => ({
    feature: name,
    value: Number(val),
  }));

  if (!mounted) {
    return (
      <div
        style={{ height }}
        className="w-full bg-[#ffffff] rounded-none flex items-center justify-center text-xs font-sans text-[#716c60]"
      >
        Loading feature profile...
      </div>
    );
  }

  return (
    <div className="w-full h-full min-h-[220px]" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 10, right: 20, left: 110, bottom: 0 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#716c60" horizontal={false} />
          <XAxis
            type="number"
            stroke="#716c60"
            fontSize={10}
            tickLine={false}
            axisLine={{ stroke: "#716c60" }}
          />
          <YAxis
            type="category"
            dataKey="feature"
            stroke="#716c60"
            fontSize={11}
            fontFamily="monospace"
            tickLine={false}
            axisLine={{ stroke: "#716c60" }}
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
          <Bar dataKey="value" fill="#a78bfa" radius={[0, 4, 4, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
