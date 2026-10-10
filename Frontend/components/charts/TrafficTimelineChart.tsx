"use client";

import React, { useEffect, useState } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";
import { TrafficTimelinePoint } from "@/lib/types";
import { EmptyState } from "../cards/EmptyState";
import { Activity } from "lucide-react";

interface TrafficTimelineChartProps {
  data: TrafficTimelinePoint[];
  height?: number;
}

export function TrafficTimelineChart({
  data,
  height = 240,
}: TrafficTimelineChartProps) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  if (!data || data.length === 0) {
    return (
      <EmptyState
        title="No traffic timeline data"
        message="Waiting for API events to populate timeline."
        icon={Activity}
      />
    );
  }

  // Format data for chart display
  const chartData = data.map((d) => {
    let timeLabel = d.timestamp;
    try {
      const dt = new Date(d.timestamp);
      timeLabel = dt.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      });
    } catch {
      // keep raw string
    }
    return {
      time: timeLabel,
      requests: d.requests,
      errors: d.errors,
      avg_latency: d.avg_latency,
    };
  });

  if (!mounted) {
    return (
      <div
        style={{ height }}
        className="w-full bg-[#ffffff] rounded-none flex items-center justify-center text-xs font-sans text-[#716c60]"
      >
        Loading timeline...
      </div>
    );
  }

  return (
    <div className="w-full h-full min-h-[200px]" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={chartData}
          margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
        >
          <defs>
            <linearGradient id="reqGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#2EAF7D" stopOpacity={0.35} />
              <stop offset="95%" stopColor="#2EAF7D" stopOpacity={0.0} />
            </linearGradient>
            <linearGradient id="errGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#DC2626" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#DC2626" stopOpacity={0.0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#D5EAE5" vertical={false} />
          <XAxis
            dataKey="time"
            stroke="#486966"
            fontSize={10}
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
              borderRadius: "2px",
              fontSize: "12px",
              fontFamily: "monospace",
              color: "#02353C",
              boxShadow: "0 4px 12px rgba(2, 53, 60, 0.08)",
            }}
            labelStyle={{ color: "#486966", marginBottom: "4px" }}
            itemStyle={{ color: "#02353C" }}
          />
          <Area
            type="monotone"
            dataKey="requests"
            name="Requests"
            stroke="#2EAF7D"
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#reqGradient)"
          />
          <Area
            type="monotone"
            dataKey="errors"
            name="Errors (4xx/5xx)"
            stroke="#DC2626"
            strokeWidth={1.5}
            fillOpacity={1}
            fill="url(#errGradient)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>

  );
}
