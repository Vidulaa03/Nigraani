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
              <stop offset="5%" stopColor="#bd7b12" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#bd7b12" stopOpacity={0.0} />
            </linearGradient>
            <linearGradient id="errGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.5} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#716c60" vertical={false} />
          <XAxis
            dataKey="time"
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
              backgroundColor: "#ffffff",
              borderColor: "#ded7ca",
              borderRadius: "0",
              fontSize: "12px",
              fontFamily: "monospace",
              color: "#27251f",
              boxShadow: "0 6px 18px rgba(39, 37, 31, 0.12)",
            }}
            labelStyle={{ color: "#716c60", marginBottom: "4px" }}
            itemStyle={{ color: "#27251f" }}
          />
          <Area
            type="monotone"
            dataKey="requests"
            name="Requests"
            stroke="#bd7b12"
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#reqGradient)"
          />
          <Area
            type="monotone"
            dataKey="errors"
            name="Errors (4xx/5xx)"
            stroke="#ef4444"
            strokeWidth={1.5}
            fillOpacity={1}
            fill="url(#errGradient)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
