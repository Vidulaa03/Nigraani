"use client";

import React, { useEffect, useState } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
  CartesianGrid,
} from "recharts";
import { EmptyState } from "../cards/EmptyState";
import { Brain } from "lucide-react";

interface MLAnomalyTimelineChartProps {
  timeline: {
    window_start: string;
    window_end: string;
    ip: string;
    ml_score: number;
    raw_score: number;
    is_anomalous: boolean;
  }[];
  height?: number;
}

export function MLAnomalyTimelineChart({
  timeline,
  height = 260,
}: MLAnomalyTimelineChartProps) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  if (!timeline || timeline.length === 0) {
    return (
      <EmptyState
        title="No ML window telemetry"
        message="Waiting for 30s IP windows with ≥3 requests to compute Isolation Forest anomaly scores."
        icon={Brain}
      />
    );
  }

  const chartData = timeline.map((item, idx) => {
    let timeLabel = `W${idx + 1}`;
    try {
      const dt = new Date(item.window_start);
      timeLabel = dt.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      });
    } catch {
      // fallback
    }

    return {
      time: timeLabel,
      score: item.ml_score,
      ip: item.ip,
      raw: item.raw_score,
      isAnomalous: item.is_anomalous,
    };
  });

  if (!mounted) {
    return (
      <div
        style={{ height }}
        className="w-full bg-[#FFFFFF] rounded-sm flex items-center justify-center text-xs font-sans text-[#486966]"
      >
        Loading ML timeline...
      </div>
    );
  }

  return (
    <div className="w-full h-full min-h-[220px]" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart
          data={chartData}
          margin={{ top: 15, right: 15, left: -20, bottom: 0 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#D5EAE5" vertical={false} />
          <XAxis
            dataKey="time"
            stroke="#486966"
            fontSize={10}
            tickLine={false}
            axisLine={{ stroke: "#D5EAE5" }}
          />
          <YAxis
            domain={[0, 100]}
            stroke="#486966"
            fontSize={10}
            tickLine={false}
            axisLine={{ stroke: "#D5EAE5" }}
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
            formatter={(value: any, name: any, props: any) => [
              `Score: ${value} (IP: ${props.payload.ip})`,
              props.payload.isAnomalous ? "ANOMALY (raw < 0)" : "NORMAL",
            ]}
          />
          <ReferenceLine
            y={50}
            stroke="#D97706"
            strokeDasharray="4 4"
            label={{
              value: "Decision Threshold (50)",
              fill: "#D97706",
              fontSize: 10,
              position: "top",
            }}
          />
          <Line
            type="monotone"
            dataKey="score"
            name="ML Anomaly Score"
            stroke="#2EAF7D"
            strokeWidth={2}
            dot={(props: any) => {
              const isAnom = props.payload.isAnomalous;
              return (
                <circle
                  key={`dot-${props.cx}-${props.cy}`}
                  cx={props.cx}
                  cy={props.cy}
                  r={isAnom ? 4 : 2.5}
                  fill={isAnom ? "#DC2626" : "#2EAF7D"}
                  stroke={isAnom ? "#FEE2E2" : "#D5EAE5"}
                  strokeWidth={1}
                />
              );
            }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
