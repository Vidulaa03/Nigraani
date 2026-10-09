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
        className="w-full bg-[#ffffff] rounded-none flex items-center justify-center text-xs font-sans text-[#716c60]"
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
          <CartesianGrid strokeDasharray="3 3" stroke="#716c60" vertical={false} />
          <XAxis
            dataKey="time"
            stroke="#716c60"
            fontSize={10}
            tickLine={false}
            axisLine={{ stroke: "#716c60" }}
          />
          <YAxis
            domain={[0, 100]}
            stroke="#716c60"
            fontSize={10}
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
            formatter={(value: any, name: any, props: any) => [
              `Score: ${value} (IP: ${props.payload.ip})`,
              props.payload.isAnomalous ? "ANOMALY (raw < 0)" : "NORMAL",
            ]}
          />
          <ReferenceLine
            y={50}
            stroke="#9b6208"
            strokeDasharray="4 4"
            label={{
              value: "Decision Threshold (50)",
              fill: "#9b6208",
              fontSize: 10,
              position: "top",
            }}
          />
          <Line
            type="monotone"
            dataKey="score"
            name="ML Anomaly Score"
            stroke="#7058a3"
            strokeWidth={2}
            dot={(props: any) => {
              const isAnom = props.payload.isAnomalous;
              return (
                <circle
                  key={`dot-${props.cx}-${props.cy}`}
                  cx={props.cx}
                  cy={props.cy}
                  r={isAnom ? 4 : 2.5}
                  fill={isAnom ? "#ef4444" : "#7058a3"}
                  stroke={isAnom ? "#fecaca" : "#d8b4fe"}
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
