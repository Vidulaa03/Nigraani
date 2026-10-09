import React from "react";
import { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface KpiCardProps {
  title: string;
  value: string | number | null | undefined;
  subtext?: string;
  icon: LucideIcon;
  color?: "cyan" | "purple" | "red" | "orange" | "green" | "amber";
  className?: string;
}

export function KpiCard({
  title,
  value,
  subtext,
  icon: Icon,
  color = "cyan",
  className,
}: KpiCardProps) {
  const colorMap = {
    cyan: {
      border: "border-amber-500/20 hover:border-amber-500/40",
      iconBg: "bg-amber-500/10 text-amber-800 border-amber-500/20",
      glow: "hover:shadow-[0_0_20px_rgba(56,189,248,0.06)]",
    },
    purple: {
      border: "border-purple-500/20 hover:border-purple-500/40",
      iconBg: "bg-purple-500/10 text-purple-800 border-purple-500/20",
      glow: "hover:shadow-[0_0_20px_rgba(168,85,247,0.06)]",
    },
    red: {
      border: "border-red-500/20 hover:border-red-500/40",
      iconBg: "bg-red-500/10 text-red-700 border-red-500/20",
      glow: "hover:shadow-[0_0_20px_rgba(239,68,68,0.06)]",
    },
    orange: {
      border: "border-orange-500/20 hover:border-orange-500/40",
      iconBg: "bg-orange-500/10 text-orange-700 border-orange-500/20",
      glow: "hover:shadow-[0_0_20px_rgba(249,115,22,0.06)]",
    },
    amber: {
      border: "border-amber-500/20 hover:border-amber-500/40",
      iconBg: "bg-amber-500/10 text-amber-800 border-amber-500/20",
      glow: "hover:shadow-[0_0_20px_rgba(245,158,11,0.06)]",
    },
    green: {
      border: "border-emerald-500/20 hover:border-emerald-500/40",
      iconBg: "bg-emerald-500/10 text-emerald-700 border-emerald-500/20",
      glow: "hover:shadow-[0_0_20px_rgba(34,197,94,0.06)]",
    },
  }[color];

  const displayValue =
    value === null || value === undefined
      ? "NO DATA"
      : typeof value === "number"
      ? value.toLocaleString()
      : value;

  return (
    <div
      className={cn(
        "relative bg-[#ffffff] border rounded-none p-4 transition-all duration-200",
        colorMap.border,
        colorMap.glow,
        className
      )}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] font-sans uppercase tracking-wider text-[#716c60]">
          {title}
        </span>
        <div
          className={cn(
            "w-8 h-8 rounded-none flex items-center justify-center border",
            colorMap.iconBg
          )}
        >
          <Icon className="w-4 h-4" />
        </div>
      </div>

      <div className="font-sans text-2xl font-bold tracking-tight text-[#27251f] my-1">
        {displayValue}
      </div>

      {subtext && (
        <div className="text-xs text-[#716c60] truncate mt-1">{subtext}</div>
      )}
    </div>
  );
}
