import React from "react";
import { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface KpiCardProps {
  title: string;
  value: string | number | null | undefined;
  subtext?: string;
  icon: LucideIcon;
  color?: "cyan" | "purple" | "red" | "orange" | "green" | "amber" | "emerald";
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
      border: "border-[#D5EAE5] hover:border-[#2EAF7D]",
      iconBg: "bg-[#EAF8F5] text-[#2EAF7D] border-[#D5EAE5]",
    },
    purple: {
      border: "border-[#D5EAE5] hover:border-[#3FD0C9]",
      iconBg: "bg-[#F2FBF9] text-[#02353C] border-[#D5EAE5]",
    },
    red: {
      border: "border-red-200 hover:border-red-400",
      iconBg: "bg-red-50 text-red-700 border-red-200",
    },
    orange: {
      border: "border-amber-200 hover:border-amber-400",
      iconBg: "bg-amber-50 text-amber-800 border-amber-200",
    },
    amber: {
      border: "border-amber-200 hover:border-amber-400",
      iconBg: "bg-amber-50 text-amber-800 border-amber-200",
    },
    green: {
      border: "border-[#D5EAE5] hover:border-[#2EAF7D]",
      iconBg: "bg-emerald-50 text-[#2EAF7D] border-emerald-200",
    },
    emerald: {
      border: "border-[#D5EAE5] hover:border-[#2EAF7D]",
      iconBg: "bg-emerald-50 text-[#2EAF7D] border-emerald-200",
    },
  }[color as string] || {
    border: "border-[#D5EAE5] hover:border-[#2EAF7D]",
    iconBg: "bg-[#EAF8F5] text-[#2EAF7D] border-[#D5EAE5]",
  };

  const displayValue =
    value === null || value === undefined
      ? "NO DATA"
      : typeof value === "number"
      ? value.toLocaleString()
      : value;

  return (
    <div
      className={cn(
        "relative bg-white border rounded-[4px] p-4 transition-all duration-200 shadow-sm",
        colorMap.border,
        className
      )}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] font-sans uppercase tracking-wider text-[#486966]">
          {title}
        </span>
        <div
          className={cn(
            "w-8 h-8 rounded-[2px] flex items-center justify-center border",
            colorMap.iconBg
          )}
        >
          <Icon className="w-4 h-4" />
        </div>
      </div>

      <div className="font-sans text-2xl font-bold tracking-tight text-[#02353C] my-1">
        {displayValue}
      </div>

      {subtext && (
        <div className="text-xs text-[#486966] truncate mt-1">{subtext}</div>
      )}
    </div>
  );
}

