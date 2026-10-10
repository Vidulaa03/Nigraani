import React from "react";
import { cn } from "@/lib/utils";

interface StatusPillProps {
  status: "online" | "healthy" | "active" | "connected" | "degraded" | "waiting" | "offline" | "error" | "unavailable";
  label?: string;
  className?: string;
}

export function StatusPill({ status, label, className }: StatusPillProps) {
  const isOk = ["online", "healthy", "active", "connected"].includes(status);
  const isWarn = ["degraded", "waiting"].includes(status);

  const dotColor = isOk
    ? "bg-[#2EAF7D]"
    : isWarn
    ? "bg-amber-500"
    : "bg-red-600";

  const textColor = isOk
    ? "text-emerald-800"
    : isWarn
    ? "text-amber-800"
    : "text-red-700";

  const bgColor = isOk
    ? "bg-emerald-50 border-emerald-200"
    : isWarn
    ? "bg-amber-50 border-amber-200"
    : "bg-red-50 border-red-200";

  return (
    <div
      className={cn(
        "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-[2px] text-[11px] font-sans font-semibold uppercase tracking-wider border",
        bgColor,
        textColor,
        className
      )}
    >
      <span className={cn("w-1.5 h-1.5 rounded-full", dotColor)} />
      {label || status.toUpperCase()}
    </div>
  );
}

