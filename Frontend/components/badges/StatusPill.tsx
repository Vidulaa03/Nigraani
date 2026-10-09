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
    ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]"
    : isWarn
    ? "bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.8)]"
    : "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]";

  const textColor = isOk
    ? "text-emerald-700"
    : isWarn
    ? "text-amber-800"
    : "text-red-700";

  const bgColor = isOk
    ? "bg-emerald-950/20 border-emerald-500/20"
    : isWarn
    ? "bg-amber-950/20 border-amber-500/20"
    : "bg-red-950/20 border-red-500/20";

  return (
    <div
      className={cn(
        "inline-flex items-center gap-2 px-2.5 py-1 rounded-none text-xs font-sans font-medium uppercase tracking-wider border",
        bgColor,
        textColor,
        className
      )}
    >
      <span className={cn("w-2 h-2 rounded-none", dotColor)} />
      {label || status.toUpperCase()}
    </div>
  );
}
