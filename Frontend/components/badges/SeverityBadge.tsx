import React from "react";
import { cn, getSeverityStyle } from "@/lib/utils";

interface SeverityBadgeProps {
  band: string | null | undefined;
  score?: number | null;
  className?: string;
}

export function SeverityBadge({ band, score, className }: SeverityBadgeProps) {
  const style = getSeverityStyle(band);
  const displayBand = (band || "LOW").toUpperCase();

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-[2px] text-xs font-semibold uppercase tracking-wider border",
        style.bg,
        style.text,
        style.border,
        className
      )}
    >
      <span className={cn("w-1.5 h-1.5 rounded-full", style.dot)} />
      {displayBand}
      {score !== undefined && score !== null ? (
        <span className="opacity-70 font-sans text-[11px]">({score})</span>
      ) : null}
    </span>
  );
}
