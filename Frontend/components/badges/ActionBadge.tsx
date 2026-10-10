import React from "react";
import { cn, getActionStyle } from "@/lib/utils";

interface ActionBadgeProps {
  action: string | null | undefined;
  className?: string;
  size?: "sm" | "md" | "lg";
}

export function ActionBadge({ action, className, size = "md" }: ActionBadgeProps) {
  const act = (action || "ALLOW").toUpperCase();
  const style = getActionStyle(act);

  const sizeClass = {
    sm: "px-2 py-0.5 text-[11px]",
    md: "px-2.5 py-1 text-xs",
    lg: "px-3.5 py-1.5 text-sm",
  }[size];

  return (
    <span
      className={cn(
        "inline-flex items-center justify-center rounded-[2px] font-sans uppercase tracking-wider border font-semibold",
        sizeClass,
        style.bg,
        style.text,
        style.border,
        style.glow,
        className
      )}
    >
      {act}
    </span>
  );
}
