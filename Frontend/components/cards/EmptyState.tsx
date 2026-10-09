import React from "react";
import { LucideIcon, Inbox } from "lucide-react";
import { cn } from "@/lib/utils";

interface EmptyStateProps {
  title: string;
  message?: string;
  icon?: LucideIcon;
  className?: string;
}

export function EmptyState({
  title,
  message,
  icon: Icon = Inbox,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center p-8 text-center rounded-none bg-[#ffffff] border border-dashed border-[#e5e0d5]",
        className
      )}
    >
      <div className="w-10 h-10 rounded-none bg-[#ffffff] border border-[#e5e0d5] flex items-center justify-center text-[#716c60] mb-3">
        <Icon className="w-5 h-5" />
      </div>
      <h4 className="text-sm font-sans font-medium text-[#464238] mb-1">
        {title}
      </h4>
      {message && (
        <p className="text-xs text-[#716c60] max-w-sm">{message}</p>
      )}
    </div>
  );
}
