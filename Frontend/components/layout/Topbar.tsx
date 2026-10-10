"use client";

import React, { useEffect, useState } from "react";
import { RefreshCw, Activity, Menu } from "lucide-react";
import { formatTimeAgo } from "@/lib/utils";
import { StatusPill } from "../badges/StatusPill";
import { useVisibilityInterval } from "@/lib/useVisibilityInterval";

import { NotificationBell } from "../notifications/NotificationBell";

interface TopbarProps {
  title: string;
  subtitle?: string;
  onRefresh: () => void;
  isRefreshing?: boolean;
  lastUpdated: Date | null;
  backendOnline: boolean;
  backendChecking?: boolean;
  onMenu?: () => void;
}

export function Topbar({
  title,
  subtitle,
  onRefresh,
  isRefreshing = false,
  lastUpdated,
  backendOnline,
  backendChecking = false,
  onMenu,
}: TopbarProps) {
  const [, setTick] = useState(0);

  useVisibilityInterval(() => setTick((t) => t + 1), 30000);

  return (
    <header className="min-h-16 px-4 sm:px-6 lg:px-8 border-b border-[#D5EAE5] bg-[#FFFFFF]/95 backdrop-blur-md flex items-center justify-between sticky top-0 z-20 gap-3">
      <button
        id="navigation-menu"
        onClick={onMenu}
        className="rounded-[2px] border border-[#D5EAE5] bg-white p-2 text-[#486966] hover:bg-[#F2FBF9] md:hidden"
        aria-label="Open navigation"
      >
        <Menu className="h-4 w-4 text-[#02353C]" />
      </button>

      {/* Page Title & Subtitle */}
      <div className="min-w-0 flex-1">
        <h1 className="text-sm sm:text-base font-bold font-sans tracking-tight text-[#02353C] flex items-center gap-2 truncate">
          {title}
        </h1>
        {subtitle && (
          <p className="hidden sm:block text-xs text-[#486966] font-sans mt-0.5 truncate">
            {subtitle}
          </p>
        )}
      </div>

      {/* Status & Actions */}
      <div className="flex items-center gap-2 sm:gap-3.5 shrink-0">
        {/* Persistent In-App Notification Bell */}
        <NotificationBell />

        {/* System Status Pill */}
        <StatusPill
          status={backendChecking ? "waiting" : backendOnline ? "online" : "offline"}
          label={backendChecking ? "CONNECTING" : backendOnline ? "SYSTEM LIVE" : "BACKEND OFFLINE"}
        />

        {/* Last updated indicator */}
        <div className="hidden sm:flex items-center gap-1.5 text-xs font-sans text-[#486966]">
          <Activity className="w-3.5 h-3.5 text-[#2EAF7D]" />
          <span>Updated: {formatTimeAgo(lastUpdated)}</span>
        </div>

        {/* Manual Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-[2px] bg-white hover:bg-[#F2FBF9] border border-[#D5EAE5] hover:border-[#2EAF7D] text-xs font-sans text-[#02353C] transition-all disabled:opacity-50"
          title="Refresh telemetry now"
        >
          <RefreshCw
            className={`w-3.5 h-3.5 text-[#2EAF7D] ${
              isRefreshing ? "animate-spin" : ""
            }`}
          />
          <span className="hidden sm:inline">Refresh</span>
        </button>
      </div>
    </header>
  );
}

