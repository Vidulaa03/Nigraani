"use client";

import React, { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldAlert, Flame, X, ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import { InAppNotification } from "@/lib/types";

export function NotificationToast() {
  const router = useRouter();
  const [activeToast, setActiveToast] = useState<InAppNotification | null>(null);
  const seenIdsRef = useRef<Set<number>>(new Set());
  const initialLoadRef = useRef(true);

  const checkForNewNotifications = async () => {
    try {
      const res = await api.getNotifications({ limit: 5, unreadOnly: true });
      const items = res.notifications || [];

      if (initialLoadRef.current) {
        // Mark all existing unread notifications as already seen on initial mount
        // so we don't spam toasts when opening the page
        items.forEach((n) => seenIdsRef.current.add(n.notification_id));
        initialLoadRef.current = false;
        return;
      }

      // Check if there is an unread notification that we haven't shown yet
      for (const notif of items) {
        if (!seenIdsRef.current.has(notif.notification_id)) {
          seenIdsRef.current.add(notif.notification_id);
          setActiveToast(notif);
          break; // Show one toast at a time
        }
      }
    } catch {
      // Gracefully handle offline backend
    }
  };

  useEffect(() => {
    checkForNewNotifications();
    const interval = setInterval(checkForNewNotifications, 6000);
    return () => clearInterval(interval);
  }, []);

  // Auto-dismiss toast after 8 seconds
  useEffect(() => {
    if (activeToast) {
      const timer = setTimeout(() => {
        setActiveToast(null);
      }, 8000);
      return () => clearTimeout(timer);
    }
  }, [activeToast]);

  if (!activeToast) return null;

  const isCritical = activeToast.severity_band === "CRITICAL";

  return (
    <div
      role="alert"
      aria-live="assertive"
      className="fixed bottom-5 right-5 z-50 max-w-sm sm:max-w-md w-full bg-white border border-[#D5EAE5] rounded-[4px] shadow-2xl p-4 transition-all animate-in fade-in slide-in-from-bottom-3 duration-200"
      style={{
        borderLeft: isCritical ? "4px solid #DC2626" : "4px solid #2EAF7D",
      }}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2.5">
          <div
            className={`p-1.5 rounded-[2px] shrink-0 ${
              isCritical ? "bg-red-50 text-red-700" : "bg-emerald-50 text-emerald-700"
            }`}
          >
            {isCritical ? (
              <Flame className="w-4 h-4" />
            ) : (
              <ShieldAlert className="w-4 h-4" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-[#02353C]">
                {activeToast.severity_band} Incident Alert
              </span>
              <span className="text-[10px] font-mono text-[#486966]">
                Score: {activeToast.severity}/100
              </span>
            </div>
            <h4 className="text-xs font-semibold text-[#02353C] mt-0.5">
              {activeToast.title}
            </h4>
            <p className="text-[11px] text-[#486966] mt-1 line-clamp-2 leading-relaxed">
              {activeToast.message}
            </p>
          </div>
        </div>

        <button
          onClick={() => setActiveToast(null)}
          className="text-[#486966] hover:text-[#02353C] p-1 rounded-[2px]"
          aria-label="Dismiss alert"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="mt-3 pt-2.5 border-t border-[#D5EAE5] flex items-center justify-between">
        <span className="text-[10px] font-mono text-[#02353C]/70">
          Incident: {activeToast.incident_id}
        </span>
        <button
          onClick={() => {
            setActiveToast(null);
            router.push("/threats");
          }}
          className="inline-flex items-center gap-1 text-xs font-semibold text-[#2EAF7D] hover:text-[#02353C] transition-colors"
        >
          <span>Investigate in SOC</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}
