"use client";

import React, { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Bell,
  Check,
  CheckCheck,
  ShieldAlert,
  Flame,
  AlertTriangle,
  Info,
  ExternalLink,
  X,
} from "lucide-react";
import { api } from "@/lib/api";
import { InAppNotification } from "@/lib/types";
import { formatTimeAgo } from "@/lib/utils";
import { SeverityBadge } from "../badges/SeverityBadge";

interface NotificationBellProps {
  onNotificationClick?: (notification: InAppNotification) => void;
}

export function NotificationBell({ onNotificationClick }: NotificationBellProps) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [notifications, setNotifications] = useState<InAppNotification[]>([]);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<"ALL" | "UNREAD" | "CRITICAL">("ALL");
  const panelRef = useRef<HTMLDivElement>(null);

  const fetchUnreadCount = async () => {
    try {
      const res = await api.getUnreadCount();
      setUnreadCount(res.unread_count || 0);
    } catch {
      // Backend offline or error handled gracefully
    }
  };

  const fetchList = async () => {
    setLoading(true);
    try {
      const res = await api.getNotifications({
        limit: 25,
        unreadOnly: filter === "UNREAD",
        severityBand: filter === "CRITICAL" ? "CRITICAL" : undefined,
      });
      setNotifications(res.notifications || []);
      setUnreadCount(res.unread_count || 0);
    } catch {
      // Handled
    } finally {
      setLoading(false);
    }
  };

  // Poll unread count every 8 seconds
  useEffect(() => {
    fetchUnreadCount();
    const interval = setInterval(fetchUnreadCount, 8000);
    return () => clearInterval(interval);
  }, []);

  // Fetch list whenever opened or filter changed
  useEffect(() => {
    if (open) {
      fetchList();
    }
  }, [open, filter]);

  // Click outside to close
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (panelRef.current && !panelRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    if (open) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [open]);

  const handleMarkAsRead = async (e: React.MouseEvent, notif: InAppNotification) => {
    e.stopPropagation();
    try {
      await api.markNotificationRead(notif.notification_id);
      setNotifications((prev) =>
        prev.map((item) =>
          item.notification_id === notif.notification_id
            ? { ...item, is_read: true }
            : item
        )
      );
      setUnreadCount((prev) => Math.max(0, prev - 1));
    } catch {
      // Handled
    }
  };

  const handleMarkAllRead = async () => {
    try {
      await api.markAllNotificationsRead();
      setNotifications((prev) => prev.map((item) => ({ ...item, is_read: true })));
      setUnreadCount(0);
    } catch {
      // Handled
    }
  };

  const handleItemClick = async (notif: InAppNotification) => {
    if (!notif.is_read) {
      try {
        await api.markNotificationRead(notif.notification_id);
        setUnreadCount((prev) => Math.max(0, prev - 1));
      } catch {
        // Handled
      }
    }
    setOpen(false);
    if (onNotificationClick) {
      onNotificationClick(notif);
    } else {
      // Navigate to threat intelligence / incidents
      router.push("/threats");
    }
  };

  const getSeverityIcon = (band: string) => {
    switch (band) {
      case "CRITICAL":
        return <Flame className="w-3.5 h-3.5 text-red-600 shrink-0" />;
      case "HIGH":
        return <ShieldAlert className="w-3.5 h-3.5 text-amber-600 shrink-0" />;
      case "MEDIUM":
        return <AlertTriangle className="w-3.5 h-3.5 text-emerald-600 shrink-0" />;
      default:
        return <Info className="w-3.5 h-3.5 text-teal-600 shrink-0" />;
    }
  };

  return (
    <div className="relative" ref={panelRef}>
      {/* Bell Button */}
      <button
        onClick={() => setOpen((prev) => !prev)}
        className="relative p-2 rounded-[2px] bg-white hover:bg-[#F2FBF9] border border-[#D5EAE5] text-[#02353C] transition-colors focus:outline-none focus:ring-1 focus:ring-[#2EAF7D]"
        aria-label="Security notifications"
        title="View incident alerts"
      >
        <Bell className="w-4 h-4 text-[#02353C]" />
        {unreadCount > 0 && (
          <span className="absolute -top-1 -right-1 flex items-center justify-center min-w-[18px] h-[18px] px-1 text-[10px] font-bold font-mono text-white bg-red-600 rounded-[2px] shadow-sm">
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        )}
      </button>

      {/* Flyout Panel */}
      {open && (
        <div className="absolute right-0 mt-2 w-80 sm:w-96 bg-white border border-[#D5EAE5] rounded-[4px] shadow-xl z-50 overflow-hidden flex flex-col max-h-[520px]">
          {/* Header */}
          <div className="p-3.5 border-b border-[#D5EAE5] bg-[#F2FBF9] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-[#02353C]">
                Security Alerts
              </span>
              {unreadCount > 0 && (
                <span className="px-1.5 py-0.5 text-[10px] font-bold font-mono bg-red-100 text-red-800 border border-red-200 rounded-[2px]">
                  {unreadCount} UNREAD
                </span>
              )}
            </div>

            <div className="flex items-center gap-2">
              {unreadCount > 0 && (
                <button
                  onClick={handleMarkAllRead}
                  className="text-[11px] font-medium text-[#2EAF7D] hover:text-[#02353C] flex items-center gap-1 transition-colors"
                  title="Mark all alerts as read"
                >
                  <CheckCheck className="w-3.5 h-3.5" />
                  <span>Mark all read</span>
                </button>
              )}
              <button
                onClick={() => setOpen(false)}
                className="text-[#486966] hover:text-[#02353C] p-0.5 rounded-[2px]"
                aria-label="Close notifications panel"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Filter Bar */}
          <div className="px-3 py-2 border-b border-[#D5EAE5] bg-white flex items-center gap-1.5 text-xs">
            <button
              onClick={() => setFilter("ALL")}
              className={`px-2.5 py-1 text-[11px] font-medium rounded-[2px] transition-colors ${
                filter === "ALL"
                  ? "bg-[#02353C] text-white"
                  : "bg-[#F2FBF9] text-[#486966] hover:text-[#02353C] border border-[#D5EAE5]"
              }`}
            >
              All Alerts
            </button>
            <button
              onClick={() => setFilter("UNREAD")}
              className={`px-2.5 py-1 text-[11px] font-medium rounded-[2px] transition-colors ${
                filter === "UNREAD"
                  ? "bg-[#02353C] text-white"
                  : "bg-[#F2FBF9] text-[#486966] hover:text-[#02353C] border border-[#D5EAE5]"
              }`}
            >
              Unread ({unreadCount})
            </button>
            <button
              onClick={() => setFilter("CRITICAL")}
              className={`px-2.5 py-1 text-[11px] font-medium rounded-[2px] transition-colors ${
                filter === "CRITICAL"
                  ? "bg-[#02353C] text-white"
                  : "bg-[#F2FBF9] text-[#486966] hover:text-[#02353C] border border-[#D5EAE5]"
              }`}
            >
              Critical
            </button>
          </div>

          {/* Notifications Scroll List */}
          <div className="overflow-y-auto divide-y divide-[#D5EAE5] flex-1">
            {loading && notifications.length === 0 ? (
              <div className="p-8 text-center text-xs text-[#486966]">
                Loading alerts...
              </div>
            ) : notifications.length === 0 ? (
              <div className="p-8 text-center">
                <Check className="w-6 h-6 text-[#2EAF7D] mx-auto mb-2 opacity-80" />
                <p className="text-xs font-medium text-[#02353C]">No alerts found</p>
                <p className="text-[11px] text-[#486966] mt-0.5">
                  {filter === "UNREAD"
                    ? "All incidents have been reviewed."
                    : "No security incident alerts recorded."}
                </p>
              </div>
            ) : (
              notifications.map((notif) => (
                <div
                  key={notif.notification_id}
                  onClick={() => handleItemClick(notif)}
                  className={`p-3 text-left transition-colors cursor-pointer group hover:bg-[#F2FBF9] ${
                    !notif.is_read ? "bg-[#F8FEFD]" : "bg-white"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-1.5 min-w-0">
                      {getSeverityIcon(notif.severity_band)}
                      <span className="text-xs font-semibold text-[#02353C] truncate">
                        {notif.title}
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className="text-[10px] text-[#486966] font-mono">
                        {formatTimeAgo(new Date(notif.created_at))}
                      </span>
                      {!notif.is_read && (
                        <button
                          onClick={(e) => handleMarkAsRead(e, notif)}
                          className="text-[#486966] hover:text-[#2EAF7D] p-0.5 rounded-[2px]"
                          title="Mark read"
                        >
                          <Check className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>

                  <p className="text-[11px] text-[#486966] mt-1 leading-snug line-clamp-2">
                    {notif.message}
                  </p>

                  <div className="mt-2 flex items-center justify-between text-[10px]">
                    <span className="font-mono text-[#02353C]/70">
                      ID: {notif.incident_id}
                    </span>
                    <span className="inline-flex items-center gap-1 text-[#2EAF7D] font-medium group-hover:underline">
                      Investigate <ExternalLink className="w-2.5 h-2.5" />
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Footer */}
          <div className="p-2 border-t border-[#D5EAE5] bg-[#F2FBF9] text-center">
            <button
              onClick={() => {
                setOpen(false);
                router.push("/threats");
              }}
              className="text-xs font-semibold text-[#02353C] hover:text-[#2EAF7D] transition-colors"
            >
              View Full Incident Intelligence &rarr;
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
