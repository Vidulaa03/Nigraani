import React from "react";
import { ShieldAlert, ShieldCheck, Shield } from "lucide-react";
import { ThreatPosture } from "@/lib/types";
import { ActionBadge } from "../badges/ActionBadge";
import { SeverityBadge } from "../badges/SeverityBadge";
import { cn } from "@/lib/utils";

interface ThreatPostureCardProps {
  posture: ThreatPosture | null | undefined;
  className?: string;
}

export function ThreatPostureCard({ posture, className }: ThreatPostureCardProps) {
  if (!posture) {
    return (
      <div
        className={cn(
          "relative bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5 flex flex-col justify-between",
          className
        )}
      >
        <div className="flex items-center justify-between mb-4">
          <span className="text-xs font-sans uppercase tracking-wider text-[#716c60]">
            Current Threat Posture
          </span>
          <Shield className="w-5 h-5 text-amber-800 opacity-60" />
        </div>
        <div className="py-6 text-center">
          <div className="font-sans text-lg font-bold text-amber-800">
            NO RISK DECISION
          </div>
          <p className="text-xs text-[#716c60] mt-1 font-sans">
            WAITING FOR ANALYZER OUTPUT
          </p>
        </div>
      </div>
    );
  }

  const { risk_score, risk_level, action, ip, reasons } = posture;

  // Determine accent style based on risk score
  const isCritical = risk_score >= 80;
  const isHigh = risk_score >= 60 && risk_score < 80;
  const isMedium = risk_score >= 30 && risk_score < 60;

  const borderColor = isCritical
    ? "border-red-500/40 shadow-[0_0_24px_rgba(239,68,68,0.12)]"
    : isHigh
    ? "border-orange-500/40 shadow-[0_0_24px_rgba(249,115,22,0.12)]"
    : isMedium
    ? "border-amber-500/30"
    : "border-emerald-500/30";

  const scoreColor = isCritical
    ? "text-red-700"
    : isHigh
    ? "text-orange-700"
    : isMedium
    ? "text-amber-800"
    : "text-emerald-700";

  return (
    <div
      className={cn(
        "relative bg-[#ffffff] border rounded-none p-5 flex flex-col justify-between transition-all",
        borderColor,
        className
      )}
    >
      <div>
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-sans uppercase tracking-wider text-[#716c60]">
            Current Threat Posture
          </span>
          {isCritical || isHigh ? (
            <ShieldAlert className="w-5 h-5 text-red-700" />
          ) : (
            <ShieldCheck className="w-5 h-5 text-emerald-700" />
          )}
        </div>

        <div className="flex items-baseline gap-2 my-2">
          <span className={cn("text-4xl font-sans font-extrabold tracking-tight", scoreColor)}>
            {risk_score}
          </span>
          <span className="text-sm font-sans text-[#716c60]">/ 100</span>
        </div>

        <div className="flex items-center gap-2 mt-3">
          <ActionBadge action={action} size="md" />
          <SeverityBadge band={risk_level} />
        </div>
      </div>

      <div className="mt-4 pt-3 border-t border-[#e5e0d5] text-xs">
        <div className="flex justify-between items-center text-[#716c60] font-sans text-[11px] mb-1">
          <span>Target IP:</span>
          <span className="text-[#464238]">{ip}</span>
        </div>
        {reasons && reasons.length > 0 && (
          <div className="text-[11px] text-[#716c60] truncate font-sans" title={reasons.join("; ")}>
            {reasons[0]}
          </div>
        )}
      </div>
    </div>
  );
}
