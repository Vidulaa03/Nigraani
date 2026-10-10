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
          "relative bg-white border border-[#D5EAE5] rounded-[4px] p-5 flex flex-col justify-between shadow-sm",
          className
        )}
      >
        <div className="flex items-center justify-between mb-4">
          <span className="text-xs font-sans uppercase tracking-wider text-[#486966]">
            Current Threat Posture
          </span>
          <Shield className="w-5 h-5 text-[#2EAF7D] opacity-60" />
        </div>
        <div className="py-6 text-center">
          <div className="font-sans text-base font-bold text-[#02353C]">
            NO ACTIVE ABUSE THREAT
          </div>
          <p className="text-xs text-[#486966] mt-1 font-sans">
            Baseline traffic monitoring active
          </p>
        </div>
      </div>
    );
  }

  const { risk_score, risk_level, action, ip, reasons } = posture;

  const isCritical = risk_score >= 80;
  const isHigh = risk_score >= 60 && risk_score < 80;
  const isMedium = risk_score >= 30 && risk_score < 60;

  const borderColor = isCritical
    ? "border-red-300"
    : isHigh
    ? "border-amber-300"
    : isMedium
    ? "border-[#D5EAE5]"
    : "border-[#D5EAE5]";

  const scoreColor = isCritical
    ? "text-red-700"
    : isHigh
    ? "text-amber-700"
    : isMedium
    ? "text-[#02353C]"
    : "text-[#2EAF7D]";

  return (
    <div
      className={cn(
        "relative bg-white border rounded-[4px] p-5 flex flex-col justify-between transition-all shadow-sm",
        borderColor,
        className
      )}
    >
      <div>
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-sans uppercase tracking-wider text-[#486966]">
            Current Threat Posture
          </span>
          {isCritical || isHigh ? (
            <ShieldAlert className="w-5 h-5 text-red-600" />
          ) : (
            <ShieldCheck className="w-5 h-5 text-[#2EAF7D]" />
          )}
        </div>

        <div className="flex items-baseline gap-2 my-2">
          <span className={cn("text-4xl font-sans font-extrabold tracking-tight", scoreColor)}>
            {risk_score}
          </span>
          <span className="text-sm font-sans text-[#486966]">/ 100</span>
        </div>

        <div className="flex items-center gap-2 mt-3">
          <ActionBadge action={action} size="md" />
          <SeverityBadge band={risk_level} />
        </div>
      </div>

      <div className="mt-4 pt-3 border-t border-[#D5EAE5] text-xs">
        <div className="flex justify-between items-center text-[#486966] font-sans text-[11px] mb-1">
          <span>Target IP:</span>
          <span className="text-[#02353C] font-mono font-medium">{ip}</span>
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
