import React from "react";
import {
  Globe,
  ShieldAlert,
  Brain,
  Sliders,
  CheckCircle,
  AlertOctagon,
  PhoneCall,
  BellRing,
} from "lucide-react";
import { InvestigationLifecycleStage } from "@/lib/types";
import { cn } from "@/lib/utils";

interface InvestigationStepperProps {
  lifecycle: InvestigationLifecycleStage[];
}

export function InvestigationStepper({ lifecycle }: InvestigationStepperProps) {
  const getStageIcon = (stageNum: number, status: string) => {
    switch (stageNum) {
      case 1:
        return <Globe className="w-4 h-4 text-[#2EAF7D]" />;
      case 2:
        return status === "FLAGGED" ? (
          <ShieldAlert className="w-4 h-4 text-[#EA580C]" />
        ) : (
          <CheckCircle className="w-4 h-4 text-[#2EAF7D]" />
        );
      case 3:
        return status === "ANOMALOUS" ? (
          <Brain className="w-4 h-4 text-[#DC2626]" />
        ) : (
          <Brain className="w-4 h-4 text-[#2EAF7D]" />
        );
      case 4:
        return <Sliders className="w-4 h-4 text-[#3FD0C9]" />;
      case 5:
        return status === "BLOCK" ? (
          <AlertOctagon className="w-4 h-4 text-[#DC2626]" />
        ) : (
          <CheckCircle className="w-4 h-4 text-[#2EAF7D]" />
        );
      case 6:
        return status === "CALL_DISPATCHED" || status === "COMPLETED" || status === "INITIATED" || status === "QUEUED" ? (
          <PhoneCall className="w-4 h-4 text-[#2EAF7D]" />
        ) : status === "NOT_TRIGGERED" ? (
          <BellRing className="w-4 h-4 text-[#486966]" />
        ) : (
          <PhoneCall className="w-4 h-4 text-[#EA580C]" />
        );
      default:
        return <Globe className="w-4 h-4 text-[#2EAF7D]" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const s = status.toUpperCase();
    if (s === "BLOCK" || s === "CRITICAL" || s === "FAILED")
      return "bg-[#DC2626]/10 text-[#DC2626] border-[#DC2626]/30";
    if (s === "FLAGGED" || s === "THROTTLE" || s === "HIGH")
      return "bg-[#EA580C]/10 text-[#EA580C] border-[#EA580C]/30";
    if (s === "ANOMALOUS" || s === "MONITOR" || s === "MEDIUM")
      return "bg-[#D97706]/10 text-[#D97706] border-[#D97706]/30";
    if (s === "NOT_TRIGGERED" || s === "STANDBY")
      return "bg-[#F2FBF9] text-[#486966] border-[#D5EAE5]";
    return "bg-[#2EAF7D]/10 text-[#02353C] border-[#2EAF7D]/30";
  };

  return (
    <div className="bg-[#FFFFFF] border border-[#D5EAE5] rounded-sm p-5 mb-6 shadow-sm">
      <div className="text-xs font-sans uppercase tracking-wider text-[#486966] mb-4 font-semibold">
        Pipeline Analysis Flow: Ingestion &rarr; Detections &rarr; Machine Learning &rarr; Risk Engine &rarr; Decision &rarr; Voice Alerting
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 relative">
        {lifecycle.map((stage) => {
          return (
            <div
              key={stage.stage}
              className="relative flex flex-col justify-between p-3.5 rounded-sm bg-[#FFFFFF] border border-[#D5EAE5] hover:border-[#2EAF7D]/40 transition-all"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="w-7 h-7 rounded-sm bg-[#F2FBF9] border border-[#D5EAE5] flex items-center justify-center">
                    {getStageIcon(stage.stage, stage.status)}
                  </div>
                  <span className="text-[10px] font-mono text-[#486966]">
                    0{stage.stage}
                  </span>
                </div>

                <div className="text-xs font-sans font-bold text-[#02353C] uppercase tracking-wider">
                  {stage.name}
                </div>
                <div className="text-[11px] text-[#486966] mt-0.5 truncate" title={stage.title}>
                  {stage.title}
                </div>
              </div>

              <div className="mt-3 pt-2 border-t border-[#D5EAE5]">
                <span
                  className={cn(
                    "inline-block px-2 py-0.5 rounded-sm text-[10px] font-mono font-bold uppercase tracking-wider border",
                    getStatusBadge(stage.status)
                  )}
                >
                  {stage.status}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
