import React from "react";
import {
  Globe,
  ShieldAlert,
  Brain,
  Sliders,
  CheckCircle,
  AlertOctagon,
  ArrowRight,
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
        return <Globe className="w-4 h-4 text-amber-800" />;
      case 2:
        return status === "FLAGGED" ? (
          <ShieldAlert className="w-4 h-4 text-orange-700" />
        ) : (
          <CheckCircle className="w-4 h-4 text-emerald-700" />
        );
      case 3:
        return status === "ANOMALOUS" ? (
          <Brain className="w-4 h-4 text-purple-800" />
        ) : (
          <Brain className="w-4 h-4 text-emerald-700" />
        );
      case 4:
        return <Sliders className="w-4 h-4 text-amber-800" />;
      case 5:
        return status === "BLOCK" ? (
          <AlertOctagon className="w-4 h-4 text-red-700" />
        ) : (
          <CheckCircle className="w-4 h-4 text-emerald-700" />
        );
      default:
        return <Globe className="w-4 h-4" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const s = status.toUpperCase();
    if (s === "BLOCK" || s === "CRITICAL")
      return "bg-red-500/10 text-red-700 border-red-500/30";
    if (s === "FLAGGED" || s === "THROTTLE" || s === "HIGH")
      return "bg-orange-500/10 text-orange-700 border-orange-500/30";
    if (s === "ANOMALOUS" || s === "MONITOR" || s === "MEDIUM")
      return "bg-amber-500/10 text-amber-800 border-amber-500/30";
    return "bg-emerald-500/10 text-emerald-700 border-emerald-500/30";
  };

  return (
    <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5 mb-6">
      <div className="text-xs font-sans uppercase tracking-wider text-[#716c60] mb-4">
        Pipeline Analysis Flow: Ingestion &rarr; Detections &rarr; Machine Learning &rarr; Risk Engine &rarr; Decision
      </div>

      <div className="grid grid-cols-1 md:grid-cols-5 gap-3 relative">
        {lifecycle.map((stage, idx) => {
          return (
            <div
              key={stage.stage}
              className="relative flex flex-col justify-between p-3.5 rounded-none bg-[#ffffff] border border-[#e5e0d5] hover:border-amber-500/30 transition-all"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="w-7 h-7 rounded-none bg-[#ffffff] border border-[#e5e0d5] flex items-center justify-center">
                    {getStageIcon(stage.stage, stage.status)}
                  </div>
                  <span className="text-[10px] font-sans text-[#716c60]">
                    0{stage.stage}
                  </span>
                </div>

                <div className="text-xs font-sans font-bold text-[#27251f] uppercase tracking-wider">
                  {stage.name}
                </div>
                <div className="text-[11px] text-[#716c60] mt-0.5 truncate">
                  {stage.title}
                </div>
              </div>

              <div className="mt-3 pt-2 border-t border-[#e5e0d5]">
                <span
                  className={cn(
                    "inline-block px-2 py-0.5 rounded-none text-[10px] font-sans font-bold uppercase tracking-wider border",
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
