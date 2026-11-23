import { PRIORITY_LABEL, SEVERITY_LABEL, STATUS_LABEL } from "@/lib/defaults";
import type { Priority, Severity, TriageStatus } from "@/lib/types";
import { cn } from "cn";

const priorityClass: Record<Priority, string> = {
  urgente: "bg-[#8d2b2b] text-[#fff8f4]",
  alta: "bg-[#8a5a12] text-[#fff8ee]",
  media: "bg-[#ead9b4] text-[#3f3422]",
  baixa: "bg-[#e6e0d4] text-[#5c564c]",
};

const severityClass: Record<Severity, string> = {
  critical: "text-[#8d2b2b]",
  high: "text-[#8a5a12]",
  medium: "text-[#5c564c]",
  low: "text-[#5c564c]",
  unknown: "text-[#5c564c]",
};

export function PriorityMark({ priority }: { priority: Priority }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 items-center rounded-full px-2 text-[11px] font-medium tracking-wide",
        priorityClass[priority],
      )}
    >
      {PRIORITY_LABEL[priority]}
    </span>
  );
}

export function SeverityMark({ severity, score }: { severity: Severity; score: number | null }) {
  return (
    <span className={cn("text-xs font-medium", severityClass[severity])}>
      {SEVERITY_LABEL[severity]}
      {score !== null ? ` ${score.toFixed(1)}` : ""}
    </span>
  );
}

export function StatusMark({ status }: { status: TriageStatus }) {
  return <span className="text-xs text-[#5c564c]">{STATUS_LABEL[status]}</span>;
}
