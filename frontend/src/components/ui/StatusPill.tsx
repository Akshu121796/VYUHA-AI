import * as React from "react";
import { cn } from "../../utils/cn";

export interface StatusPillProps extends React.HTMLAttributes<HTMLDivElement> {
  status: "online" | "offline" | "isolated" | "investigating" | "active" | "resolved" | "running" | "suspicious" | "terminated" | "suppressed";
}

export function StatusPill({ className, status, ...props }: StatusPillProps) {
  let pulseClass = "";
  let dotColor = "";
  let textColor = "theme-text-secondary";
  let bgClass = "theme-status-neutral";

  switch (status) {
    case "online":
    case "resolved":
    case "running":
      pulseClass = "pulse-green";
      dotColor = "bg-cyber-low";
      textColor = "theme-status-success";
      bgClass = "theme-status-success";
      break;
    case "isolated":
    case "active":
    case "suspicious":
      pulseClass = "pulse-red";
      dotColor = "bg-cyber-critical";
      textColor = "theme-status-danger";
      bgClass = "theme-status-danger";
      break;
    case "investigating":
      pulseClass = "pulse-orange";
      dotColor = "bg-cyber-high";
      textColor = "theme-status-warning";
      bgClass = "theme-status-warning";
      break;
    case "offline":
    case "terminated":
    default:
      pulseClass = "";
      dotColor = "bg-slate-400";
      textColor = "theme-text-secondary";
      bgClass = "theme-status-neutral";
      break;
  }

  return (
    <div className={cn("inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.18em]", bgClass, className)} {...props}>
      <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", dotColor, pulseClass)} />
      <span className={textColor}>{status}</span>
    </div>
  );
}

export default StatusPill;
