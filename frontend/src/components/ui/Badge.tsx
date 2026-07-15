import * as React from "react";
import { cn } from "../../utils/cn";
import { Severity } from "../../types";

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "secondary" | "outline" | "primary" | "critical" | "high" | "medium" | "low" | "neutral" | "safe";
  severity?: Severity;
}

function Badge({ className, variant, severity, ...props }: BadgeProps) {
  let activeVariant: string = severity || variant || "default";

  if (activeVariant === "safe") {
    activeVariant = "low";
  }

  return (
    <div
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-1 text-[10px] font-semibold tracking-wide transition-premium select-none",
        {
          "border-slate-200 bg-slate-900 text-white": activeVariant === "default",
          "border-slate-200 bg-slate-100 text-slate-700": activeVariant === "secondary",
          "border-slate-200 bg-transparent text-slate-700": activeVariant === "outline",
          "border-blue-200 bg-blue-50 text-cyber-primary": activeVariant === "primary",
          "border-red-200 bg-red-50 text-cyber-critical": activeVariant === "critical",
          "border-amber-200 bg-amber-50 text-cyber-high": activeVariant === "high",
          "border-yellow-200 bg-yellow-50 text-cyber-medium": activeVariant === "medium",
          "border-emerald-200 bg-emerald-50 text-cyber-low": activeVariant === "low",
          "border-slate-200 bg-slate-50 text-slate-600": activeVariant === "neutral",
        },
        className
      )}
      {...props}
    />
  );
}

export { Badge };
export default Badge;
