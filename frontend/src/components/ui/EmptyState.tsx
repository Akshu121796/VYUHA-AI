import * as React from "react";
import { ShieldAlert } from "lucide-react";
import { cn } from "../../utils/cn";
import { Button } from "./Button";

export interface EmptyStateProps extends React.HTMLAttributes<HTMLDivElement> {
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
  icon?: React.ReactNode;
}

export function EmptyState({
  className,
  title,
  description,
  actionLabel,
  onAction,
  icon = <ShieldAlert className="h-7 w-7 text-slate-400" />,
  ...props
}: EmptyStateProps) {
  return (
    <div className={cn("flex min-h-[240px] flex-col items-center justify-center rounded-[24px] border border-dashed border-slate-200 bg-slate-50/70 p-8 text-center shadow-sm", className)} {...props}>
      <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border border-slate-200 bg-white text-slate-500 shadow-sm">
        {icon}
      </div>
      <h4 className="text-sm font-semibold uppercase tracking-[0.2em] text-slate-800">{title}</h4>
      <p className="mt-2 max-w-[280px] text-sm leading-6 text-slate-500">{description}</p>
      {actionLabel && onAction && (
        <Button variant="cyber" size="sm" onClick={onAction} className="mt-5">
          {actionLabel}
        </Button>
      )}
    </div>
  );
}

export default EmptyState;
