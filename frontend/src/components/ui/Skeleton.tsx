import * as React from "react";
import { cn } from "../../utils/cn";

export interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {}

export function Skeleton({ className, ...props }: SkeletonProps) {
  return (
    <div
      className={cn("rounded-sm skeleton-gradient h-4 w-full", className)}
      {...props}
    />
  );
}

export default Skeleton;
