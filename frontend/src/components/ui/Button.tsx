import * as React from "react";
import { cn } from "../../utils/cn";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "destructive" | "outline" | "secondary" | "ghost" | "link" | "cyber" | "neutral";
  size?: "default" | "sm" | "lg" | "icon";
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "default", ...props }, ref) => {
    return (
      <button
        className={cn(
          "inline-flex items-center justify-center whitespace-nowrap rounded-xl text-sm font-medium tracking-tight transition-premium focus-visible:outline-none disabled:pointer-events-none disabled:opacity-40 active:scale-[0.98] cursor-pointer selection:bg-transparent",
          {
            "theme-button-primary hover:-translate-y-0.5": variant === "default",
            "theme-button-danger": variant === "destructive",
            "border theme-button-outline": variant === "outline",
            "border theme-button-secondary": variant === "secondary",
            "theme-button-ghost": variant === "ghost",
            "theme-button-link underline-offset-4 hover:underline": variant === "link",
            "border theme-button-cyber": variant === "cyber",
            "border theme-button-neutral": variant === "neutral",
          },
          {
            "h-10 px-4 py-2": size === "default",
            "h-8 rounded-lg px-3 text-xs": size === "sm",
            "h-11 rounded-2xl px-8": size === "lg",
            "h-10 w-10 p-0": size === "icon",
          },
          className
        )}
        ref={ref}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";

export { Button };
export default Button;
