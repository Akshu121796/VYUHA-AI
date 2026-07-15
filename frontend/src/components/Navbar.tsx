import React, { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { Menu, Search, MessageSquareCode, Bell, Sun, Moon, ShieldCheck } from "lucide-react";
import { useAuth } from "../hooks/useAuth";
import { mockIncidents } from "../services/mockData";
import { cn } from "../utils/cn";

interface NavbarProps {
  onOpenCommandMenu: () => void;
  onToggleCopilot: () => void;
  isCopilotOpen: boolean;
  isSidebarCollapsed: boolean;
  onToggleSidebar: () => void;
}

export function Navbar({ onOpenCommandMenu, onToggleCopilot, isCopilotOpen, isSidebarCollapsed, onToggleSidebar }: NavbarProps) {
  const { user } = useAuth();
  const location = useLocation();
  const [themeMode, setThemeMode] = useState<"day" | "night">("day");

  useEffect(() => {
    const storedTheme = window.localStorage.getItem("vyuha-theme");
    const isDark = storedTheme ? storedTheme === "dark" : false;
    setThemeMode(isDark ? "night" : "day");
    document.documentElement.classList.toggle("dark", isDark);
    document.documentElement.classList.remove("high-contrast");
  }, []);

  const toggleTheme = () => {
    const nextMode = themeMode === "day" ? "night" : "day";
    const isDark = nextMode === "night";
    setThemeMode(nextMode);
    document.documentElement.classList.toggle("dark", isDark);
    document.documentElement.classList.remove("high-contrast");
    window.localStorage.setItem("vyuha-theme", isDark ? "dark" : "light");
  };

  const getBreadcrumbs = () => {
    const path = location.pathname;
    if (path === "/") return ["VYUHA.AI", "Operations Dashboard"];

    const parts = path.split("/").filter(Boolean);
    const crumbs = ["VYUHA.AI"];

    parts.forEach((part) => {
      const name = part.charAt(0).toUpperCase() + part.slice(1).replace(/-/g, " ");
      crumbs.push(name);
    });
    return crumbs;
  };

  const crumbs = getBreadcrumbs();
  const criticalCount = mockIncidents.filter((i) => i.status === "active" && i.severity === "critical").length;
  const highCount = mockIncidents.filter((i) => i.status === "active" && i.severity === "high").length;

  let postureText = "SECURE";
  let postureColor = "border-emerald-200 bg-emerald-50 text-cyber-low";
  let pulseColor = "bg-cyber-low";

  if (criticalCount > 0) {
    postureText = "ACTIVE INTRUSION";
    postureColor = "border-red-200 bg-red-50 text-cyber-critical";
    pulseColor = "bg-cyber-critical animate-ping";
  } else if (highCount > 0) {
    postureText = "ELEVATED RISK";
    postureColor = "border-amber-200 bg-amber-50 text-cyber-high";
    pulseColor = "bg-cyber-high animate-pulse";
  }

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between border theme-border theme-surface px-5 theme-shadow-card backdrop-blur-xl">
      <div className="flex items-center gap-3">
        {isSidebarCollapsed && (
          <button
            onClick={onToggleSidebar}
            aria-label="Open navigation menu"
            aria-expanded="false"
            className="rounded-2xl p-2 theme-text-secondary transition-all hover:bg-[var(--surface-secondary)] hover:text-[var(--text-primary)] md:hidden"
            title="Open Navigation Menu"
          >
            <Menu className="h-4.5 w-4.5" />
          </button>
        )}

        <div className="flex items-center gap-2 text-sm">
          {crumbs.map((crumb, idx) => (
            <React.Fragment key={idx}>
              {idx > 0 && <span className="text-slate-300">/</span>}
              <span className={cn(idx === crumbs.length - 1 ? "font-semibold theme-text" : "theme-text-secondary")}>{crumb}</span>
            </React.Fragment>
          ))}
        </div>
      </div>

      <div className="flex items-center gap-3">
        <div className={cn("flex items-center gap-2 rounded-full border px-3 py-1.5 text-[10px] font-medium uppercase tracking-[0.18em]", postureColor)}>
          <span className="relative flex h-2 w-2">
            {criticalCount > 0 && <span className="absolute inline-flex h-full w-full rounded-full bg-cyber-critical opacity-75 animate-ping" />}
            <span className={cn("relative inline-flex h-2 w-2 rounded-full", pulseColor)} />
          </span>
          <span>POSTURE {postureText}</span>
        </div>

        <button onClick={onOpenCommandMenu} className="flex w-[180px] items-center justify-between gap-3 rounded-2xl border theme-border theme-surface-secondary px-3 py-2 text-sm theme-text-secondary shadow-sm transition-all hover:theme-surface">
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-slate-400" />
            <span className="theme-text-secondary">Search</span>
          </div>
          <kbd className="rounded-lg border theme-border theme-surface px-1.5 py-0.5 text-[10px] font-semibold theme-text-secondary">Ctrl K</kbd>
        </button>

        <div className="flex items-center gap-2 border-l theme-border pl-3">
          <button onClick={toggleTheme} title={themeMode === "day" ? "Switch to dark mode" : "Switch to light mode"} className="rounded-2xl p-2 theme-text-secondary transition-all hover:bg-[var(--surface-secondary)] hover:text-[var(--text-primary)]">
            {themeMode === "day" ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
          </button>
          <button className="relative rounded-2xl p-2 theme-text-secondary transition-all hover:bg-[var(--surface-secondary)] hover:text-[var(--text-primary)]">
            <Bell className="h-4 w-4" />
            {criticalCount > 0 && <span className="absolute right-2 top-2 h-1.5 w-1.5 rounded-full bg-cyber-critical" />}
          </button>
          <button onClick={onToggleCopilot} className={cn("flex items-center gap-2 rounded-2xl border px-3 py-2 text-[10px] font-medium uppercase tracking-[0.16em] transition-all", isCopilotOpen ? "theme-button-cyber" : "theme-button-outline")}> 
            <MessageSquareCode className="h-4 w-4" />
            <span className="hidden md:inline">Copilot</span>
          </button>
          <div className="flex items-center gap-2 border-l theme-border pl-3">
            <img src={user?.avatar || "https://api.dicebear.com/7.x/identicon/svg?seed=vyuha"} alt="Profile" className="h-9 w-9 rounded-full border border-slate-200 bg-slate-50" />
            <div className="hidden xl:block text-left">
              <p className="text-sm font-semibold theme-text">{user?.username || "Operator"}</p>
              <div className="mt-0.5 flex items-center gap-1 text-[10px] uppercase tracking-[0.2em] text-slate-500">
                <ShieldCheck className="h-3 w-3 text-cyber-primary" />
                {user?.role || "ANALYST"}
              </div>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}

export default Navbar;
