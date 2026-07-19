import React, { useEffect, useState, useRef } from "react";
import { useLocation } from "react-router-dom";
import { Menu, Search, MessageSquareCode, Bell, Sun, Moon, ShieldCheck, ShieldAlert, CheckSquare, FileText, Server, AlertCircle } from "lucide-react";
import { useAuth } from "../hooks/useAuth";
import { useIncidentsData, useNotificationsData } from "../hooks/queries/useVyuhaQueries";
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
  
  // Notification states
  const [isNotificationsOpen, setIsNotificationsOpen] = useState(false);
  const [readNotifications, setReadNotifications] = useState<string[]>([]);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const { data: incidents } = useIncidentsData();
  const { data: notifications } = useNotificationsData();

  useEffect(() => {
    const storedTheme = window.localStorage.getItem("vyuha-theme");
    const isDark = storedTheme ? storedTheme === "dark" : false;
    setThemeMode(isDark ? "night" : "day");
    document.documentElement.classList.toggle("dark", isDark);
    document.documentElement.classList.remove("high-contrast");
  }, []);

  useEffect(() => {
    const storedRead = localStorage.getItem("vyuha_read_notifications");
    if (storedRead) {
      try {
        setReadNotifications(JSON.parse(storedRead));
      } catch (e) {
        // fallback
      }
    }
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

  const markAllAsRead = () => {
    if (notifications) {
      const allIds = notifications.map((n: any) => n.id);
      localStorage.setItem("vyuha_read_notifications", JSON.stringify(allIds));
      setReadNotifications(allIds);
    }
  };

  const markAsRead = (id: string) => {
    if (!readNotifications.includes(id)) {
      const updated = [...readNotifications, id];
      localStorage.setItem("vyuha_read_notifications", JSON.stringify(updated));
      setReadNotifications(updated);
    }
  };

  // Close notifications on click outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsNotificationsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const crumbs = getBreadcrumbs();
  const liveIncidents = incidents || [];
  const criticalCount = liveIncidents.filter((i: any) => (i.status === "active" || i.status === "open") && i.severity === "critical").length;
  const highCount = liveIncidents.filter((i: any) => (i.status === "active" || i.status === "open") && i.severity === "high").length;

  let postureText = "SECURE";
  let postureColor = "border-emerald-200 bg-emerald-50 text-cyber-low dark:border-emerald-950/20 dark:bg-emerald-950/10";
  let pulseColor = "bg-cyber-low";

  if (criticalCount > 0) {
    postureText = "ACTIVE INTRUSION";
    postureColor = "border-red-200 bg-red-50 text-cyber-critical dark:border-red-950/20 dark:bg-red-950/10";
    pulseColor = "bg-cyber-critical animate-ping";
  } else if (highCount > 0) {
    postureText = "ELEVATED RISK";
    postureColor = "border-amber-200 bg-amber-50 text-cyber-high dark:border-amber-950/20 dark:bg-amber-950/10";
    pulseColor = "bg-cyber-high animate-pulse";
  }

  const unreadCount = (notifications || []).filter((n: any) => !readNotifications.includes(n.id)).length;

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
              {idx > 0 && <span className="text-slate-300 dark:text-slate-700">/</span>}
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
          
          {/* Notifications Dropdown */}
          <div className="relative" ref={dropdownRef}>
            <button 
              onClick={() => setIsNotificationsOpen(!isNotificationsOpen)} 
              title="Notifications center" 
              className={cn(
                "relative rounded-2xl p-2 theme-text-secondary transition-all hover:bg-[var(--surface-secondary)] hover:text-[var(--text-primary)]",
                isNotificationsOpen && "bg-[var(--surface-secondary)] text-[var(--text-primary)]"
              )}
            >
              <Bell className="h-4 w-4" />
              {unreadCount > 0 && (
                <span className="absolute right-1 top-1 flex h-4 w-4 items-center justify-center rounded-full bg-cyber-critical text-[8px] font-bold text-white shadow-sm">
                  {unreadCount}
                </span>
              )}
            </button>

            {isNotificationsOpen && (
              <div className="absolute right-0 mt-3.5 w-80 rounded-[20px] border theme-border theme-surface p-0 shadow-xl z-50 overflow-hidden text-left">
                {/* Header */}
                <div className="flex items-center justify-between border-b theme-border px-4 py-3 bg-slate-50/50 dark:bg-slate-900/30">
                  <span className="font-mono text-[10px] font-bold uppercase tracking-wider theme-text">System Alerts</span>
                  {unreadCount > 0 && (
                    <button 
                      onClick={markAllAsRead} 
                      className="text-[9px] font-mono font-semibold text-cyber-primary hover:underline"
                    >
                      MARK ALL READ
                    </button>
                  )}
                </div>

                {/* Notifications list */}
                <div className="max-h-80 overflow-y-auto divide-y theme-border">
                  {(!notifications || notifications.length === 0) ? (
                    <div className="flex flex-col items-center justify-center py-8 px-4 text-center space-y-2">
                      <AlertCircle className="h-6 w-6 text-slate-350 dark:text-slate-600" />
                      <span className="text-[10px] font-mono text-slate-400">NO RECENT ALERTS</span>
                    </div>
                  ) : (
                    notifications.map((n: any) => {
                      const isUnread = !readNotifications.includes(n.id);
                      return (
                        <div 
                          key={n.id} 
                          onClick={() => markAsRead(n.id)}
                          className={cn(
                            "p-3.5 flex gap-3 transition-colors cursor-pointer hover:bg-slate-50/50 dark:hover:bg-slate-900/20",
                            isUnread && "bg-blue-50/5 dark:bg-blue-950/5 font-semibold"
                          )}
                        >
                          <div className={cn(
                            "h-7 w-7 rounded-xl flex items-center justify-center shrink-0 border",
                            n.type === "finding" && "bg-red-50 border-red-100 text-cyber-critical",
                            n.type === "approval" && "bg-amber-50 border-amber-100 text-cyber-high",
                            n.type === "report" && "bg-blue-50 border-blue-100 text-cyber-primary",
                            n.type === "endpoint" && "bg-slate-50 border-slate-200 text-slate-600"
                          )}>
                            {n.type === "finding" && <ShieldAlert className="h-3.5 w-3.5" />}
                            {n.type === "approval" && <CheckSquare className="h-3.5 w-3.5" />}
                            {n.type === "report" && <FileText className="h-3.5 w-3.5" />}
                            {n.type === "endpoint" && <Server className="h-3.5 w-3.5" />}
                          </div>
                          <div className="space-y-0.5 min-w-0">
                            <div className="flex justify-between items-center gap-2">
                              <span className="text-[10px] font-sans font-bold theme-text truncate">{n.title}</span>
                              <span className="text-[8px] font-mono text-slate-400 shrink-0">{new Date(n.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                            </div>
                            <p className="text-[10px] text-slate-505 leading-snug break-words">{n.message}</p>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            )}
          </div>

          <button onClick={onToggleCopilot} className={cn("flex items-center gap-2 rounded-2xl border px-3 py-2 text-[10px] font-medium uppercase tracking-[0.16em] transition-all", isCopilotOpen ? "theme-button-cyber" : "theme-button-outline")}> 
            <MessageSquareCode className="h-4 w-4" />
            <span className="hidden md:inline">Copilot</span>
          </button>
          
          <div className="flex items-center gap-2 border-l theme-border pl-3">
            <img src={user?.avatar || "https://api.dicebear.com/7.x/identicon/svg?seed=vyuha"} alt="Profile" className="h-9 w-9 rounded-full border border-slate-200 bg-slate-50" />
            <div className="hidden xl:block text-left">
              <p className="text-sm font-semibold theme-text">{user?.username || "Operator"}</p>
              <div className="mt-0.5 flex items-center gap-1 text-[10px] uppercase tracking-[0.2em] text-slate-555">
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
