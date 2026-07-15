import React from "react";
import { NavLink, useNavigate } from "react-router-dom";
import {
  Landmark,
  ShieldAlert,
  MessageSquareCode,
  CheckSquare,
  FileText,
  Settings,
  LogOut,
  Shield,
  ChevronLeft,
  ChevronRight,
  X,
  UserCheck,
  Server,
  Network,
} from "lucide-react";
import { useAuth } from "../hooks/useAuth";
import { mockIncidents, mockApprovalTasks } from "../services/mockData";
import { cn } from "../utils/cn";

interface SidebarProps {
  isCollapsed: boolean;
  onToggleCollapse: () => void;
  onNavigate: () => void;
}

export function Sidebar({ isCollapsed, onToggleCollapse, onNavigate }: SidebarProps) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const activeFindingsCount = mockIncidents.filter((i) => i.status === "active").length;
  const pendingApprovalsCount = mockApprovalTasks.filter((t) => t.status === "pending").length;

  const menuItems = [
    { path: "/", name: "Dashboard", icon: <Landmark className="h-4 w-4" /> },
    {
      path: "/findings",
      name: "Findings",
      icon: <ShieldAlert className="h-4 w-4" />,
      badge: activeFindingsCount > 0 ? activeFindingsCount : undefined,
      badgeColor: "border-red-200 bg-red-50 text-cyber-critical",
    },
    { path: "/endpoints", name: "Endpoints", icon: <Server className="h-4 w-4" /> },
    { path: "/graph", name: "Attack Paths", icon: <Network className="h-4 w-4" /> },
    { path: "/copilot", name: "AI Copilot", icon: <MessageSquareCode className="h-4 w-4" /> },
    {
      path: "/approvals",
      name: "Approval Queue",
      icon: <CheckSquare className="h-4 w-4" />,
      badge: pendingApprovalsCount > 0 ? pendingApprovalsCount : undefined,
      badgeColor: "border-amber-200 bg-amber-50 text-cyber-high",
    },
    { path: "/reports", name: "Reports", icon: <FileText className="h-4 w-4" /> },
    { path: "/settings", name: "Settings", icon: <Settings className="h-4 w-4" /> },
  ];

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <aside
      className={cn(
        "fixed z-50 my-3 ml-3 flex h-[calc(100vh-24px)] shrink-0 flex-col justify-between overflow-hidden rounded-[28px] border border-slate-200/80 bg-white/90 shadow-[0_24px_80px_-36px_rgba(15,23,42,0.34)] backdrop-blur transition-all duration-300 select-none dark:border-slate-800 dark:bg-slate-950/85 dark:shadow-[0_24px_80px_-36px_rgba(2,6,23,0.8)] md:relative",
        isCollapsed ? "w-16 -translate-x-[calc(100%+24px)] md:w-16 md:translate-x-0" : "w-64 translate-x-0 md:w-64"
      )}
    >
      <div>
        <button
          type="button"
          onClick={onToggleCollapse}
          aria-label="Close navigation menu"
          className="absolute right-3 top-3 z-[60] flex h-11 w-11 items-center justify-center rounded-2xl text-slate-500 transition-all hover:bg-slate-100 hover:text-slate-900 dark:hover:bg-slate-800 dark:hover:text-slate-100 md:hidden"
        >
          <X className="h-5 w-5" />
        </button>
        <div className={cn("flex h-16 items-center justify-between border-b border-slate-100/80 px-4 dark:border-slate-800/80", isCollapsed ? "justify-center" : "")}>
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-2xl border border-blue-200 bg-gradient-to-br from-blue-50 to-slate-50 text-cyber-primary shadow-sm dark:border-blue-900/60 dark:from-blue-950/70 dark:to-slate-900">
              <Shield className="h-4.5 w-4.5" />
            </div>
            {!isCollapsed && (
              <div>
                <p className="text-sm font-semibold tracking-tight text-slate-900 dark:text-slate-100">VYUHA<span className="text-cyber-primary">.AI</span></p>
                <p className="text-[10px] uppercase tracking-[0.2em] text-slate-400 dark:text-slate-500">SOC Console</p>
              </div>
            )}
          </div>
        </div>

        <button
          onClick={onToggleCollapse}
          className="absolute -right-3 top-5 hidden h-6 w-6 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-500 shadow-md transition-all hover:border-cyber-primary hover:text-cyber-primary dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 md:flex"
        >
          {isCollapsed ? <ChevronRight className="h-3 w-3" /> : <ChevronLeft className="h-3 w-3" />}
        </button>

        <nav className="space-y-1 p-3">
          {menuItems.map((item, idx) => (
            <NavLink
              key={idx}
              to={item.path}
              onClick={onNavigate}
              className={({ isActive }) =>
                cn(
                  "flex items-center justify-between rounded-2xl px-3 py-2.5 text-sm font-medium transition-all",
                  isActive
                    ? "bg-blue-50 text-cyber-primary shadow-[inset_0_0_0_1px_rgba(37,99,235,0.12)] dark:bg-blue-950/50 dark:text-blue-300"
                    : "text-slate-600 hover:bg-slate-50 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-900 dark:hover:text-slate-100"
                )
              }
            >
              <div className="flex items-center gap-3">
                <span className={cn("flex h-8 w-8 items-center justify-center rounded-xl", isCollapsed ? "ml-0" : "")}>{item.icon}</span>
                {!isCollapsed && <span>{item.name}</span>}
              </div>

              {!isCollapsed && item.badge && (
                <span className={cn("rounded-full border px-2 py-0.5 text-[10px] font-semibold", item.badgeColor)}>{item.badge}</span>
              )}
            </NavLink>
          ))}
        </nav>
      </div>

      <div className="border-t border-slate-100/80 bg-slate-50/70 p-3 dark:border-slate-800 dark:bg-slate-900/70">
        <div className={cn("flex items-center justify-between rounded-2xl px-2 py-2", isCollapsed ? "justify-center" : "border border-slate-200 bg-white shadow-sm dark:border-slate-700 dark:bg-slate-950")}>
          <div className="flex min-w-0 items-center gap-2.5">
            <img
              src={user?.avatar || "https://api.dicebear.com/7.x/identicon/svg?seed=vyuha"}
              alt="Avatar"
              className="h-9 w-9 rounded-full border border-slate-200 bg-slate-50"
            />
            {!isCollapsed && (
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-slate-900 dark:text-slate-100">{user?.username || "Operator"}</p>
                <div className="mt-0.5 flex items-center gap-1">
                  <UserCheck className="h-3 w-3 text-cyber-primary" />
                  <p className="truncate text-[10px] uppercase tracking-[0.2em] text-slate-500 dark:text-slate-400">{user?.role || "ANALYST"}</p>
                </div>
              </div>
            )}
          </div>

          {!isCollapsed && (
            <button onClick={handleLogout} title="Logout" className="rounded-full p-2 text-slate-400 transition-all hover:bg-slate-100 hover:text-cyber-critical dark:hover:bg-slate-800">
              <LogOut className="h-4 w-4" />
            </button>
          )}
        </div>
        {isCollapsed && (
          <button onClick={handleLogout} title="Logout" className="mt-2 flex w-full items-center justify-center rounded-2xl py-2 text-slate-400 transition-all hover:bg-slate-100 hover:text-cyber-critical dark:hover:bg-slate-800">
            <LogOut className="h-4 w-4" />
          </button>
        )}
      </div>
    </aside>
  );
}

export default Sidebar;
