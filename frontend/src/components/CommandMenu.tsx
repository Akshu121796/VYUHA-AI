import React, { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Search, ShieldAlert, Monitor, Settings, FileText, CheckSquare, MessageSquare, Landmark } from "lucide-react";
import { cn } from "../utils/cn";
import { useEndpointsData } from "../hooks/queries/useVyuhaQueries";

interface CommandMenuProps {
  isOpen: boolean;
  onClose: () => void;
}

interface CommandItem {
  id: string;
  title: string;
  category: "Navigation" | "Endpoints" | "Quick Actions";
  icon: React.ReactNode;
  action: () => void;
}

export function CommandMenu({ isOpen, onClose }: CommandMenuProps) {
  const navigate = useNavigate();
  const { data: endpoints } = useEndpointsData();
  const [search, setSearch] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const endpointCommands = (endpoints || []).map((ep: any) => ({
    id: `ep-${ep.id}`,
    title: `Host profile: ${ep.hostname} (${ep.ip} - ${ep.os})`,
    category: "Endpoints" as const,
    icon: <Monitor className="h-4 w-4 text-brand-secondary" />,
    action: () => navigate(`/endpoints/${ep.id}`)
  }));

  // Command database
  const commands: CommandItem[] = [
    { id: "dash", title: "Go to Dashboard", category: "Navigation", icon: <Landmark className="h-4 w-4" />, action: () => navigate("/") },
    { id: "findings", title: "View Detections & Findings", category: "Navigation", icon: <ShieldAlert className="h-4 w-4" />, action: () => navigate("/findings") },
    { id: "graph", title: "Attack Vector Graph", category: "Navigation", icon: <FileText className="h-4 w-4" />, action: () => navigate("/graph") },
    { id: "copilot", title: "AI Copilot Terminal", category: "Navigation", icon: <MessageSquare className="h-4 w-4" />, action: () => navigate("/copilot") },
    { id: "approvals", title: "Mitigation Approval Queue", category: "Navigation", icon: <CheckSquare className="h-4 w-4" />, action: () => navigate("/approvals") },
    { id: "reports", title: "Compliance Scorecard & Reports", category: "Navigation", icon: <FileText className="h-4 w-4" />, action: () => navigate("/reports") },
    { id: "settings", title: "Settings & API Integrations", category: "Navigation", icon: <Settings className="h-4 w-4" />, action: () => navigate("/settings") },
    
    // Dynamically map endpoints to the command list
    ...endpointCommands,

    // Quick Actions
    { id: "act-copilot", title: "Ask Copilot to scan for vulnerabilities", category: "Quick Actions", icon: <MessageSquare className="h-4 w-4 text-brand-accent" />, action: () => navigate("/copilot?query=scan+vulnerabilities") }
  ];

  // Filter commands by search term
  const filtered = commands.filter(cmd =>
    cmd.title.toLowerCase().includes(search.toLowerCase()) ||
    cmd.category.toLowerCase().includes(search.toLowerCase())
  );

  // Focus input when opened
  useEffect(() => {
    if (isOpen) {
      setSearch("");
      setActiveIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  // Handle keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!isOpen) return;

      if (e.key === "ArrowDown") {
        e.preventDefault();
        setActiveIndex(prev => (prev + 1) % filtered.length);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setActiveIndex(prev => (prev - 1 + filtered.length) % filtered.length);
      } else if (e.key === "Enter") {
        e.preventDefault();
        if (filtered[activeIndex]) {
          filtered[activeIndex].action();
          onClose();
        }
      } else if (e.key === "Escape") {
        onClose();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, filtered, activeIndex, onClose]);

  // Click outside listener
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh] px-4">
      {/* Backdrop */}
      <div className="fixed inset-0 bg-background/70 backdrop-blur-sm" />

      {/* Menu Container */}
      <div 
        ref={containerRef}
        className="relative z-50 w-full max-w-lg overflow-hidden rounded-sm border border-border bg-[#0e0e11] shadow-2xl animate-in fade-in slide-in-from-top-4 duration-200"
      >
        {/* Search Input wrapper */}
        <div className="flex items-center border-b border-border/60 px-4 py-3 bg-[#0c0c0e]">
          <Search className="h-4 w-4 text-brand-secondary mr-3" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Type a command or search endpoint profiles..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setActiveIndex(0);
            }}
            className="w-full bg-transparent text-sm text-foreground placeholder:text-zinc-600 focus:outline-none"
          />
          <kbd className="hidden sm:inline-block rounded-sm bg-input border border-border px-1.5 py-0.5 text-[10px] font-mono text-zinc-500">
            ESC
          </kbd>
        </div>

        {/* Results List */}
        <div className="max-h-[300px] overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <div className="py-6 text-center text-xs text-brand-secondary font-mono">
              No security matches found for "{search}"
            </div>
          ) : (
            <div>
              {/* Group commands by category */}
              {["Navigation", "Endpoints", "Quick Actions"].map(cat => {
                const catCmds = filtered.filter(c => c.category === cat);
                if (catCmds.length === 0) return null;
                
                return (
                  <div key={cat} className="mb-2 last:mb-0">
                    <div className="px-2 py-1 text-[10px] font-mono font-medium text-zinc-600 uppercase tracking-wider">
                      {cat}
                    </div>
                    <div className="space-y-0.5 mt-1">
                      {catCmds.map(cmd => {
                        // Find global index in filtered array
                        const globalIdx = filtered.findIndex(c => c.id === cmd.id);
                        const isSelected = globalIdx === activeIndex;

                        return (
                          <div
                            key={cmd.id}
                            onClick={() => {
                              cmd.action();
                              onClose();
                            }}
                            className={cn(
                              "flex items-center justify-between rounded-sm px-3 py-2 text-xs font-medium cursor-pointer transition-all duration-75",
                              isSelected 
                                ? "bg-zinc-900 text-foreground" 
                                : "text-brand-secondary hover:bg-zinc-950 hover:text-foreground"
                            )}
                          >
                            <div className="flex items-center">
                              <span className={cn("mr-3", isSelected ? "text-brand-accent" : "text-zinc-500")}>
                                {cmd.icon}
                              </span>
                              <span>{cmd.title}</span>
                            </div>
                            {isSelected && (
                              <kbd className="rounded-sm bg-input border border-border px-1 text-[9px] font-mono text-zinc-500">
                                ENTER
                              </kbd>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default CommandMenu;
