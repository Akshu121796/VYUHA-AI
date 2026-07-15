import React, { useState, useEffect, useCallback } from "react";
import { Navigate, Outlet, useSearchParams } from "react-router-dom";
import { Sparkles, Terminal, Send, ArrowRight, MessageSquareCode, Trash2, Cpu } from "lucide-react";
import { useAuth } from "../hooks/useAuth";
import { Sidebar } from "../components/Sidebar";
import { Navbar } from "../components/Navbar";
import { CommandMenu } from "../components/CommandMenu";
import { mockCopilotAnswers } from "../services/mockData";
import { Button } from "../components/ui/Button";
import { Badge } from "../components/ui/Badge";
import { cn } from "../utils/cn";

export function ProtectedLayout() {
  const { isAuthenticated, isLoading } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);
  const [isCommandMenuOpen, setIsCommandMenuOpen] = useState(false);

  // This is the sole source of truth for the responsive sidebar. On compact
  // screens, a collapsed sidebar is off-canvas; on desktop it is minimized.
  const toggleSidebar = useCallback(() => {
    setIsSidebarCollapsed((collapsed) => !collapsed);
  }, []);

  const closeSidebarOnMobile = useCallback(() => {
    if (window.matchMedia("(max-width: 767px)").matches) {
      setIsSidebarCollapsed(true);
    }
  }, []);

  // Collapse sidebar automatically on smaller screens
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth < 768) {
        setIsSidebarCollapsed(true);
      }
    };
    handleResize();
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  // Attach one keyboard listener only while the mobile drawer is visible.
  useEffect(() => {
    if (isSidebarCollapsed || !window.matchMedia("(max-width: 767px)").matches) return;

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setIsSidebarCollapsed(true);
    };

    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, [isSidebarCollapsed]);

  // Lock the document only while the mobile drawer is open, then restore its
  // previous inline style on close/unmount.
  useEffect(() => {
    if (isSidebarCollapsed || !window.matchMedia("(max-width: 767px)").matches) return;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [isSidebarCollapsed]);

  // AI Copilot state
  const [chatMessages, setChatMessages] = useState<Array<{ role: "user" | "assistant"; content: string; code?: string; language?: string; actions?: any[] }>>([
    {
      role: "assistant",
      content: "Hello! I am VYUHA.AI's Cyber Security Copilot. I scan security telemetry, analyze endpoint vulnerabilities, and run incident playbooks. Ask me about CVEs, credential access on ad-dc-windows-01, SSH logins on web-prod-ubuntu-01, or pending isolation requests.",
      actions: [
        { label: "Analyze web-prod-ubuntu-01", action: "ask", payload: "analyze xz-backdoor vulnerability" },
        { label: "Investigate ad-dc-windows-01", action: "ask", payload: "review lsass memory dump" }
      ]
    }
  ]);
  const [copilotInput, setCopilotInput] = useState("");
  const [isCopilotTyping, setIsCopilotTyping] = useState(false);
  const chatEndRef = React.useRef<HTMLDivElement>(null);

  // Monitor search query parameters to open copilot automatically
  useEffect(() => {
    const query = searchParams.get("query");
    if (query) {
      setIsCopilotOpen(true);
      handleSendCopilotMessage(decodeURIComponent(query).replace(/\+/g, " "));
      // Clear query param so it doesn't trigger repeatedly
      setSearchParams({});
    }
  }, [searchParams]);

  // Global keyboard shortcuts (Cmd+K / Ctrl+K for search)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setIsCommandMenuOpen(prev => !prev);
      }
      if ((e.metaKey || e.ctrlKey) && e.key === "i") {
        e.preventDefault();
        setIsCopilotOpen(prev => !prev);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Scroll to bottom of chat when new message arrives
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages, isCopilotTyping]);

  const handleSendCopilotMessage = (contentText: string) => {
    if (!contentText.trim()) return;

    const userMsg = { role: "user" as const, content: contentText };
    setChatMessages(prev => [...prev, userMsg]);
    setCopilotInput("");
    setIsCopilotTyping(true);

    setTimeout(() => {
      setIsCopilotTyping(false);
      const cleaned = contentText.toLowerCase();
      let response: { role: "assistant"; content: string; code?: string; language?: string; actions?: any[] } = {
        role: "assistant" as const,
        content: `I've received your query: "${contentText}". I will monitor system process queues and quarantine vectors.`
      };

      if (cleaned.includes("xz") || cleaned.includes("backdoor")) {
        response = {
          role: "assistant" as const,
          content: mockCopilotAnswers["analyze xz-backdoor vulnerability"].text,
          code: mockCopilotAnswers["analyze xz-backdoor vulnerability"].code,
          language: mockCopilotAnswers["analyze xz-backdoor vulnerability"].language,
          actions: mockCopilotAnswers["analyze xz-backdoor vulnerability"].actions
        };
      } else if (cleaned.includes("lsass") || cleaned.includes("dump")) {
        response = {
          role: "assistant" as const,
          content: mockCopilotAnswers["review lsass memory dump"].text,
          code: mockCopilotAnswers["review lsass memory dump"].code,
          language: mockCopilotAnswers["review lsass memory dump"].language,
          actions: mockCopilotAnswers["review lsass memory dump"].actions
        };
      }

      setChatMessages(prev => [...prev, response]);
    }, 800);
  };

  const handleCopilotAction = (act: any) => {
    if (act.action === "ask") {
      handleSendCopilotMessage(act.payload);
    }
  };

  const clearChatHistory = () => {
    setChatMessages([
      {
        role: "assistant",
        content: "Chat session reset. Ask me about system telemetry, vulnerabilities, or action approvals."
      }
    ]);
  };

  if (isLoading) {
    return (
      <div className="h-screen w-screen bg-background flex flex-col items-center justify-center space-y-4">
        <span className="h-5 w-5 bg-brand-accent rounded-full animate-ping" />
        <span className="font-mono text-xs text-brand-secondary">AUTHENTICATING...</span>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="h-screen w-screen flex overflow-hidden bg-background">
      {/* Collapsible Left Sidebar */}
      <Sidebar isCollapsed={isSidebarCollapsed} onToggleCollapse={toggleSidebar} onNavigate={closeSidebarOnMobile} />

      {/* Mobile Sidebar overlay backdrop */}
      <div
        aria-hidden="true"
        onClick={closeSidebarOnMobile}
        className={cn(
          "fixed inset-0 z-40 bg-slate-950/50 backdrop-blur-[2px] transition-opacity duration-300 md:hidden",
          isSidebarCollapsed ? "pointer-events-none opacity-0" : "pointer-events-auto opacity-100"
        )}
      />

      {/* Main Container */}
      <div className="flex-1 flex flex-col min-w-0 h-full overflow-hidden relative">
        {/* Top Navbar */}
        <Navbar 
          onOpenCommandMenu={() => setIsCommandMenuOpen(true)} 
          onToggleCopilot={() => setIsCopilotOpen(!isCopilotOpen)} 
          isCopilotOpen={isCopilotOpen} 
          isSidebarCollapsed={isSidebarCollapsed}
          onToggleSidebar={toggleSidebar}
        />

        {/* Content Outlet scroll frame */}
        <main className="flex-1 overflow-y-auto bg-background relative">
          {/* Subtle tactical grid overlay */}
          <div className="absolute inset-0 cyber-grid-overlay opacity-5 pointer-events-none" />
          <div className="relative z-10 p-6 min-h-full">
            <Outlet />
          </div>
        </main>

        {/* Global Command Menu Dialog */}
        <CommandMenu isOpen={isCommandMenuOpen} onClose={() => setIsCommandMenuOpen(false)} />
      </div>

      {/* Persistent slide-out AI Copilot Pane */}
      <div className={cn(
        "border-l border-slate-200 bg-white/95 h-screen transition-all duration-300 flex flex-col justify-between shrink-0 z-40 select-none shadow-[0_0_40px_rgba(15,23,42,0.06)] dark:border-slate-800 dark:bg-slate-950/95 dark:shadow-[0_0_40px_rgba(2,6,23,0.5)]",
        isCopilotOpen ? "w-[380px]" : "w-0 overflow-hidden border-l-0"
      )}>
        {/* Header */}
        <div className="h-14 border-b border-slate-200 flex items-center justify-between px-4 bg-gradient-to-r from-slate-50 to-white dark:border-slate-800 dark:from-slate-900 dark:to-slate-950">
          <div className="flex items-center space-x-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-xl border border-blue-100 bg-blue-50 text-cyber-primary">
              <Sparkles className="h-4 w-4 animate-pulse" />
            </div>
            <div>
              <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-slate-700 dark:text-slate-200">
                VYUHA.AI COPILOT
              </span>
              <p className="text-[9px] text-slate-500 dark:text-slate-400">Guided SOC response workspace</p>
            </div>
          </div>
          <button 
            onClick={clearChatHistory}
            title="Clear Chat"
            className="rounded-full p-1.5 text-slate-400 transition-all hover:bg-slate-100 hover:text-slate-900 dark:hover:bg-slate-800 dark:hover:text-slate-100"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>

        {/* Chat History Container */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-[radial-gradient(circle_at_top_left,_rgba(37,99,235,0.06),_transparent_45%)] dark:bg-[radial-gradient(circle_at_top_left,_rgba(37,99,235,0.12),_transparent_45%)]">
          {chatMessages.map((msg, index) => (
            <div key={index} className={cn("space-y-1.5", msg.role === "user" ? "items-end" : "items-start")}>
              {/* Role Title */}
              <div className="flex items-center space-x-1.5 px-0.5">
                <span className={cn(
                  "text-[9px] font-mono uppercase tracking-wider",
                  msg.role === "user" ? "text-brand-secondary ml-auto" : "text-brand-accent"
                )}>
                  {msg.role === "user" ? "ANALYST" : "COPILOT AGENT"}
                </span>
              </div>

              {/* Message bubble */}
              <div className={cn(
                "rounded-2xl p-3 text-xs leading-relaxed max-w-[95%] shadow-sm",
                msg.role === "user" 
                  ? "bg-slate-900 text-white border border-slate-900 ml-auto dark:bg-slate-100 dark:text-slate-900 dark:border-slate-100" 
                  : "bg-white text-slate-700 border border-slate-200 dark:bg-slate-900 dark:text-slate-200 dark:border-slate-700"
              )}>
                {/* Text Content */}
                <p className="whitespace-pre-line">{msg.content}</p>

                {/* Code Block if any */}
                {msg.code && (
                  <div className="mt-3 overflow-hidden rounded-sm border border-slate-200 bg-slate-50 dark:border-slate-700 dark:bg-slate-950">
                    <div className="flex items-center justify-between border-b border-slate-200 bg-slate-100 px-3 py-1 dark:border-slate-700 dark:bg-slate-900">
                      <span className="text-[9px] font-mono text-slate-500">{msg.language || "code"}</span>
                      <Terminal className="h-3 w-3 text-slate-400" />
                    </div>
                    <pre className="p-3 text-[10px] font-mono text-brand-accent overflow-x-auto">
                      <code>{msg.code}</code>
                    </pre>
                  </div>
                )}

                {/* Simulated action triggers */}
                {msg.actions && msg.actions.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-2">
                    {msg.actions.map((act, aIdx) => (
                      <button
                        key={aIdx}
                        onClick={() => handleCopilotAction(act)}
                        className="flex items-center text-[10px] font-mono font-medium bg-brand-darkBlue hover:bg-blue-100 text-brand-accent border border-brand-accent/20 hover:border-brand-accent/40 rounded-sm px-2 py-1 transition-all"
                      >
                        {act.label}
                        <ArrowRight className="ml-1 h-2.5 w-2.5" />
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}

          {/* Typing Indicator */}
          {isCopilotTyping && (
            <div className="space-y-1.5">
              <span className="text-[9px] font-mono uppercase tracking-wider text-brand-accent">
                COPILOT AGENT
              </span>
              <div className="bg-white border border-slate-200 rounded-sm p-3 max-w-[60px] flex items-center justify-center space-x-1">
                <span className="h-1.5 w-1.5 bg-brand-accent rounded-full animate-bounce" style={{ animationDelay: "0ms" }} />
                <span className="h-1.5 w-1.5 bg-brand-accent rounded-full animate-bounce" style={{ animationDelay: "150ms" }} />
                <span className="h-1.5 w-1.5 bg-brand-accent rounded-full animate-bounce" style={{ animationDelay: "300ms" }} />
              </div>
            </div>
          )}

          <div ref={chatEndRef} />
        </div>

        {/* Input panel */}
        <div className="border-t border-slate-200 bg-white/90 p-3">
          <form 
            onSubmit={(e) => {
              e.preventDefault();
              handleSendCopilotMessage(copilotInput);
            }}
            className="flex gap-2"
          >
            <input
              type="text"
              placeholder="Ask Copilot or request playbooks..."
              value={copilotInput}
              onChange={(e) => setCopilotInput(e.target.value)}
              className="flex-1 rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:border-brand-accent"
            />
            <Button type="submit" variant="cyber" size="icon" className="shrink-0 h-9 w-9 rounded-2xl">
              <Send className="h-3.5 w-3.5" />
            </Button>
          </form>
          <div className="mt-2 text-center">
            <span className="text-[9px] font-mono text-slate-400">
              Try asking: "analyze xz-backdoor vulnerability"
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ProtectedLayout;
