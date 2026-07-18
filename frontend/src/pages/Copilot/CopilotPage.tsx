import React, { useState, useEffect, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { 
  MessageSquareCode, 
  Send, 
  Sparkles, 
  Trash2, 
  Plus, 
  Terminal, 
  Server, 
  ArrowRight,
  ShieldAlert
} from "lucide-react";
import { Card, CardContent } from "../../components/ui/Card";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { cn } from "../../utils/cn";
import { useCopilotMutation, useEndpointsData } from "../../hooks/queries/useVyuhaQueries";

// Conversational interface types
interface Message {
  role: "user" | "assistant";
  content: string;
  isStreaming?: boolean;
  codeBlock?: { language: string; code: string };
  referenceCard?: { hostname: string; ip: string; cve?: string; severity: "critical" | "high" | "medium" | "low" };
}

interface Thread {
  id: string;
  title: string;
  timestamp: string;
}

export function CopilotPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const chatEndRef = useRef<HTMLDivElement>(null);

  const { data: assets } = useEndpointsData();
  const copilotMutation = useCopilotMutation();

  // Thread History list state
  const [threads, setThreads] = useState<Thread[]>([
    { id: "1", title: "[Triage] xz-utils supply chain", timestamp: "03:42" },
    { id: "2", title: "[Containment] LSASS memory dump", timestamp: "03:38" },
    { id: "3", title: "[Audit] SSH Brute Force Campaign", timestamp: "02:15" },
    { id: "4", title: "[Policy] Block RDP lateral routes", timestamp: "01:05" }
  ]);
  const [activeThreadId, setActiveThreadId] = useState<string>("1");

  // Chat message state
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content: "Hello! I am VYUHA.AI Security Copilot. I scan system logs, triage endpoint CVE exposures, and deploy Palo Alto edge containment playbooks. How can I assist your SOC analysis today?"
    }
  ]);
  
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);

  // Suggested Questions list
  const suggestedQuestions = [
    { label: "Triage xz-utils exploit", query: "triage xz-utils supply chain exploit on web-prod-ubuntu-01" },
    { label: "Analyze LSASS memory dump", query: "analyze LSASS memory dump alert on ad-dc-windows-01" },
    { label: "Block WAN Attacker IP", query: "how do I block IP 185.220.101.44 on Palo Alto edge firewalls?" }
  ];

  // Auto-fill query parameter if routed from other pages
  useEffect(() => {
    const urlQuery = searchParams.get("query");
    if (urlQuery) {
      handleSendPrompt(urlQuery);
    }
  }, [searchParams]);

  // Autoscroll chat logs
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isTyping]);

  const handleSendPrompt = (queryText: string) => {
    if (!queryText.trim() || isTyping) return;

    // Append User Message
    const userMsg: Message = { role: "user", content: queryText };
    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setIsTyping(true);

    copilotMutation.mutate(queryText, {
      onSuccess: (data: any) => {
        setIsTyping(false);
        const { answer } = data;

        // Parse code blocks from Markdown content
        const match = answer.match(/```(\w+)?\n([\s\S]+?)\n```/);
        let codeBlock: { language: string; code: string } | undefined;
        let cleanContent = answer;
        if (match) {
          codeBlock = {
            language: match[1] || "bash",
            code: match[2].trim()
          };
          cleanContent = answer.replace(/```(\w+)?\n([\s\S]+?)\n```/g, "").trim();
        }

        // Dynamically find host references in the response text
        const matchedAsset = assets?.find((a: any) => 
          answer.toLowerCase().includes(a.hostname.toLowerCase()) || 
          answer.toLowerCase().includes(a.ip.toLowerCase())
        );

        let referenceCard: { hostname: string; ip: string; cve?: string; severity: "critical" | "high" | "medium" | "low" } | undefined;
        if (matchedAsset) {
          const maxCve = matchedAsset.cves?.[0]?.id;
          referenceCard = {
            hostname: matchedAsset.hostname,
            ip: matchedAsset.ip,
            cve: maxCve,
            severity: matchedAsset.criticalAlertsCount > 0 ? "critical" as const : matchedAsset.highAlertsCount > 0 ? "high" as const : "medium" as const
          };
        }

        // Emulate streaming increments for typing effect
        const sentences = cleanContent.split("\n");
        let currentSentenceIndex = 0;

        const streamMsg: Message = {
          role: "assistant",
          content: "",
          isStreaming: true
        };
        
        setMessages(prev => [...prev, streamMsg]);

        const interval = setInterval(() => {
          if (currentSentenceIndex < sentences.length) {
            const chunk = sentences.slice(0, currentSentenceIndex + 1).join("\n");
            setMessages(prev => {
              const updated = [...prev];
              const last = updated[updated.length - 1];
              if (last && last.role === "assistant") {
                last.content = chunk;
              }
              return updated;
            });
            currentSentenceIndex++;
          } else {
            clearInterval(interval);
            setMessages(prev => {
              const updated = [...prev];
              const last = updated[updated.length - 1];
              if (last && last.role === "assistant") {
                last.content = cleanContent;
                last.isStreaming = false;
                last.codeBlock = codeBlock;
                last.referenceCard = referenceCard;
              }
              return updated;
            });
          }
        }, 80);
      },
      onError: (err: any) => {
        setIsTyping(false);
        const errMsg = err?.response?.data?.error || err?.message || "RAG Copilot Pipeline failed.";
        setMessages(prev => [
          ...prev,
          {
            role: "assistant",
            content: `Failed to query Security Copilot: ${errMsg}`
          }
        ]);
      }
    });
  };

  const handleCreateNewChat = () => {
    const newId = (threads.length + 1).toString();
    const newThread: Thread = {
      id: newId,
      title: `[Triage] Investigation thread #${newId}`,
      timestamp: "Just now"
    };
    setThreads([newThread, ...threads]);
    setActiveThreadId(newId);
    setMessages([
      {
        role: "assistant",
        content: "New chat session initialized. How can VYUHA.AI Security Copilot assist your SOC investigation today?"
      }
    ]);
  };

  const handleClearHistory = () => {
    setThreads([]);
    setMessages([
      {
        role: "assistant",
        content: "All historic threads cleared. Initializing new chat session."
      }
    ]);
  };

  return (
    <div className="flex flex-col xl:flex-row h-[calc(100vh-100px)] border border-slate-200 bg-white rounded-lg overflow-hidden select-none shadow-card">
      
      {/* Left Column: Conversation History Sidebar (1/4 width) */}
      <div className="w-full xl:w-64 border-b xl:border-b-0 xl:border-r border-slate-200 bg-slate-50 flex flex-col justify-between shrink-0 h-48 xl:h-full">
        <div>
          {/* Sidebar Header */}
          <div className="p-3.5 border-b border-slate-200 flex items-center justify-between bg-slate-100/30">
            <span className="text-[10px] font-mono font-bold tracking-wider text-slate-400 uppercase">Chat Threads</span>
            <Button variant="outline" size="sm" className="h-6 w-6 p-0" onClick={handleCreateNewChat} title="New Chat">
              <Plus className="h-3.5 w-3.5" />
            </Button>
          </div>
          
          {/* Threads List */}
          <div className="p-2 space-y-1 overflow-y-auto max-h-[120px] xl:max-h-[380px]">
            {threads.map(t => (
              <button
                key={t.id}
                onClick={() => {
                  setActiveThreadId(t.id);
                  setMessages([
                    {
                      role: "assistant",
                      content: `Loaded historic console log session: "${t.title}". Ready for localized playbooks triaging.`
                    }
                  ]);
                }}
                className={cn(
                  "w-full text-left rounded p-2.5 text-xs font-mono transition-premium flex items-center justify-between cursor-pointer",
                  activeThreadId === t.id 
                    ? "bg-white text-slate-900 font-semibold border-l-2 border-brand-accent pl-2.5 shadow-sm" 
                    : "text-slate-550 hover:bg-white/60 hover:text-slate-900"
                )}
              >
                <div className="flex items-center space-x-2 truncate">
                  <MessageSquareCode className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                  <span className="truncate">{t.title}</span>
                </div>
                <span className="text-[8px] text-slate-400 shrink-0 font-sans">{t.timestamp}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Clear History footer */}
        {threads.length > 0 && (
          <div className="p-2 border-t border-slate-200 bg-slate-100/20">
            <button
              onClick={handleClearHistory}
              className="w-full font-mono text-[9px] text-slate-400 hover:text-red-600 hover:bg-red-50 border border-slate-200 rounded py-1.5 flex items-center justify-center gap-1 cursor-pointer transition-all"
            >
              <Trash2 className="h-3 w-3" />
              CLEAR HISTORY LOGS
            </button>
          </div>
        )}
      </div>

      {/* Center Column: Active Chat Interface */}
      <div className="flex-1 flex flex-col justify-between min-w-0 bg-white relative h-full">
        {/* Subtle grid background */}
        <div className="absolute inset-0 cyber-grid-overlay opacity-5 pointer-events-none z-0" />
        
        {/* Header Indicator */}
        <div className="h-12 border-b border-slate-200 bg-white px-4 flex items-center justify-between shrink-0 relative z-10 select-none shadow-sm">
          <div className="flex items-center space-x-2 text-[10px] font-mono text-slate-400">
            <span className="h-1.5 w-1.5 rounded-full bg-cyber-low animate-pulse" />
            <span>COGNITIVE CORE STATUS: ONLINE</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-[9px] font-mono text-slate-500">
              4 active threads
            </div>
            <div className="rounded-full border border-emerald-100 bg-emerald-50 px-2.5 py-1 text-[9px] font-mono text-emerald-700">
              Playbook ready
            </div>
          </div>
        </div>

        {/* Messages Feed Area */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4 relative z-10 bg-slate-50/30">
          {messages.map((msg, idx) => (
            <div 
              key={idx} 
              className={cn(
                "flex space-x-3 text-xs max-w-[760px] mx-auto",
                msg.role === "user" ? "justify-end text-right" : "justify-start text-left"
              )}
            >
              {/* Identicon avatar */}
              {msg.role === "assistant" && (
                <div className="h-8 w-8 rounded bg-blue-50 border border-blue-100 text-brand-accent flex items-center justify-center shrink-0">
                  <Sparkles className="h-4 w-4 text-cyber-primary" />
                </div>
              )}
              
              <div className="space-y-3.5 max-w-[85%]">
                {/* Bubble card */}
                <div className={cn(
                  "p-4 rounded-lg border leading-relaxed shadow-sm font-sans",
                  msg.role === "user" 
                    ? "bg-slate-900 border-slate-950 text-white rounded-tr-none text-left" 
                    : "bg-white border-slate-200 text-slate-700 rounded-tl-none"
                )}>
                  {/* Markdown headings helper */}
                  {msg.content.startsWith("###") ? (
                    <div className="space-y-2">
                      <h4 className="text-xs font-mono font-bold tracking-tight text-slate-900 border-b border-slate-100 pb-1">
                        {msg.content.split("\n")[0].replace("###", "")}
                      </h4>
                      <p className="whitespace-pre-wrap leading-relaxed">
                        {msg.content.split("\n").slice(1).join("\n")}
                      </p>
                    </div>
                  ) : (
                    <span className="whitespace-pre-wrap leading-relaxed">{msg.content}</span>
                  )}
                </div>

                {/* Markdown Code Block */}
                {msg.codeBlock && (
                  <Card className="bg-slate-950 border-slate-900 max-w-full overflow-x-auto rounded-lg shadow-md">
                    <CardContent className="p-3.5 font-mono text-[10px] text-slate-200 leading-relaxed relative">
                      <div className="absolute top-1.5 right-2 text-[8px] text-slate-500 select-none uppercase font-bold">{msg.codeBlock.language}</div>
                      <pre className="whitespace-pre">{msg.codeBlock.code}</pre>
                    </CardContent>
                  </Card>
                )}

                {/* Host Reference Card link */}
                {msg.referenceCard && (
                  <div 
                    onClick={() => navigate(`/endpoints`)}
                    className="flex items-center justify-between p-3.5 border border-slate-200 hover:border-brand-accent/40 bg-slate-50/50 hover:bg-white rounded-md cursor-pointer transition-premium group shadow-sm"
                  >
                    <div className="flex items-center space-x-3 min-w-0">
                      <div className="h-7 w-7 bg-blue-50 border border-blue-100 text-cyber-primary flex items-center justify-center rounded shrink-0">
                        <Server className="h-3.5 w-3.5" />
                      </div>
                      <div className="min-w-0">
                        <span className="font-mono text-[10.5px] font-bold text-slate-800 block truncate">{msg.referenceCard.hostname}</span>
                        <span className="font-mono text-[8.5px] text-slate-400 block mt-0.5">{msg.referenceCard.ip}</span>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2 shrink-0 pl-4">
                      {msg.referenceCard.cve && (
                        <Badge variant="critical" className="h-4 text-[8px] px-1 font-bold font-mono">
                          {msg.referenceCard.cve}
                        </Badge>
                      )}
                      <ArrowRight className="h-3.5 w-3.5 text-slate-450 group-hover:text-brand-accent transition-colors" />
                    </div>
                  </div>
                )}
              </div>

              {msg.role === "user" && (
                <div className="h-8 w-8 rounded bg-slate-100 border border-slate-200 flex items-center justify-center shrink-0 select-none font-bold text-slate-700 font-mono text-[10px]">
                  OP
                </div>
              )}
            </div>
          ))}

          {/* Thinking loading indicator */}
          {isTyping && (
            <div className="flex space-x-3 text-xs max-w-[760px] mx-auto">
              <div className="h-8 w-8 rounded bg-blue-50 border border-blue-100 text-brand-accent flex items-center justify-center shrink-0">
                <Sparkles className="h-4 w-4 text-cyber-primary animate-pulse" />
              </div>
              <div className="bg-white border border-slate-200 p-3 rounded-lg rounded-tl-none text-slate-400 flex items-center gap-1.5 h-8 select-none shadow-sm">
                <span className="h-1.5 w-1.5 rounded-full bg-slate-400 animate-bounce" />
                <span className="h-1.5 w-1.5 rounded-full bg-slate-400 animate-bounce delay-100" />
                <span className="h-1.5 w-1.5 rounded-full bg-slate-400 animate-bounce delay-200" />
              </div>
            </div>
          )}
          
          <div ref={chatEndRef} />
        </div>

        {/* Input Prompter Console Area */}
        <div className="p-4 border-t border-slate-200 bg-white relative z-10 shrink-0 shadow-sm">
          <div className="max-w-[760px] mx-auto space-y-3">
            {/* Suggested Chips (top) */}
            {messages.length === 1 && !isTyping && (
              <div className="flex flex-wrap gap-2 text-[10px] font-mono select-none">
                {suggestedQuestions.map((q, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleSendPrompt(q.query)}
                    className="px-3 py-1.5 rounded-full border border-slate-200 bg-slate-50 text-slate-550 hover:text-slate-900 hover:bg-slate-100 hover:border-slate-350 cursor-pointer transition-all flex items-center gap-1 shadow-sm"
                  >
                    <span>{q.label}</span>
                    <ArrowRight className="h-2.5 w-2.5 text-slate-400" />
                  </button>
                ))}
              </div>
            )}

            {/* Input Form Box */}
            <div className="relative border border-slate-200 focus-within:border-brand-accent/50 focus-within:ring-2 focus-within:ring-brand-accent/15 rounded-md bg-slate-50/30 flex items-center pr-3 transition-all h-10 shadow-sm">
              <input
                type="text"
                placeholder="Ask VYUHA.AI Security Copilot a question..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleSendPrompt(input);
                }}
                className="flex-1 bg-transparent border-0 outline-none text-xs font-mono text-slate-800 px-3.5 h-full"
              />
              <button
                onClick={() => handleSendPrompt(input)}
                className="p-1 rounded text-slate-400 hover:text-brand-accent transition-colors cursor-pointer"
                title="Send query"
              >
                <Send className="h-4 w-4" />
              </button>
            </div>
            
            <div className="text-[8.5px] font-mono text-slate-400 text-center select-none">
              Press Enter to send • VYUHA.AI Copilot may generate logs matching simulated SOC triages
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CopilotPage;
