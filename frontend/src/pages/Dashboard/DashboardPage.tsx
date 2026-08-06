import React from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  PieChart, 
  Pie, 
  Cell, 
  Tooltip as ChartTooltip, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid 
} from "recharts";
import { 
  ShieldAlert, 
  Monitor, 
  CheckSquare, 
  Activity,
  ArrowUpRight,
  ChevronRight,
  ArrowRight,
  Clock,
  Sparkles
} from "lucide-react";
import { useDashboardData } from "../../hooks/queries/useVyuhaQueries";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../components/ui/Card";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { StatusPill } from "../../components/ui/StatusPill";
import { Skeleton } from "../../components/ui/Skeleton";
import { cn } from "../../utils/cn";

export function DashboardPage() {
  const navigate = useNavigate();
  const { data, isLoading } = useDashboardData();

  // Dynamically compile timeline events from audit logs, approvals, and findings
  const timelineEvents = React.useMemo(() => {
    if (!data) return [];
    const events: any[] = [];

    // 1. Process audit logs
    const auditLogs = data.auditLogs || [];
    auditLogs.forEach((log: any) => {
      let title = "Security Action";
      let desc = log.action;
      let type: "critical" | "high" | "medium" | "low" | "neutral" = "neutral";

      if (log.action === "asset_isolated") {
        title = "Host isolated";
        desc = `Host ${log.details?.hostname || "unknown"} isolated from production segment.`;
        type = "critical";
      } else if (log.action === "asset_reconnected") {
        title = "Host reconnected";
        desc = `Host ${log.details?.hostname || "unknown"} reconnected to production segment.`;
        type = "low";
      } else if (log.action === "process_terminated") {
        title = "Process terminated";
        desc = `Process (PID ${log.details?.pid}) terminated on host ${log.details?.hostname || "unknown"}.`;
        type = "high";
      } else if (log.action === "approval_requested") {
        title = "Playbook executed";
        desc = `Containment playbook approval requested for finding ID ${log.details?.finding_id || ""}.`;
        type = "medium";
      } else if (log.action === "approval_approved") {
        title = "Approval granted";
        desc = `Administrative approval granted for request ID ${log.details?.approval_id || ""}.`;
        type = "low";
      } else if (log.action === "approval_rejected") {
        title = "Approval rejected";
        desc = `Administrative approval rejected for request ID ${log.details?.approval_id || ""}.`;
        type = "neutral";
      } else if (log.action === "remediation_applied") {
        title = "Playbook executed";
        desc = `Playbook mitigation applied for finding ID ${log.details?.finding_id || ""}.`;
        type = "low";
      } else if (log.action === "remediation_verified") {
        title = "Remediation verified";
        desc = `Remediation verified for finding ID ${log.details?.finding_id || ""}.`;
        type = "low";
      } else if (log.action === "report_generated") {
        title = "Report generated";
        desc = `Report "${log.details?.title || ""}" compiled and generated.`;
        type = "neutral";
      }

      events.push({
        id: `audit-${log.id}`,
        title,
        description: desc,
        timestamp: new Date(log.created_at || log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + " UTC",
        rawTime: new Date(log.created_at || log.timestamp).getTime(),
        type
      });
    });

    // 2. Process approvals
    const approvalsList = data.approvals || [];
    approvalsList.forEach((appr: any) => {
      if (appr.status === "pending") {
        events.push({
          id: `appr-${appr.id}`,
          title: "Approval pending",
          description: `Isolation approval required for target ${appr.target}. Reason: ${appr.reason}`,
          timestamp: new Date(appr.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + " UTC",
          rawTime: new Date(appr.timestamp).getTime(),
          type: "medium"
        });
      }
    });

    // 3. Process findings (Threat detected)
    const incidentsList = data.incidents || [];
    incidentsList.forEach((inc: any) => {
      events.push({
        id: `inc-${inc.id}`,
        title: "Threat detected",
        description: `${inc.title} detected on asset ${inc.hostname}.`,
        timestamp: new Date(inc.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + " UTC",
        rawTime: new Date(inc.timestamp).getTime(),
        type: inc.severity === "critical" ? "critical" : inc.severity === "high" ? "high" : inc.severity === "medium" ? "medium" : "low"
      });
    });

    // Sort newest first
    return events.sort((a, b) => b.rawTime - a.rawTime);
  }, [data]);

  if (isLoading || !data) {
    return (
      <div className="space-y-6">
        <div className="h-10 w-64 bg-slate-200/60 animate-pulse rounded-md" />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <Skeleton className="h-[115px] w-full rounded-md" />
          <Skeleton className="h-[115px] w-full rounded-md" />
          <Skeleton className="h-[115px] w-full rounded-md" />
          <Skeleton className="h-[115px] w-full rounded-md" />
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Skeleton className="h-[280px] w-full rounded-md" />
          <Skeleton className="h-[280px] w-full rounded-md" />
        </div>
        <Skeleton className="h-64 w-full rounded-md" />
      </div>
    );
  }

  const { incidents, endpoints, approvals } = data;

  const getTimelineStyles = (type: string) => {
    switch (type) {
      case "critical":
        return {
          bullet: "bg-cyber-critical pulse-red",
          box: "border-red-100 bg-red-50/35 dark:border-red-950/20 dark:bg-red-950/5 shadow-[0_8px_18px_-16px_rgba(239,68,68,0.35)]"
        };
      case "high":
        return {
          bullet: "bg-cyber-high pulse-orange",
          box: "border-amber-100 bg-amber-50/35 dark:border-amber-950/20 dark:bg-amber-950/5 shadow-[0_8px_18px_-16px_rgba(245,158,11,0.28)]"
        };
      case "medium":
        return {
          bullet: "bg-cyber-medium pulse-yellow",
          box: "border-yellow-100 bg-yellow-50/35 dark:border-yellow-950/20 dark:bg-yellow-950/5 shadow-[0_8px_18px_-16px_rgba(234,179,8,0.28)]"
        };
      case "low":
        return {
          bullet: "bg-cyber-low pulse-green",
          box: "border-emerald-100 bg-emerald-50/35 dark:border-emerald-950/20 dark:bg-emerald-950/5 shadow-[0_8px_18px_-16px_rgba(34,197,94,0.28)]"
        };
      default:
        return {
          bullet: "bg-cyber-neutral",
          box: "border-slate-200 bg-slate-50/35 dark:border-slate-800/20 dark:bg-slate-900/5 shadow-sm"
        };
    }
  };

  // Telemetry counts
  const activeIncidents = incidents.filter((i: any) => i.status === "active" || i.status === "investigating");
  const criticalCount = incidents.filter((i: any) => i.severity === "critical" && i.status === "active").length;
  const highRiskHosts = endpoints.filter((e: any) => e.criticalAlertsCount > 0 || e.highAlertsCount > 0).length;
  const pendingApprovals = approvals.filter((t: any) => t.status === "pending").length;

  // Mini sparklines data
  const criticalTrend = [{ v: 1 }, { v: 2 }, { v: 1 }, { v: 3 }, { v: 2 }, { v: criticalCount }];
  const riskTrend = [{ v: 0 }, { v: 1 }, { v: 1 }, { v: 2 }, { v: 1 }, { v: highRiskHosts }];
  const incidentTrend = [{ v: 4 }, { v: 6 }, { v: 5 }, { v: 8 }, { v: 7 }, { v: activeIncidents.length }];
  const approvalTrend = [{ v: 2 }, { v: 1 }, { v: 3 }, { v: 2 }, { v: 1 }, { v: pendingApprovals }];

  // Chart 1: Severity Distribution (Recharts Pie)
  const severityData = [
    { name: "Critical", value: incidents.filter((i: any) => i.severity === "critical").length, color: "#ef4444" },
    { name: "High", value: incidents.filter((i: any) => i.severity === "high").length, color: "#f59e0b" },
    { name: "Medium", value: incidents.filter((i: any) => i.severity === "medium").length, color: "#eab308" },
    { name: "Low", value: incidents.filter((i: any) => i.severity === "low").length, color: "#22c55e" }
  ];

  // Chart 2: Endpoint Health (Recharts Bar)
  const endpointHealthData = [
    { name: "Online", value: endpoints.filter((e: any) => e.status === "online").length, color: "#22c55e" },
    { name: "Offline", value: endpoints.filter((e: any) => e.status === "offline").length, color: "#94a3b8" },
    { name: "Isolated", value: endpoints.filter((e: any) => e.status === "isolated").length, color: "#ef4444" }
  ];

  // Motion animation presets matching Apple guidelines
  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: {
        staggerChildren: 0.06
      }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 8 },
    show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 120, damping: 18 } }
  };

  return (
    <motion.div 
      className="space-y-6"
      variants={containerVariants}
      initial="hidden"
      animate="show"
    >
      {/* Command center hero */}
      <motion.div variants={itemVariants} className="relative overflow-hidden rounded-[24px] border theme-border theme-card theme-shadow-elevated p-5 md:p-6">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_88%_8%,rgba(37,99,235,0.13),transparent_28%),radial-gradient(circle_at_64%_100%,rgba(139,92,246,0.055),transparent_34%)]" />
        <div className="relative grid gap-4 lg:grid-cols-[1.18fr_.82fr] lg:items-stretch">
        <div className="flex flex-col justify-between gap-4">
          <div className="max-w-2xl">
            <p className="text-sm font-medium theme-primary">Security command center</p>
            <h1 className="mt-1 max-w-3xl text-2xl font-semibold tracking-[-0.035em] theme-text md:text-3xl">
              Your perimeter is protected. Stay ahead of what&apos;s next.
            </h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 theme-text-secondary">
              One live workspace for threat intelligence, endpoint posture, and high-confidence response actions.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1.5 text-[10px] font-medium uppercase tracking-[0.18em] text-emerald-700">
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
              Live • 03:42 UTC
            </div>
            <div className="rounded-full border border-blue-200 bg-blue-50 px-3 py-1.5 text-[10px] font-medium uppercase tracking-[0.18em] text-blue-700">
              94% playbook readiness
            </div>
          </div>
        </div>

        <div className="flex flex-col justify-between gap-4 rounded-2xl border theme-border theme-surface-secondary px-4 py-4 theme-shadow-card">
          <div className="grid grid-cols-2 gap-x-4 gap-y-3">
            <div><p className="text-[11px] font-medium theme-text-secondary">Security score</p><p className="mt-0.5 text-2xl font-semibold tracking-tight theme-text">94<span className="text-sm font-medium theme-text-muted">/100</span></p></div>
            <div><p className="text-[11px] font-medium theme-text-secondary">Threat level</p><p className="mt-1 inline-flex items-center gap-1.5 text-sm font-semibold theme-status-warning"><span className="h-2 w-2 rounded-full bg-cyber-high" /> Elevated</p></div>
            <div><p className="text-[11px] font-medium theme-text-secondary">Today&apos;s security issues</p><p className="mt-0.5 text-lg font-semibold theme-text">{activeIncidents.length} active</p></div>
            <div><p className="text-[11px] font-medium theme-text-secondary">AI & latest scan</p><p className="mt-0.5 text-sm font-medium theme-status-success">Ready · 03:42 UTC</p></div>
          </div>
          <Button
            className="h-9 bg-blue-600 px-4 text-white shadow-[0_8px_16px_-10px_rgba(37,99,235,0.75)] hover:bg-blue-700"
            onClick={() => navigate("/copilot?query=analyze+lsass+memory+dump")}
          >
            Open AI Copilot
            <ArrowUpRight className="ml-1.5 h-3.5 w-3.5" />
          </Button>
        </div>
        </div>
      </motion.div>

      {/* Row 1: 4 Cards */}
      <motion.div variants={itemVariants} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Card 1: Critical Findings */}
        <motion.div whileHover={{ y: -2 }} className="transition-premium">
          <Card hoverable className="relative overflow-hidden border-t-2 border-t-red-400 bg-gradient-to-br from-red-50/35 via-white to-white dark:from-red-950/20 dark:via-slate-900/40 dark:to-slate-950/40">
            <div className="relative z-[1] pt-10 px-5 pb-5 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-[9.5px] font-mono font-bold uppercase tracking-wider theme-text-secondary">Critical security issues</span>
                <div className="flex h-8.5 w-8.5 items-center justify-center rounded-xl border border-red-100 bg-red-50 text-red-600 shrink-0">
                  <ShieldAlert className="h-4 w-4" />
                </div>
              </div>
              <div className="flex items-baseline justify-between">
                <span className="text-3xl font-bold tracking-tight theme-text">{criticalCount}</span>
                <span className="rounded-full border border-red-100 bg-red-50 px-2.5 py-0.5 text-[9px] font-mono font-semibold text-red-650">+12% today</span>
              </div>
              <div className="h-7">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={criticalTrend}>
                    <defs>
                      <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2}/>
                        <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <Area type="monotone" dataKey="v" stroke="#ef4444" strokeWidth={1.5} fillOpacity={1} fill="url(#critGrad)" dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          </Card>
        </motion.div>

        {/* Card 2: High Risk Endpoints */}
        <motion.div whileHover={{ y: -2 }} className="transition-premium">
          <Card hoverable className="relative overflow-hidden border-t-2 border-t-amber-400 bg-gradient-to-br from-amber-50/35 via-white to-white dark:from-amber-950/20 dark:via-slate-900/40 dark:to-slate-950/40">
            <div className="relative z-[1] pt-10 px-5 pb-5 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-[9.5px] font-mono font-bold uppercase tracking-wider theme-text-secondary">High risk hosts</span>
                <div className="flex h-8.5 w-8.5 items-center justify-center rounded-xl border border-amber-100 bg-amber-50 text-amber-600 shrink-0">
                  <Monitor className="h-4 w-4" />
                </div>
              </div>
              <div className="flex items-baseline justify-between">
                <span className="text-3xl font-bold tracking-tight theme-text">{highRiskHosts}</span>
                <span className="rounded-full border border-amber-100 bg-amber-50 px-2.5 py-0.5 text-[9px] font-mono font-semibold text-amber-650">+8% today</span>
              </div>
              <div className="h-7">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={riskTrend}>
                    <defs>
                      <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.2}/>
                        <stop offset="95%" stopColor="#f59e0b" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <Area type="monotone" dataKey="v" stroke="#f59e0b" strokeWidth={1.5} fillOpacity={1} fill="url(#riskGrad)" dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          </Card>
        </motion.div>

        {/* Card 3: Open Incidents */}
        <motion.div whileHover={{ y: -2 }} className="transition-premium">
          <Card hoverable className="relative overflow-hidden border-t-2 border-t-blue-400 bg-gradient-to-br from-blue-50/45 via-white to-white dark:from-blue-950/20 dark:via-slate-900/40 dark:to-slate-950/40">
            <div className="relative z-[1] pt-10 px-5 pb-5 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-[9.5px] font-mono font-bold uppercase tracking-wider theme-text-secondary">Open incidents</span>
                <div className="flex h-8.5 w-8.5 items-center justify-center rounded-xl border border-blue-100 bg-blue-50 text-blue-600 shrink-0">
                  <Activity className="h-4 w-4" />
                </div>
              </div>
              <div className="flex items-baseline justify-between">
                <span className="text-3xl font-bold tracking-tight theme-text">{activeIncidents.length}</span>
                <span className="rounded-full border border-blue-100 bg-blue-50 px-2.5 py-0.5 text-[9px] font-mono font-semibold text-blue-700">3 new today</span>
              </div>
              <div className="h-7">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={incidentTrend}>
                    <defs>
                      <linearGradient id="incGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#2563eb" stopOpacity={0.2}/>
                        <stop offset="95%" stopColor="#2563eb" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <Area type="monotone" dataKey="v" stroke="#2563eb" strokeWidth={1.5} fillOpacity={1} fill="url(#incGrad)" dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          </Card>
        </motion.div>

        {/* Card 4: Pending Approvals */}
        <motion.div whileHover={{ y: -2 }} className="transition-premium">
          <Card hoverable className="relative overflow-hidden border-t-2 border-t-violet-400 bg-gradient-to-br from-violet-50/45 via-white to-white dark:from-violet-950/20 dark:via-slate-900/40 dark:to-slate-950/40">
            <div className="relative z-[1] pt-10 px-5 pb-5 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-[9.5px] font-mono font-bold uppercase tracking-wider theme-text-secondary">Pending approvals</span>
                <div className="flex h-8.5 w-8.5 items-center justify-center rounded-xl border border-violet-100 bg-violet-50 text-violet-600 shrink-0">
                  <CheckSquare className="h-4 w-4" />
                </div>
              </div>
              <div className="flex items-baseline justify-between">
                <span className="text-3xl font-bold tracking-tight theme-text">{pendingApprovals}</span>
                <span className="rounded-full border border-violet-100 bg-violet-50 px-2.5 py-0.5 text-[9px] font-mono font-semibold text-violet-700">Awaiting review</span>
              </div>
              <div className="h-7">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={approvalTrend}>
                    <defs>
                      <linearGradient id="appGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#7c3aed" stopOpacity={0.2}/>
                        <stop offset="95%" stopColor="#7c3aed" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <Area type="monotone" dataKey="v" stroke="#7c3aed" strokeWidth={1.5} fillOpacity={1} fill="url(#appGrad)" dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          </Card>
        </motion.div>
      </motion.div>

      {/* Row 2: Charts (2 Columns) */}
      <motion.div variants={itemVariants} className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Severity Distribution Donut */}
        <Card>
          <CardHeader>
            <CardTitle>Severity Distribution</CardTitle>
            <CardDescription>Threat categorization across active networks</CardDescription>
          </CardHeader>
          <CardContent className="h-56 flex items-center justify-center p-4">
            <div className="relative w-44 h-44 shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={75}
                    paddingAngle={2.5}
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <ChartTooltip 
                  contentStyle={{ background: "var(--chart-tooltip-bg)", border: "1px solid var(--border)", borderRadius: "12px", fontSize: "11px", boxShadow: "var(--shadow-card)" }} 
                  />
                </PieChart>
              </ResponsiveContainer>
              
              {/* Centered details */}
              <div className="absolute inset-0 flex flex-col items-center justify-center select-none pointer-events-none">
                <span className="text-xl font-bold font-mono tracking-tight text-slate-800">{incidents.length}</span>
                <span className="text-[8px] font-mono text-slate-400 uppercase tracking-widest">Security Issues</span>
              </div>
            </div>
            
            {/* Custom chart legend */}
            <div className="ml-8 space-y-2 text-xs font-mono select-none">
              {severityData.map((val, idx) => (
                <div key={idx} className="flex items-center space-x-2.5">
                  <span className="h-2 w-2 rounded-full shrink-0" style={{ backgroundColor: val.color }} />
                  <span className="text-slate-500 w-16 uppercase text-[10px]">{val.name}</span>
                  <span className="text-slate-800 font-bold text-[10.5px]">{val.value}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Endpoint Health Bar */}
        <Card>
          <CardHeader>
            <CardTitle>Endpoint Health Status</CardTitle>
            <CardDescription>Administrative segment connectivity index</CardDescription>
          </CardHeader>
          <CardContent className="h-56 p-4">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={endpointHealthData} barSize={26}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--chart-grid)" />
                <XAxis 
                  dataKey="name" 
                  tickLine={false} 
                  axisLine={false} 
                  tick={{ fontSize: 9, fontFamily: "monospace", fill: "var(--text-muted)" }} 
                />
                <YAxis 
                  tickLine={false} 
                  axisLine={false} 
                  tick={{ fontSize: 9, fontFamily: "monospace", fill: "var(--text-muted)" }} 
                />
                <ChartTooltip 
                  cursor={{ fill: "transparent" }}
                  contentStyle={{ background: "var(--chart-tooltip-bg)", border: "1px solid var(--border)", borderRadius: "12px", fontSize: "11px", boxShadow: "var(--shadow-card)" }} 
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {endpointHealthData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </motion.div>

      {/* Row 3: Recent Findings Table */}
      <motion.div variants={itemVariants}>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-3">
            <div>
              <CardTitle>Recent Detections</CardTitle>
              <CardDescription>Latest scan data indicators captured by active sensors</CardDescription>
            </div>
            <Button variant="outline" size="sm" className="font-mono text-[9px] h-7" onClick={() => navigate("/findings")}>
              TRIAGE VIEW
              <ChevronRight className="ml-1 h-3.5 w-3.5" />
            </Button>
          </CardHeader>
          <CardContent className="p-0 border-t border-slate-100">
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-slate-50/80 font-mono text-slate-400 border-b border-slate-200 uppercase tracking-wider">
                  <tr>
                    <th className="p-3 pl-4">Incident ID</th>
                    <th className="p-3">Threat Description</th>
                    <th className="p-3">Target Device</th>
                    <th className="p-3 hidden sm:table-cell">Security Category</th>
                    <th className="p-3 hidden md:table-cell">Incident State</th>
                    <th className="p-3 text-right pr-4">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono text-slate-600">
                  {incidents.slice(0, 3).map((inc: any) => (
                    <tr key={inc.id} className="hover:bg-slate-50/50 transition-premium">
                      <td className="p-3 pl-4 font-bold text-slate-800">{inc.id}</td>
                      <td className="p-3 font-sans text-slate-800 font-medium max-w-[240px] truncate" title={inc.title}>
                        {inc.title}
                      </td>
                      <td className="p-3 text-cyber-primary font-bold">{inc.hostname}</td>
                      <td className="p-3 text-slate-500 hidden sm:table-cell">{inc.category}</td>
                      <td className="p-3 hidden md:table-cell">
                        <StatusPill status={inc.status} />
                      </td>
                      <td className="p-3 text-right pr-4">
                        <button
                          onClick={() => navigate(`/findings`)}
                          className="text-cyber-primary hover:underline inline-flex items-center gap-1 text-[11px]"
                        >
                          Triage
                          <ArrowRight className="h-3 w-3" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Row 4: Attack Timeline */}
      <motion.div variants={itemVariants}>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-1.5">
              <Clock className="h-4 w-4 text-cyber-primary animate-pulse" />
              Containment Attack Timeline
            </CardTitle>
            <CardDescription>Chronological sequence of security actions and network blocks (Last 12 Hours)</CardDescription>
          </CardHeader>
          <CardContent className="p-4.5 pt-0">
            <div className="relative ml-2.5 space-y-3 border-l border-slate-200 dark:border-slate-800 pl-6 pt-3">
              {timelineEvents.length === 0 ? (
                <div className="text-xs text-slate-400 dark:text-slate-500 font-mono py-4">No recent security actions or detections logged.</div>
              ) : (
                timelineEvents.slice(0, 8).map((evt) => {
                  const styles = getTimelineStyles(evt.type);
                  return (
                    <div key={evt.id} className={cn("relative rounded-xl border p-3 transition-premium hover:-translate-y-0.5", styles.box)}>
                      <span className={cn("absolute -left-[31px] top-4.5 h-2.5 w-2.5 rounded-full border-2 border-white dark:border-slate-900", styles.bullet)} />
                      <div className="flex flex-col gap-1 text-xs sm:flex-row sm:items-center sm:justify-between">
                        <span className="font-semibold text-slate-800 dark:text-slate-200">{evt.title}</span>
                        <span className="w-fit rounded-full theme-surface px-2 py-0.5 text-[10px] font-medium theme-text-secondary shadow-sm">{evt.timestamp}</span>
                      </div>
                      <p className="text-[10.5px] text-slate-500 dark:text-slate-400 mt-0.5">
                        {evt.description}
                      </p>
                    </div>
                  );
                })
              )}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Row 5: AI Insight Card */}
      <motion.div variants={itemVariants}>
        <div className="rounded-md border border-blue-100 bg-blue-50/20 p-4.5 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="h-8 w-8 rounded bg-blue-50 text-cyber-primary border border-blue-100 flex items-center justify-center shrink-0 mt-0.5">
              <Sparkles className="h-4.5 w-4.5 text-cyber-primary animate-pulse" />
            </div>
            <div>
              <h4 className="text-xs font-bold font-mono tracking-wide text-blue-900 uppercase">AI Security Insight</h4>
              <p className="text-xs text-slate-600 mt-1 leading-relaxed max-w-3xl">
                We detected active elevated access attack routes over LSASS memory reading hooks on <span className="font-semibold text-slate-800">ad-dc-windows-01</span>. Isolating the workstation via the active playbook is recommended to prevent credentials dumping.
              </p>
            </div>
          </div>
          <Button 
            variant="cyber" 
            size="sm" 
            className="font-mono text-[9px] shrink-0 h-7.5 bg-blue-600 text-white hover:bg-blue-700 border border-blue-700"
            onClick={() => navigate("/copilot?query=analyze+lsass+memory+dump")}
          >
            ASK COPILOT
            <ArrowUpRight className="ml-1 h-3 w-3" />
          </Button>
        </div>
      </motion.div>
    </motion.div>
  );
}

export default DashboardPage;
