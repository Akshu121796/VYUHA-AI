import React, { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { 
  ShieldAlert, 
  Cpu, 
  HardDrive, 
  Network, 
  Clock, 
  Terminal, 
  CheckCircle,
  ShieldX,
  AlertTriangle,
  ArrowLeft,
  Server,
  Layers,
  Sparkles,
  ClipboardList,
  Activity,
  FileCode
} from "lucide-react";
import { 
  useEndpointDetailData, 
  useToggleIsolationMutation, 
  useTerminateProcessMutation 
} from "../../hooks/queries/useVyuhaQueries";
import { Endpoint, SystemProcess, CVEInfo } from "../../types";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../components/ui/Card";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from "../../components/ui/Table";
import { StatusPill } from "../../components/ui/StatusPill";
import { Skeleton } from "../../components/ui/Skeleton";
import { cn } from "../../utils/cn";

export function EndpointDetailsPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const { data: endpoint, isLoading } = useEndpointDetailData(id || "");
  const toggleIsolation = useToggleIsolationMutation();
  const terminateProcess = useTerminateProcessMutation();
  const [activeTab, setActiveTab] = useState<"overview" | "vulns" | "processes" | "logs" | "recommendations">("overview");

  if (isLoading || !endpoint) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-[120px] w-full mt-4" />
        <div className="flex gap-2 border-b border-border/60 pb-2 mt-4">
          <Skeleton className="h-8 w-24" />
          <Skeleton className="h-8 w-24" />
          <Skeleton className="h-8 w-24" />
        </div>
        <Skeleton className="h-64 w-full mt-4" />
      </div>
    );
  }

  // Calculate Health Score
  const healthScore = Math.max(
    10,
    100 - (endpoint.criticalAlertsCount * 40) - (endpoint.highAlertsCount * 15) - (endpoint.cves.length * 5)
  );

  // Calculate Risk Score (out of 10.0)
  const maxCveScore = endpoint.cves.length > 0 
    ? Math.max(...endpoint.cves.map((c: CVEInfo) => c.score)) 
    : endpoint.criticalAlertsCount > 0 ? 9.8 : 1.2;

  const handleTerminateProcess = (pid: number) => {
    terminateProcess.mutate({ id: endpoint.id, pid });
  };

  const handleToggleIsolation = () => {
    toggleIsolation.mutate(endpoint.id);
  };

  // Timeline events specific to host
  const hostEvents = [
    { time: "03:42:00 Z", desc: "Network socket isolation request registered.", type: "system" },
    { time: "03:38:00 Z", desc: "Suspicious administrative PowerShell invoke flagged.", type: "warning" },
    { time: "02:15:10 Z", desc: "Anti-malware baseline scan completed.", type: "info" },
    { time: "01:05:44 Z", desc: "Active Directory policy sync completed.", type: "info" }
  ];

  // Trace logs mock specific to host
  const traceLogs = [
    `[2026-07-12 03:42:00] [INFO] Scan agent version 2.4.1 checking in.`,
    `[2026-07-12 03:41:04] [WARN] Process spawn: powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand Q2xlYXI...`,
    `[2026-07-12 03:38:10] [ALERT] LSASS process memory dump dump query recorded on PID 652 by NT AUTHORITY\\SYSTEM`,
    `[2026-07-12 03:37:05] [INFO] Connection established: RDP session from 10.120.40.112:54890`,
    `[2026-07-12 03:12:44] [INFO] DNS lookup: ad-dc-windows-01.vyuha.internal resolved to ${endpoint.ip}`,
  ];

  // Playbook recommendations
  const recommendations = [
    { title: "Isolate network interface at Edge Switch", desc: "Sever RDP/SSH pathways to isolate host vectors while retaining SOC VPN channels." },
    { title: "Patch Netlogon protocol (Zerologon weakness)", desc: "Enforce domain controller registry keys to mandate secure Netlogon channels." },
    { title: "Audit local administrator groups", desc: "Review workstation access groups to restrict lateral movement credential dumps." }
  ];

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb & Actions */}
      <div className="flex items-center justify-between border-b border-slate-200 pb-4">
        <div className="flex items-center space-x-2 text-xs font-mono">
          <Button variant="ghost" size="icon" className="h-7 w-7 text-slate-400" onClick={() => navigate(-1)}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <span className="text-slate-300">/</span>
          <span className="text-brand-secondary hover:text-slate-900 cursor-pointer" onClick={() => navigate("/endpoints")}>DEVICES</span>
          <span className="text-slate-300">/</span>
          <span className="text-slate-900 font-semibold">{endpoint.hostname}</span>
        </div>
        <div className="flex gap-2.5 font-mono">
          <Button
            variant={endpoint.status === "isolated" ? "cyber" : "destructive"}
            size="sm"
            className="text-[10px]"
            onClick={handleToggleIsolation}
          >
            <ShieldX className="mr-1.5 h-3.5 w-3.5" />
            {endpoint.status === "isolated" ? "RECONNECT NETWORK" : "ISOLATE DEVICE"}
          </Button>
        </div>
      </div>

      {/* Top Hero Card */}
      <Card className="border-slate-200 bg-white relative overflow-hidden shadow-card">
        {/* Decorative Top Accent line */}
        <div className={cn(
          "absolute top-0 left-0 right-0 h-[1.5px]",
          healthScore > 80 ? "bg-cyber-low" : healthScore > 50 ? "bg-cyber-high" : "bg-cyber-critical"
        )} />
        
        <CardContent className="p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
          <div className="space-y-3.5">
            <div className="flex flex-wrap items-center gap-3">
              <h2 className="text-xl font-bold font-sans tracking-tight text-slate-900">{endpoint.hostname}</h2>
              <StatusPill status={endpoint.status} />
              <Badge variant="outline" className="font-mono text-[9px] lowercase bg-slate-50 border-slate-200 text-slate-500">{endpoint.policyGroup}</Badge>
            </div>
            
            {/* Meta Grid details */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-2 font-mono text-[10px] text-slate-500">
              <div>
                <span className="text-slate-400 block uppercase">OS Target</span>
                <span className="text-slate-800 font-sans mt-0.5 block">{endpoint.os} ({endpoint.osVersion})</span>
              </div>
              <div>
                <span className="text-slate-400 block uppercase">IP Address</span>
                <span className="text-slate-800 mt-0.5 block">{endpoint.ip}</span>
              </div>
              <div>
                <span className="text-slate-400 block uppercase">MAC Address</span>
                <span className="text-slate-800 mt-0.5 block">{endpoint.mac}</span>
              </div>
              <div>
                <span className="text-slate-400 block uppercase">Last Scanned Ingest</span>
                <span className="text-slate-800 mt-0.5 block">{new Date(endpoint.lastSeen).toLocaleTimeString()}</span>
              </div>
            </div>
          </div>

          {/* Health Index Rating */}
          <div className="flex items-center space-x-3 bg-slate-50 border border-slate-200 p-3.5 rounded-md shrink-0 select-none shadow-sm">
            <div className="text-center font-mono">
              <span className="text-[9px] uppercase tracking-wider text-slate-400 block font-semibold">Health Rating</span>
              <span className={cn(
                "text-2xl font-bold tracking-tight block mt-0.5",
                healthScore > 80 ? "text-cyber-low" : healthScore > 50 ? "text-cyber-high" : "text-cyber-critical"
              )}>
                {healthScore}%
              </span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Tabs Selector Navigation */}
      <div className="flex border-b border-slate-200 font-mono text-[11px] select-none gap-2">
        {(["overview", "vulns", "processes", "logs", "recommendations"] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={cn(
              "px-4 py-2 border-b-2 font-medium tracking-wide uppercase transition-premium cursor-pointer -mb-[1px]",
              activeTab === tab
                ? "border-cyber-primary text-slate-900 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-900"
            )}
          >
            {tab === "vulns" ? "Weaknesses" : tab}
          </button>
        ))}
      </div>

      {/* Tabs Contents render frame */}
      <div className="pt-2">
        {/* Tab 1: Overview */}
        {activeTab === "overview" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
            
            {/* Risk Gauge & AI Summary Card (Left/Center Column) */}
            <div className="lg:col-span-2 space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* SVG Risk score Dial */}
                <Card className="flex flex-col items-center justify-center p-5 min-h-[200px] shadow-card">
                  <CardHeader className="text-center border-b-0 pb-0">
                    <CardTitle className="text-slate-700">Device Risk Level</CardTitle>
                    <CardDescription>
                      Maximum CVSS score <span className="inline-flex items-center justify-center cursor-help text-blue-500 hover:text-blue-400 dark:text-blue-400 dark:hover:text-blue-300 font-bold ml-1.5 text-[13px] select-none transition-colors align-middle" title="Common Vulnerability Scoring System, a standard for rating security weaknesses.">ⓘ</span> registered on this host
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="pt-4 flex flex-col items-center justify-center relative w-full h-[140px]">
                    {/* SVG Radial Gauge */}
                    <svg className="w-24 h-24 transform -rotate-90">
                      {/* background circle */}
                      <circle cx="48" cy="48" r="40" stroke="#f1f5f9" strokeWidth="6" fill="transparent" />
                      {/* Colored metric arc */}
                      <circle
                        cx="48"
                        cy="48"
                        r="40"
                        stroke={maxCveScore > 8 ? "#ef4444" : maxCveScore > 5 ? "#f97316" : "#3b82f6"}
                        strokeWidth="6"
                        fill="transparent"
                        strokeDasharray={251.2}
                        strokeDashoffset={251.2 - (251.2 * maxCveScore) / 10}
                        strokeLinecap="round"
                        className="transition-all duration-500"
                      />
                    </svg>
                    {/* Score Text Overlay */}
                    <div className="absolute inset-0 flex flex-col items-center justify-center pt-2 select-none">
                      <span className="font-mono text-xl font-bold text-slate-800">{maxCveScore.toFixed(1)}</span>
                      <span className="font-mono text-[8px] text-slate-400 uppercase">CVSS Max</span>
                    </div>
                  </CardContent>
                </Card>

                {/* Performance indicators */}
                <Card className="p-5 flex flex-col justify-between min-h-[200px] shadow-card">
                  <CardHeader className="border-b-0 p-0 pb-2">
                    <CardTitle className="text-slate-700">Active Resources Load</CardTitle>
                  </CardHeader>
                  <CardContent className="p-0 space-y-3 pt-2">
                    {/* CPU */}
                    <div className="space-y-1">
                      <div className="flex justify-between text-[10px] font-mono">
                        <span className="text-slate-500">CPU load</span>
                        <span className="text-slate-800 font-bold">{endpoint.cpuUsage}%</span>
                      </div>
                      <div className="h-1.5 bg-slate-100 border border-slate-200/50 rounded-full overflow-hidden">
                        <div 
                          className={cn("h-full rounded-full", endpoint.cpuUsage > 80 ? "bg-cyber-critical" : "bg-cyber-primary")}
                          style={{ width: `${endpoint.cpuUsage}%` }}
                        />
                      </div>
                    </div>

                    {/* RAM */}
                    <div className="space-y-1">
                      <div className="flex justify-between text-[10px] font-mono">
                        <span className="text-slate-500">Memory load</span>
                        <span className="text-slate-800 font-bold">{endpoint.memoryUsage}%</span>
                      </div>
                      <div className="h-1.5 bg-slate-100 border border-slate-200/50 rounded-full overflow-hidden">
                        <div 
                          className={cn("h-full rounded-full", endpoint.memoryUsage > 80 ? "bg-cyber-critical" : "bg-cyber-primary")}
                          style={{ width: `${endpoint.memoryUsage}%` }}
                        />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* AI Copilot summary block */}
              <Card className="border-blue-200 bg-blue-50/20 relative overflow-hidden subtle-glass">
                <CardContent className="p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                  <div className="flex items-start gap-4">
                    <div className="h-8.5 w-8.5 shrink-0 bg-blue-50 border border-blue-100 text-cyber-primary flex items-center justify-center rounded">
                      <Sparkles className="h-4.5 w-4.5" />
                    </div>
                    <div className="space-y-1">
                      <span className="text-[10px] font-mono uppercase tracking-wider text-blue-900 font-bold block">
                        VYUHA.AI Host Audit Insights
                      </span>
                      <p className="text-xs text-slate-600 leading-relaxed font-sans max-w-[640px]">
                        {endpoint.id === "web-prod-ubuntu-01" ? (
                          "Host web-prod-ubuntu-01 is exhibiting high network activity logs matching xz backdoor campaign indicators. Backdoor binary utils present inside server repository. Immediate switch isolation of the RDP VLAN is recommended."
                        ) : (
                          "Host ad-dc-windows-01 domain controller indicates active credential dump events targeting local lsass.exe process memory handlers. Terminating NT parent administration shells is recommended."
                        )}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Event Timeline (Right Column) */}
            <div className="space-y-4">
              <Card className="shadow-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-1.5 text-slate-700">
                    <Clock className="h-4 w-4 text-cyber-primary animate-pulse" />
                    Recent Device Events
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-4 pt-1">
                  <div className="relative pl-5 border-l border-slate-200 ml-2 space-y-4 pt-2">
                    {hostEvents.map((evt, idx) => (
                      <div key={idx} className="relative">
                        <span className={cn(
                          "absolute -left-[26px] top-1 h-2.5 w-2.5 rounded-full border-2 border-white shadow-sm",
                          evt.type === "system" && "bg-cyber-critical pulse-red",
                          evt.type === "warning" && "bg-cyber-high pulse-orange",
                          evt.type === "info" && "bg-cyber-primary"
                        )} />
                        <span className="font-mono text-[9px] text-slate-400 block">{evt.time}</span>
                        <p className="text-xs font-sans text-slate-600 mt-0.5">{evt.desc}</p>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        )}

        {/* Tab 2: Vulnerabilities */}
        {activeTab === "vulns" && (
          <Card className="shadow-card">
            <CardHeader className="flex flex-row items-center justify-between pb-3">
              <div>
                <CardTitle className="text-slate-700">Identified CVE Weaknesses</CardTitle>
                <CardDescription>Known security weaknesses detected inside server library components</CardDescription>
              </div>
              <Badge severity="critical" className="h-4 px-1">{endpoint.cves.length} DETECTED</Badge>
            </CardHeader>
            <CardContent className="p-0 border-t border-slate-200">
              {endpoint.cves.length === 0 ? (
                <div className="py-12 text-center text-xs font-mono text-cyber-low bg-cyber-low/5">
                  ✓ ZERO ACTIVE CVE WEAKNESSES DETECTED ON THIS DEVICE
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader className="bg-slate-50/50">
                      <TableRow className="border-b border-slate-200">
                        <TableHead className="pl-4 font-semibold text-slate-500">CVE ID</TableHead>
                        <TableHead className="font-semibold text-slate-500">CVSS Score</TableHead>
                        <TableHead className="font-semibold text-slate-500">Severity</TableHead>
                        <TableHead className="font-semibold text-slate-500 hidden md:table-cell">Description</TableHead>
                        <TableHead className="text-right pr-4 font-semibold text-slate-500 hidden sm:table-cell">Disclosed Date</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody className="bg-white divide-y divide-slate-100">
                      {endpoint.cves.map((cve: CVEInfo) => (
                        <TableRow key={cve.id} className="hover:bg-slate-50/50 transition-premium">
                          <TableCell className="pl-4 font-bold text-slate-800 font-mono">{cve.id}</TableCell>
                          <TableCell className="font-bold text-slate-800 font-mono">{cve.score.toFixed(1)}</TableCell>
                          <TableCell>
                            <Badge severity={cve.severity} className="h-4.5 px-1.5">{cve.severity}</Badge>
                          </TableCell>
                          <TableCell className="max-w-[320px] font-sans truncate text-slate-650 hidden md:table-cell" title={cve.description}>
                            {cve.description}
                          </TableCell>
                          <TableCell className="text-right pr-4 text-slate-400 font-mono hidden sm:table-cell">{cve.publishDate}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Tab 3: Processes */}
        {activeTab === "processes" && (
          <Card className="shadow-card">
            <CardHeader>
              <CardTitle className="text-slate-700">System Process Registry</CardTitle>
              <CardDescription>Live execution hooks recorded inside memory blocks</CardDescription>
            </CardHeader>
            <CardContent className="p-0 border-t border-slate-200">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader className="bg-slate-50/50">
                    <TableRow className="border-b border-slate-200">
                      <TableHead className="pl-4 font-semibold text-slate-500">PID</TableHead>
                      <TableHead className="font-semibold text-slate-500">Process Name</TableHead>
                      <TableHead className="font-semibold text-slate-500 hidden md:table-cell">CPU %</TableHead>
                      <TableHead className="font-semibold text-slate-500 hidden sm:table-cell">Memory (MB)</TableHead>
                      <TableHead className="font-semibold text-slate-500">Status</TableHead>
                      <TableHead className="text-right pr-4 font-semibold text-slate-500">Remediation</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody className="bg-white divide-y divide-slate-100">
                    {endpoint.processes.map((proc: any) => (
                      <TableRow 
                        key={proc.pid} 
                        className={cn(
                          "hover:bg-slate-50/50 transition-premium",
                          proc.status === "suspicious" && "bg-red-50/30",
                          proc.status === "terminated" && "opacity-40 bg-slate-50/20"
                        )}
                      >
                        <TableCell className="pl-4 font-mono text-slate-400">{proc.pid}</TableCell>
                        <TableCell className={cn(
                          "font-mono font-semibold",
                          proc.status === "suspicious" ? "text-cyber-critical" : "text-slate-800"
                        )}>
                          {proc.name}
                        </TableCell>
                        <TableCell className="font-mono text-slate-600 hidden md:table-cell">{proc.cpu}%</TableCell>
                        <TableCell className="font-mono text-slate-600 hidden sm:table-cell">{proc.memory} MB</TableCell>
                        <TableCell>
                          <StatusPill status={proc.status} />
                        </TableCell>
                        <TableCell className="text-right pr-4">
                          {proc.status === "suspicious" && (
                            <Button
                              variant="destructive"
                              size="sm"
                              className="h-6 rounded text-[9px] font-mono px-2"
                              onClick={() => handleTerminateProcess(proc.pid)}
                            >
                              KILL PROCESS
                            </Button>
                          )}
                          {proc.status === "terminated" && (
                            <span className="text-[10px] text-slate-400 italic">Terminated</span>
                          )}
                          {proc.status === "running" && (
                            <span className="text-[10px] text-slate-300">-</span>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Tab 4: Logs */}
        {activeTab === "logs" && (
          <Card className="shadow-card">
            <CardHeader className="flex flex-row items-center justify-between pb-3">
              <div>
                <CardTitle className="text-slate-700">Trace Logs Scan Data</CardTitle>
                <CardDescription>Ingested kernel event logs for domain diagnostic triaging</CardDescription>
              </div>
              <Terminal className="h-4 w-4 text-slate-400" />
            </CardHeader>
            <CardContent className="p-4 border-t border-slate-200 bg-slate-950 rounded-b-md">
              <pre className="font-mono text-[10px] text-slate-200 leading-relaxed overflow-x-auto whitespace-pre-wrap">
                {traceLogs.join("\n")}
              </pre>
            </CardContent>
          </Card>
        )}

        {/* Tab 5: Recommendations */}
        {activeTab === "recommendations" && (
          <div className="space-y-4">
            <h3 className="text-xs font-mono font-bold tracking-wider text-slate-400 uppercase flex items-center gap-1.5 pl-1">
              <ClipboardList className="h-4 w-4 text-cyber-primary" /> Copilot Playbooks & Patches
            </h3>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {recommendations.map((rec, idx) => (
                <Card key={idx} className="bg-white border-slate-200 hover:border-brand-accent/40 shadow-card hover:shadow-premium transition-all flex flex-col justify-between rounded-md overflow-hidden">
                  <CardHeader className="pb-2 bg-slate-50/30">
                    <CardTitle className="font-mono text-[10.5px] leading-tight text-slate-800">{rec.title}</CardTitle>
                  </CardHeader>
                  <CardContent className="p-4 pt-3 text-[10px] text-slate-500 font-sans leading-relaxed">
                    {rec.desc}
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default EndpointDetailsPage;
