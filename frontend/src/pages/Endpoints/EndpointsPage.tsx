import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { 
  Search, 
  ArrowUpRight, 
  Server,
  ArrowLeft
} from "lucide-react";
import { useEndpointsData } from "../../hooks/queries/useVyuhaQueries";
import { Card, CardContent } from "../../components/ui/Card";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { Input } from "../../components/ui/Input";
import { StatusPill } from "../../components/ui/StatusPill";
import { EmptyState } from "../../components/ui/EmptyState";
import { Skeleton } from "../../components/ui/Skeleton";
import { cn } from "../../utils/cn";
import { Endpoint } from "../../types";

export function EndpointsPage() {
  const navigate = useNavigate();
  const { data: endpoints, isLoading } = useEndpointsData();
  const [search, setSearch] = useState("");
  const [osFilter, setOsFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  if (isLoading || !endpoints) {
    return (
      <div className="space-y-6">
        <div className="h-10 w-48 bg-slate-200/60 animate-pulse rounded-md" />
        <Skeleton className="h-12 w-full rounded-md" />
        <Skeleton className="h-[280px] w-full mt-4 rounded-md" />
      </div>
    );
  }

  const filteredEndpoints = endpoints.filter((ep: Endpoint) => {
    const matchesSearch = 
      ep.hostname.toLowerCase().includes(search.toLowerCase()) ||
      ep.ip.toLowerCase().includes(search.toLowerCase()) ||
      ep.policyGroup.toLowerCase().includes(search.toLowerCase());

    const matchesOs = osFilter === "all" || ep.os.toLowerCase().includes(osFilter.toLowerCase());
    const matchesStatus = statusFilter === "all" || ep.status === statusFilter;

    return matchesSearch && matchesOs && matchesStatus;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 border-b border-slate-200/70 pb-5 dark:border-slate-800/70 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 font-sans dark:text-slate-100">
            Assets Directory
          </h1>
          <p className="mt-1 text-xs text-slate-500 font-sans dark:text-slate-400">
            Audit hardware telemetry, OS kernel builds, and live CPU resource metrics across enrollment groups.
          </p>
        </div>
        <div>
          <Button variant="ghost" size="icon" className="h-7 w-7 text-slate-400" onClick={() => navigate("/")}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="flex flex-col gap-4 rounded-[20px] border border-slate-200/80 bg-white/80 p-3.5 shadow-sm backdrop-blur dark:border-slate-800 dark:bg-slate-950/70 md:flex-row md:items-center md:justify-between">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search */}
          <div className="relative w-[220px]">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
            <Input
              placeholder="Search hostname, IP, policy..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 h-8 text-xs font-mono border-slate-200 bg-slate-50/50"
            />
          </div>

          {/* OS Filter */}
          <div className="flex border border-slate-200 rounded-md overflow-hidden bg-slate-50 h-8 text-[11px] font-mono shadow-sm">
            <button
              onClick={() => setOsFilter("all")}
              className={cn("px-2.5 transition-colors cursor-pointer", osFilter === "all" ? "bg-white text-slate-900 font-semibold shadow-sm" : "text-slate-400 hover:text-slate-900")}
            >
              ALL OS
            </button>
            <button
              onClick={() => setOsFilter("windows")}
              className={cn("px-2.5 border-l border-slate-200 transition-colors cursor-pointer", osFilter === "windows" ? "bg-white text-slate-900 font-semibold shadow-sm" : "text-slate-400 hover:text-slate-900")}
            >
              WINDOWS
            </button>
            <button
              onClick={() => setOsFilter("linux")}
              className={cn("px-2.5 border-l border-slate-200 transition-colors cursor-pointer", osFilter === "linux" ? "bg-white text-slate-900 font-semibold shadow-sm" : "text-slate-400 hover:text-slate-900")}
            >
              LINUX
            </button>
            <button
              onClick={() => setOsFilter("macos")}
              className={cn("px-2.5 border-l border-slate-200 transition-colors cursor-pointer", osFilter === "macos" ? "bg-white text-slate-900 font-semibold shadow-sm" : "text-slate-400 hover:text-slate-900")}
            >
              MAC
            </button>
          </div>

          {/* Status Filter */}
          <div className="flex border border-slate-200 rounded-md overflow-hidden bg-slate-50 h-8 text-[11px] font-mono shadow-sm">
            <button
              onClick={() => setStatusFilter("all")}
              className={cn("px-2.5 transition-colors cursor-pointer", statusFilter === "all" ? "bg-white text-slate-900 font-semibold shadow-sm" : "text-slate-400 hover:text-slate-900")}
            >
              ALL STATES
            </button>
            <button
              onClick={() => setStatusFilter("online")}
              className={cn("px-2.5 border-l border-slate-200 transition-colors cursor-pointer", statusFilter === "online" ? "bg-white text-slate-900 font-semibold shadow-sm" : "text-slate-450 hover:text-slate-900")}
            >
              ONLINE
            </button>
            <button
              onClick={() => setStatusFilter("isolated")}
              className={cn("px-2.5 border-l border-slate-200 transition-colors cursor-pointer", statusFilter === "isolated" ? "bg-white text-slate-900 font-semibold shadow-sm" : "text-slate-450 hover:text-slate-900")}
            >
              ISOLATED
            </button>
          </div>
        </div>

        <div className="text-[10px] font-mono text-slate-400 dark:text-slate-500">
          Showing {filteredEndpoints.length} of {endpoints.length} enrolled systems
        </div>
      </div>

      {/* Main Grid View */}
      {filteredEndpoints.length === 0 ? (
        <EmptyState
          title="No assets matching filters"
          description="We couldn't locate any enrolled endpoints matching your active search parameter or filters."
          actionLabel="CLEAR ALL FILTERS"
          onAction={() => {
            setSearch("");
            setOsFilter("all");
            setStatusFilter("all");
          }}
        />
      ) : (
        <Card className="overflow-hidden rounded-[20px] border-slate-200 bg-white/90 shadow-card dark:border-slate-800 dark:bg-slate-950/80">
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left border-collapse">
                <thead className="border-b border-slate-200 bg-slate-50/50 font-mono uppercase tracking-wider text-slate-550 dark:border-slate-800 dark:bg-slate-900/70 dark:text-slate-400">
                  <tr>
                    <th className="p-3.5 pl-4 font-semibold">Hostname</th>
                    <th className="p-3.5 font-semibold hidden sm:table-cell">Platform</th>
                    <th className="p-3.5 font-semibold hidden md:table-cell">IP Address</th>
                    <th className="p-3.5 font-semibold hidden md:table-cell">Policy Group</th>
                    <th className="p-3.5 font-semibold hidden lg:table-cell">Resource Load</th>
                    <th className="p-3.5 font-semibold">Vulnerability CVEs</th>
                    <th className="p-3.5 font-semibold">Network Status</th>
                    <th className="p-3.5 text-right pr-4 font-semibold">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 bg-white font-mono text-slate-650 dark:divide-slate-800 dark:bg-slate-950/50 dark:text-slate-300">
                  {filteredEndpoints.map((ep: Endpoint) => (
                    <tr key={ep.id} className="transition-premium hover:bg-slate-50/50 dark:hover:bg-slate-900/70">
                      {/* Hostname */}
                      <td className="p-3.5 pl-4 font-semibold text-slate-800">
                        <div className="flex items-center space-x-2">
                          <Server className="h-3.5 w-3.5 text-cyber-primary" />
                          <span>{ep.hostname}</span>
                        </div>
                      </td>

                      {/* OS Platform */}
                      <td className="p-3.5 text-slate-500 font-sans hidden sm:table-cell">{ep.os}</td>

                      {/* IP */}
                      <td className="p-3.5 text-slate-500 hidden md:table-cell">{ep.ip}</td>

                      {/* Policy Group */}
                      <td className="p-3.5 text-cyber-primary hidden md:table-cell">{ep.policyGroup}</td>

                      {/* Resource Meters */}
                      <td className="p-3.5 max-w-[160px] hidden lg:table-cell">
                        <div className="space-y-1.5 font-sans">
                          {/* CPU mini progress */}
                          <div className="flex items-center justify-between text-[9px] text-slate-400 font-mono">
                            <span>CPU {ep.cpuUsage}%</span>
                            <span>RAM {ep.memoryUsage}%</span>
                          </div>
                          <div className="flex gap-1.5">
                            {/* CPU Bar */}
                            <div className="h-1.5 bg-slate-100 border border-slate-200/50 rounded-full overflow-hidden flex-1">
                              <div 
                                className={cn("h-full rounded-full", ep.cpuUsage > 80 ? "bg-cyber-critical" : "bg-cyber-primary")}
                                style={{ width: `${ep.cpuUsage}%` }}
                              />
                            </div>
                            {/* RAM Bar */}
                            <div className="h-1.5 bg-slate-100 border border-slate-200/50 rounded-full overflow-hidden flex-1">
                              <div 
                                className={cn("h-full rounded-full", ep.memoryUsage > 80 ? "bg-cyber-critical" : "bg-cyber-primary")}
                                style={{ width: `${ep.memoryUsage}%` }}
                              />
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* CVE Badge */}
                      <td className="p-3.5">
                        {ep.cves.length > 0 ? (
                          <Badge variant="critical" className="h-4.5 text-[8.5px] px-1.5 font-bold">
                            {ep.cves.length} DETECTED
                          </Badge>
                        ) : (
                          <span className="text-[10px] text-cyber-low font-bold">✓ SECURE</span>
                        )}
                      </td>

                      {/* Status */}
                      <td className="p-3.5">
                        <StatusPill status={ep.status} />
                      </td>

                      {/* Action */}
                      <td className="p-3.5 text-right pr-4">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-[10px]"
                          onClick={() => navigate(`/endpoints/${ep.id}`)}
                        >
                          TELEMETRY
                          <ArrowUpRight className="ml-1 h-3 w-3 text-slate-400" />
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default EndpointsPage;
