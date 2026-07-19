import React, { useState, useEffect, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import {
  ColumnDef,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  useReactTable,
  SortingState,
} from "@tanstack/react-table";
import { 
  ShieldAlert, 
  Search, 
  ArrowRight, 
  ShieldX, 
  CheckCircle, 
  Eye, 
  Sparkles,
  Server,
  ChevronDown,
  ChevronUp,
  ChevronsLeft,
  ChevronsRight,
  ChevronLeft,
  ChevronRight,
  RefreshCw
} from "lucide-react";
import { useIncidentsData, useUpdateIncidentMutation, useResetTelemetryMutation } from "../../hooks/queries/useVyuhaQueries";
import { Incident, Severity, IncidentStatus } from "../../types";
import { Card, CardContent } from "../../components/ui/Card";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { Input } from "../../components/ui/Input";
import { StatusPill } from "../../components/ui/StatusPill";
import { EmptyState } from "../../components/ui/EmptyState";
import { Skeleton } from "../../components/ui/Skeleton";
import { cn } from "../../utils/cn";
import { toast } from "sonner";

export function FindingsPage() {
  const navigate = useNavigate();

  const { data: incidentsData, isLoading } = useIncidentsData();
  const updateIncident = useUpdateIncidentMutation();
  const resetTelemetry = useResetTelemetryMutation();

  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);

  // Sync selectedIncident when data finishes loading
  useEffect(() => {
    if (incidentsData && incidentsData.length > 0 && !selectedIncident) {
      setSelectedIncident(incidentsData[0]);
    }
  }, [incidentsData, selectedIncident]);

  // Filters State
  const [globalSearch, setGlobalSearch] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | "all">("all");
  const [selectedStatus, setSelectedStatus] = useState<IncidentStatus | "all">("all");

  // Sorting State
  const [sorting, setSorting] = useState<SortingState>([]);

  // Filter local database before passing it to react-table
  const filteredData = useMemo(() => {
    const list = incidentsData || [];
    return list.filter((inc: Incident) => {
      const matchesSeverity = selectedSeverity === "all" || inc.severity === selectedSeverity;
      const matchesStatus = selectedStatus === "all" || inc.status === selectedStatus;
      return matchesSeverity && matchesStatus;
    });
  }, [incidentsData, selectedSeverity, selectedStatus]);

  // TanStack table columns definition
  const columns = useMemo<ColumnDef<Incident>[]>(
    () => [
      {
        accessorKey: "hostname",
        header: "Endpoint",
        cell: (info) => (
          <div className="flex items-center space-x-2">
            <Server className="h-3.5 w-3.5 text-cyber-primary" />
            <span className="font-semibold text-foreground font-mono">{info.getValue() as string}</span>
          </div>
        ),
      },
      {
        accessorKey: "id",
        header: "CVE / Incident",
        cell: (info) => {
          const row = info.row.original;
          const cveId = row.id === "INC-2026-0041" ? "CVE-2021-34527" : row.id === "INC-2026-0042" ? "CVE-2024-3094" : row.id === "INC-2026-0044" ? "CVE-2023-38408" : "N/A";
          return (
            <div className="space-y-0.5">
              <span className="font-mono font-bold text-foreground block">{cveId}</span>
              <span className="text-[9px] text-zinc-500 block font-mono">{row.id}</span>
            </div>
          );
        }
      },
      {
        accessorKey: "severity",
        header: "Severity",
        cell: (info) => <Badge severity={info.getValue() as Severity}>{info.getValue() as string}</Badge>,
      },
      {
        id: "riskScore",
        accessorKey: "severity",
        header: "Risk Score",
        cell: (info) => {
          const val = info.getValue() as string;
          const score = val === "critical" ? 10.0 : val === "high" ? 8.8 : val === "medium" ? 6.5 : 3.2;
          return (
            <span className="font-bold font-mono text-foreground">
              {score.toFixed(1)}
            </span>
          );
        }
      },
      {
        accessorKey: "status",
        header: "Status",
        cell: (info) => <StatusPill status={info.getValue() as IncidentStatus} />,
      },
      {
        accessorKey: "timestamp",
        header: "Last Seen",
        cell: (info) => (
          <span className="text-zinc-500 font-mono text-[10px]">
            {new Date(info.getValue() as string).toLocaleTimeString()}
          </span>
        ),
      },
      {
        id: "actions",
        header: () => <div className="text-right pr-2">Action</div>,
        cell: (info) => (
          <div className="text-right pr-2">
            <Button
              variant="ghost"
              size="sm"
              className="h-6 rounded-sm text-[9px] font-mono px-2"
              onClick={(e) => {
                e.stopPropagation(); // prevent row click activation
                setSelectedIncident(info.row.original);
              }}
            >
              DETAILS
            </Button>
          </div>
        ),
      },
    ],
    []
  );

  // TanStack table hooks
  const table = useReactTable({
    data: filteredData,
    columns,
    state: {
      sorting,
      globalFilter: globalSearch,
    },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalSearch,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: {
      pagination: {
        pageSize: 5
      }
    }
  });

  const handleUpdateStatus = (id: string, newStatus: IncidentStatus) => {
    updateIncident.mutate({ id, status: newStatus }, {
      onSuccess: (data) => {
        setSelectedIncident(data);
      }
    });
  };

  const clearFilters = () => {
    setGlobalSearch("");
    setSelectedSeverity("all");
    setSelectedStatus("all");
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 border-b border-slate-200/70 pb-5 dark:border-slate-800/70 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-xl font-medium tracking-tight text-slate-900 font-mono dark:text-slate-100">
            SYS.DETECTION_LOGS
          </h1>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Triaging security findings across monitored corporate endpoints using TanStack datagrids.
          </p>
        </div>
        <div className="flex gap-2">
          <Button 
            variant="outline" 
            size="sm" 
            className="font-mono text-[10px]" 
            disabled={resetTelemetry.isPending}
            onClick={() => {
              resetTelemetry.mutate(undefined, {
                onSuccess: () => {
                  toast.success("Telemetry logs reset to initial active state.");
                },
                onError: (err: any) => {
                  toast.error("Failed to reset telemetry: " + (err.message || "Unknown error"));
                }
              });
            }}
          >
            <RefreshCw className={cn("mr-1.5 h-3 w-3 text-brand-secondary", resetTelemetry.isPending && "animate-spin")} />
            {resetTelemetry.isPending ? "RESETTING..." : "RESET TELEMETRY"}
          </Button>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="flex flex-col gap-4 rounded-[20px] border border-slate-200/80 bg-white/80 p-3.5 shadow-sm backdrop-blur dark:border-slate-800 dark:bg-slate-950/70 md:flex-row md:items-center md:justify-between">
        <div className="flex flex-wrap items-center gap-3">
          {/* Advanced Search Input */}
          <div className="relative w-[220px]">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
            <Input
              placeholder="Search assets, IDs..."
              value={globalSearch}
              onChange={(e) => setGlobalSearch(e.target.value)}
              className="pl-9 h-8 text-xs font-mono border-slate-200 bg-slate-50/50"
            />
          </div>

          {/* Severity Filters */}
          <div className="flex border border-slate-200 rounded-md overflow-hidden bg-slate-50 h-8 text-[11.5px] font-mono shadow-sm">
            <button
              onClick={() => setSelectedSeverity("all")}
              className={cn("px-3 transition-colors", selectedSeverity === "all" ? "bg-white text-slate-800 font-semibold shadow-sm dark:bg-slate-800 dark:text-slate-100" : "text-slate-400 hover:text-slate-900 dark:hover:text-slate-100")}
            >
              ALL
            </button>
            {["critical", "high", "medium", "low"].map(sev => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev as Severity)}
                className={cn(
                  "px-3 border-l border-slate-200 transition-all uppercase dark:border-slate-700",
                  selectedSeverity === sev ? "bg-white text-slate-900 font-semibold shadow-sm dark:bg-slate-800 dark:text-slate-100" : "text-slate-400 hover:text-slate-900 dark:hover:text-slate-100",
                  selectedSeverity === sev && sev === "critical" && "text-cyber-critical",
                  selectedSeverity === sev && sev === "high" && "text-cyber-high",
                  selectedSeverity === sev && sev === "medium" && "text-cyber-medium",
                  selectedSeverity === sev && sev === "low" && "text-cyber-low"
                )}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Status Filters */}
          <div className="flex border border-slate-200 rounded-md overflow-hidden bg-slate-50 h-8 text-[11.5px] font-mono shadow-sm">
            <button
              onClick={() => setSelectedStatus("all")}
              className={cn("px-3 transition-colors", selectedStatus === "all" ? "bg-white text-slate-900 font-semibold shadow-sm" : "text-slate-400 hover:text-slate-900")}
            >
              ALL STATES
            </button>
            <button
              onClick={() => setSelectedStatus("active")}
              className={cn("px-3 border-l border-slate-200 transition-colors", selectedStatus === "active" ? "bg-white text-slate-900 font-semibold shadow-sm" : "text-slate-400 hover:text-slate-900")}
            >
              ACTIVE
            </button>
            <button
              onClick={() => setSelectedStatus("resolved")}
              className={cn("px-3 border-l border-slate-200 transition-colors", selectedStatus === "resolved" ? "bg-white text-slate-900 font-semibold shadow-sm" : "text-slate-400 hover:text-slate-900")}
            >
              RESOLVED
            </button>
          </div>
        </div>

        <div className="text-[10px] font-mono text-slate-400 dark:text-slate-500">
          Filtered {filteredData.length} records
        </div>
      </div>

      {/* Main Split Grid */}
      <div className="flex flex-col xl:flex-row gap-6 items-start">
        
        {/* TanStack Table Card (62% width) */}
        <div className="w-full xl:w-[62%] space-y-4 shrink-0">
          <div className="relative border border-slate-200 rounded-md overflow-hidden bg-white shadow-card h-[460px] overflow-auto">
            
            {/* Skeletons load */}
            {isLoading ? (
              <div className="p-4 space-y-4">
                <Skeleton className="h-10 w-full rounded" />
                <Skeleton className="h-10 w-full rounded" />
                <Skeleton className="h-10 w-full rounded" />
                <Skeleton className="h-10 w-full rounded" />
                <Skeleton className="h-10 w-full rounded" />
              </div>
            ) : table.getRowModel().rows.length === 0 ? (
              <div className="h-full flex items-center justify-center p-6 bg-slate-50/30">
                <EmptyState
                  title="No detections match parameters"
                  description="We couldn't locate any findings matching your active filter configuration. Clear queries to rebuild telemetry."
                  actionLabel="RESET CONSOLE FILTERS"
                  onAction={clearFilters}
                />
              </div>
            ) : (
              <table className="w-full text-xs text-left border-collapse">
                {/* Sticky headers */}
                <thead className="bg-slate-50/95 backdrop-blur-sm border-b border-slate-200 font-mono text-slate-500 uppercase tracking-wider sticky top-0 z-10">
                  {table.getHeaderGroups().map(headerGroup => (
                    <tr key={headerGroup.id}>
                      {headerGroup.headers.map(header => (
                        <th 
                          key={header.id} 
                          className={cn(
                            "p-4 px-5 font-semibold align-middle cursor-pointer hover:bg-slate-100/60 transition-colors select-none",
                            header.column.id === "timestamp" && "hidden md:table-cell",
                            header.column.id === "severity" && "hidden sm:table-cell",
                            header.column.id === "riskScore" && "hidden md:table-cell"
                          )}
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          <div className="flex items-center space-x-1.5">
                            <span>{flexRender(header.column.columnDef.header, header.getContext())}</span>
                            <span>
                              {header.column.getIsSorted() === "asc" && <ChevronUp className="h-3 w-3" />}
                              {header.column.getIsSorted() === "desc" && <ChevronDown className="h-3 w-3" />}
                            </span>
                          </div>
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono text-slate-600 bg-white">
                  {table.getRowModel().rows.map(row => {
                    const isSelected = selectedIncident?.id === row.original.id;
                    return (
                      <tr 
                        key={row.id}
                        onClick={() => setSelectedIncident(row.original)}
                        className={cn(
                          "hover:bg-slate-50/60 cursor-pointer transition-premium",
                          isSelected && "bg-blue-50/30 border-l-2 border-l-cyber-primary"
                        )}
                      >
                        {row.getVisibleCells().map(cell => (
                          <td 
                            key={cell.id} 
                            className={cn(
                              "p-4 px-5 align-middle",
                              cell.column.id === "timestamp" && "hidden md:table-cell",
                              cell.column.id === "severity" && "hidden sm:table-cell",
                              cell.column.id === "riskScore" && "hidden md:table-cell"
                            )}
                          >
                            {flexRender(cell.column.columnDef.cell, cell.getContext())}
                          </td>
                        ))}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>

          {/* Pagination Controls */}
          {!isLoading && table.getRowModel().rows.length > 0 && (
            <div className="flex items-center justify-between bg-white border border-slate-200 p-3.5 rounded-md shadow-sm font-mono text-[10px] text-slate-500">
              <div className="flex items-center space-x-2">
                <span>Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}</span>
                <span>•</span>
                <span>Total records: {filteredData.length}</span>
              </div>
              <div className="flex items-center space-x-1.5">
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="h-6 w-6 p-0" 
                  onClick={() => table.setPageIndex(0)}
                  disabled={!table.getCanPreviousPage()}
                >
                  <ChevronsLeft className="h-3.5 w-3.5" />
                </Button>
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="h-6 w-6 p-0" 
                  onClick={() => table.previousPage()}
                  disabled={!table.getCanPreviousPage()}
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                </Button>
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="h-6 w-6 p-0" 
                  onClick={() => table.nextPage()}
                  disabled={!table.getCanNextPage()}
                >
                  <ChevronRight className="h-3.5 w-3.5" />
                </Button>
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="h-6 w-6 p-0" 
                  onClick={() => table.setPageIndex(table.getPageCount() - 1)}
                  disabled={!table.getCanNextPage()}
                >
                  <ChevronsRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          )}
        </div>

        {/* Detailed Inspector Panel (38% width) */}
        <div className="w-full xl:w-[38%] xl:sticky xl:top-6 shrink-0">
          {selectedIncident ? (
            <Card className="border-slate-200 bg-white shadow-card overflow-hidden relative flex flex-col max-h-[calc(100vh-210px)] h-[calc(100vh-210px)] min-h-[420px]">
              <div className={cn(
                "absolute top-0 left-0 right-0 h-[1.5px] shrink-0",
                selectedIncident.severity === "critical" && "bg-cyber-critical",
                selectedIncident.severity === "high" && "bg-cyber-high",
                selectedIncident.severity === "medium" && "bg-cyber-medium",
                selectedIncident.severity === "low" && "bg-cyber-low"
              )} />
              <div className="px-5 py-4 border-b border-slate-150 flex justify-between items-center theme-surface-secondary gap-3 min-w-0 shrink-0 relative z-10">
                <span className="font-mono text-xs font-bold text-slate-800 dark:text-slate-200 truncate" title={selectedIncident.id}>{selectedIncident.id}</span>
                <span className="text-[9px] font-mono text-slate-400 dark:text-slate-500 shrink-0">INGESTED: {selectedIncident.detector}</span>
              </div>
              
              <CardContent className="p-5 space-y-4 flex-1 overflow-y-auto min-h-0">
                {/* Threat description */}
                <div>
                  <h3 className="text-xs font-bold theme-text leading-tight break-words line-clamp-3 overflow-hidden" title={selectedIncident.title}>
                    {selectedIncident.title}
                  </h3>
                  <div className="flex items-center gap-2 mt-2">
                    <Badge severity={selectedIncident.severity}>{selectedIncident.severity}</Badge>
                    <span className="font-mono text-[9px] theme-text-secondary bg-slate-50 border border-slate-200 px-1.5 py-0.5 rounded">
                      {selectedIncident.category}
                    </span>
                  </div>
                </div>

                <div className="bg-slate-50/60 border border-slate-200 rounded-md p-4 font-sans text-xs theme-text-secondary leading-relaxed break-words max-h-48 overflow-y-auto scrollbar-thin">
                  {selectedIncident.description}
                </div>

                {/* Scope parameters */}
                <div className="space-y-2 border-t border-slate-100 pt-4">
                  <h4 className="text-[9px] font-mono font-bold tracking-wider theme-text-muted uppercase">Target Details</h4>
                  
                  <div className="grid grid-cols-2 gap-3 font-mono text-[10px]">
                    <div>
                      <span className="theme-text-muted block">Host Name</span>
                      <span 
                        onClick={() => navigate(`/endpoints/${selectedIncident.hostname}`)}
                        className="text-cyber-primary hover:underline cursor-pointer font-bold flex items-center gap-1 mt-0.5"
                      >
                        {selectedIncident.hostname}
                        <Eye className="h-2.5 w-2.5" />
                      </span>
                    </div>
                    <div>
                      <span className="theme-text-muted block">IP Address</span>
                      <span className="theme-text font-bold mt-0.5 block">{selectedIncident.ip}</span>
                    </div>
                    <div>
                      <span className="theme-text-muted block">Timestamp</span>
                      <span className="theme-text font-bold mt-0.5 block">
                        {new Date(selectedIncident.timestamp).toLocaleDateString()}
                      </span>
                    </div>
                    <div>
                      <span className="theme-text-muted block">Mitigation Status</span>
                      <div className="mt-1">
                        <StatusPill status={selectedIncident.status} />
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>

              {/* Operations check playbooks (Pinned Footer) */}
              <div className="px-5 py-4 border-t border-slate-100 bg-slate-50/20 dark:bg-slate-950/20 dark:border-slate-800 shrink-0 space-y-2.5">
                <h4 className="text-[9px] font-mono font-bold tracking-wider text-slate-400 uppercase">Containment Playbooks</h4>
                
                <div className="flex flex-col gap-2">
                  <Button 
                    variant="cyber" 
                    size="sm" 
                    className="w-full text-xs font-mono justify-center"
                    onClick={() => navigate(`/copilot?query=review+${selectedIncident.id === "INC-2026-0041" ? "lsass+memory+dump" : "xz-backdoor+vulnerability"}`)}
                  >
                    <Sparkles className="mr-2 h-3.5 w-3.5" />
                    Ask AI Copilot for playbook
                  </Button>

                  <div className="grid grid-cols-2 gap-2 mt-0.5">
                    {selectedIncident.status === "active" && (
                      <>
                        <Button
                          variant="secondary"
                          size="sm"
                          className="font-mono text-[9px] border-cyber-low/30 text-cyber-low hover:bg-cyber-low/10"
                          onClick={() => handleUpdateStatus(selectedIncident.id, "resolved")}
                        >
                          <CheckCircle className="mr-1 h-3 w-3" />
                          RESOLVE
                        </Button>
                        <Button
                          variant="destructive"
                          size="sm"
                          className="font-mono text-[9px] bg-cyber-critical/10 text-cyber-critical hover:bg-cyber-critical/20 border border-cyber-critical/20"
                          onClick={() => navigate(`/approvals?incident=${selectedIncident.id}`)}
                        >
                          <ShieldX className="mr-1 h-3 w-3" />
                          QUARANTINE
                        </Button>
                      </>
                    )}

                    {selectedIncident.status === "resolved" && (
                      <div className="col-span-2 text-center py-2 text-[9px] font-mono text-cyber-low bg-cyber-low/5 border border-cyber-low/20 rounded-md">
                        Incident closed by administrator. Telemetry marked clean.
                      </div>
                    )}

                    {selectedIncident.status === "suppressed" && (
                      <div className="col-span-2 text-center py-2 text-[9px] font-mono text-slate-500 bg-slate-50 border border-slate-200 rounded-md">
                        Incident suppressed at edge sensor logs.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </Card>
          ) : (
            <div className="border border-dashed border-slate-200 py-24 text-center rounded-md text-xs font-mono text-slate-400">
              Select a grid row to load the threat details inspector.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default FindingsPage;
