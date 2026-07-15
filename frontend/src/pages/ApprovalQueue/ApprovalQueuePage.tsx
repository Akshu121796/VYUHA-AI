import React, { useState } from "react";
import { 
  Check, 
  X, 
  BookmarkCheck, 
  AlertTriangle, 
  Server, 
  Zap, 
  Info
} from "lucide-react";
import { useApprovalsData, useResolveApprovalMutation } from "../../hooks/queries/useVyuhaQueries";
import { ApprovalTask } from "../../types";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../components/ui/Card";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { Dialog, DialogHeader, DialogTitle, DialogDescription } from "../../components/ui/Dialog";
import { StatusPill } from "../../components/ui/StatusPill";
import { Skeleton } from "../../components/ui/Skeleton";
import { cn } from "../../utils/cn";
import { toast } from "sonner";

export function ApprovalQueuePage() {
  const { data: tasks, isLoading } = useApprovalsData();
  const resolveMutation = useResolveApprovalMutation();
  
  // Modal states
  const [selectedTask, setSelectedTask] = useState<ApprovalTask | null>(null);
  const [modalType, setModalType] = useState<"approve" | "reject" | null>(null);

  if (isLoading || !tasks) {
    return (
      <div className="space-y-6">
        <div className="h-10 w-48 bg-slate-200/60 animate-pulse rounded-md" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-4">
          <Skeleton className="h-[200px] w-full rounded-md" />
          <Skeleton className="h-[200px] w-full rounded-md" />
        </div>
      </div>
    );
  }

  const pendingTasks = tasks.filter((t: ApprovalTask) => t.status === "pending");
  const completedTasks = tasks.filter((t: ApprovalTask) => t.status !== "pending");

  const handleOpenModal = (task: ApprovalTask, type: "approve" | "reject") => {
    setSelectedTask(task);
    setModalType(type);
  };

  const handleCloseModal = () => {
    setSelectedTask(null);
    setModalType(null);
  };

  const handleConfirmAction = () => {
    if (!selectedTask || !modalType) return;

    const finalStatus = modalType === "approve" ? "approved" : "rejected";
    
    resolveMutation.mutate({ id: selectedTask.id, status: finalStatus }, {
      onSuccess: () => {
        if (finalStatus === "approved") {
          toast.success(`Action successfully executed: "${selectedTask.action}"`);
        } else {
          toast.error(`Action dismissed: "${selectedTask.action}"`);
        }
        handleCloseModal();
      }
    });
  };

  // Before / After states mapping for selected task
  const getTaskComparisons = (task: ApprovalTask) => {
    switch (task.id) {
      case "TASK-2026-901":
        return {
          before: "XZ Backdoor active on root shell PID 4410",
          after: "xz-utils dependency reinstalled to 5.4.1. Shell terminated.",
          impact: "Workstation network packages will experience a 10-second ping disruption.",
          reduction: "92%"
        };
      case "TASK-2026-902":
        return {
          before: "LSASS memory handle read queries allowed dynamically",
          after: "Registry RunAsPPL key enabled. LSASS queries isolated.",
          impact: "Requires target system restart to load registry keys. Incurs 2-minute server pause.",
          reduction: "84%"
        };
      case "TASK-2026-903":
        return {
          before: "IP 185.220.101.44 SSH brute-forcing allowed",
          after: "IP banned at border firewalls. Active SSH campaigns contained.",
          impact: "Zero downtime. External IP traffic denied at gateway boundaries.",
          reduction: "75%"
        };
      default:
        return {
          before: "Threat vectors active inside targeted host files",
          after: "File quarantined and signatures locked.",
          impact: "Requires administrative privileges. No service disruptions.",
          reduction: "65%"
        };
    }
  };

  const comparisons = selectedTask ? getTaskComparisons(selectedTask) : null;

  const getTaskSeverity = (task: ApprovalTask) => {
    if (task.action === "terminate_process" || task.action === "isolate_host") {
      return "critical";
    }
    if (task.action === "block_ip") {
      return "high";
    }
    return "medium";
  };

  const getTaskHostname = (task: ApprovalTask) => {
    const target = task.target || "";
    if (target.includes("web-prod-ubuntu")) return "web-prod-ubuntu-01";
    if (target.includes("ad-dc-windows")) return "ad-dc-windows-01";
    if (target.includes("workstation")) return target.split(" on ")[1] || target;
    return target;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-slate-200/70 pb-5 dark:border-slate-800/70">
        <h1 className="text-xl font-bold tracking-tight text-slate-900 font-sans dark:text-slate-100">
          Remediation Gates
        </h1>
        <p className="mt-1 text-xs text-slate-500 font-sans dark:text-slate-400">
          Review and authorize suggested security policies. Action approval triggers immediate network deployment.
        </p>
      </div>

      {/* Main Split Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 items-start">
        
        {/* Pending Actions List (2/3 width) */}
        <div className="xl:col-span-2 space-y-4">
          <h2 className="text-xs font-mono font-bold tracking-wider text-slate-400 uppercase pl-1">
            Pending Remediation Requests ({pendingTasks.length})
          </h2>

          {pendingTasks.length === 0 ? (
            <Card className="border-dashed border-slate-200 bg-white/80 py-16 text-center rounded-[20px] shadow-sm dark:border-slate-700 dark:bg-slate-950/70">
              <CardContent className="space-y-3">
                <BookmarkCheck className="mx-auto h-10 w-10 text-cyber-low" />
                <p className="text-sm font-sans font-semibold text-slate-800">All playbooks authorized</p>
                <p className="text-xs text-slate-400 font-mono">No pending authorization tasks in this session.</p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {pendingTasks.map((task: ApprovalTask) => {
                const cmp = getTaskComparisons(task);
                const badgeSeverity = getTaskSeverity(task);
                const hostname = getTaskHostname(task);
                return (
                  <Card key={task.id} className="relative flex min-h-[220px] flex-col justify-between overflow-hidden rounded-[20px] border-slate-200 bg-white/90 shadow-card transition-premium hover:border-brand-accent/40 hover:shadow-premium dark:border-slate-800 dark:bg-slate-950/80">
                    {/* Severity colored indicator line */}
                    <div className={cn(
                      "absolute top-0 left-0 right-0 h-[1.5px]",
                      badgeSeverity === "critical" && "bg-cyber-critical",
                      badgeSeverity === "high" && "bg-cyber-high",
                      badgeSeverity === "medium" && "bg-cyber-medium"
                    )} />

                    <div className="p-4.5 space-y-3.5">
                      {/* Header info */}
                      <div className="flex justify-between items-center">
                        <span className="font-mono text-[9px] font-bold text-slate-400">{task.id}</span>
                        <Badge severity={badgeSeverity}>{badgeSeverity}</Badge>
                      </div>

                      {/* Endpoint specs */}
                      <div className="flex items-center space-x-2 font-mono text-[10.5px]">
                        <Server className="h-3.5 w-3.5 text-cyber-primary" />
                        <span className="text-slate-800 font-bold">{hostname}</span>
                      </div>

                      {/* Recommended Fix */}
                      <div className="space-y-1">
                        <span className="text-[9px] font-mono uppercase text-slate-450 block font-semibold">Recommended Fix</span>
                        <p className="text-xs font-semibold text-slate-800 leading-tight">
                          {task.action}
                        </p>
                      </div>

                      {/* Risk Reduction Rating */}
                      <div className="flex items-center gap-1.5 font-mono text-[10px] text-cyber-low bg-green-50 border border-green-100 px-2 py-1 rounded w-fit shadow-sm">
                        <Zap className="h-3 w-3 fill-cyber-low/10" />
                        <span className="font-bold">-{cmp.reduction} RISK REDUCTION</span>
                      </div>
                    </div>

                    {/* Action buttons */}
                    <div className="flex gap-2 border-t border-slate-100 bg-slate-50/50 p-4 dark:border-slate-800 dark:bg-slate-900/70">
                      <Button
                        variant="outline"
                        size="sm"
                        className="flex-1 font-mono text-[9.5px] border-slate-200 text-slate-600 hover:bg-slate-50"
                        onClick={() => handleOpenModal(task, "reject")}
                      >
                        <X className="mr-1 h-3 w-3 text-slate-400" />
                        REJECT
                      </Button>
                      <Button
                        variant="cyber"
                        size="sm"
                        className="flex-1 font-mono text-[9.5px]"
                        onClick={() => handleOpenModal(task, "approve")}
                      >
                        <Check className="mr-1 h-3 w-3" />
                        APPROVE & EXECUTE
                      </Button>
                    </div>
                  </Card>
                );
              })}
            </div>
          )}
        </div>

        {/* Action Audit Logs (1/3 width) */}
        <div className="space-y-4">
          <h2 className="text-xs font-mono font-bold tracking-wider text-slate-400 uppercase flex items-center gap-1.5 pl-1">
            <BookmarkCheck className="h-4 w-4 text-cyber-low" /> History Audit Logs
          </h2>

          <Card className="overflow-hidden rounded-[20px] border-slate-200 bg-white/90 shadow-card dark:border-slate-800 dark:bg-slate-950/80">
            <CardContent className="p-0">
              <div className="divide-y divide-slate-100">
                {completedTasks.length === 0 ? (
                  <div className="py-12 text-center text-xs font-mono text-slate-400">
                    No historic overrides recorded in this session.
                  </div>
                ) : (
                  completedTasks.map((task: ApprovalTask) => (
                    <div key={task.id} className="p-4.5 space-y-2 text-xs font-mono">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-700">{task.id}</span>
                        <span className={cn(
                          "text-[9px] uppercase font-bold px-1.5 py-0.2 rounded border",
                          task.status === "approved" 
                            ? "bg-green-50 text-cyber-low border-green-150" 
                            : "bg-slate-50 text-slate-400 border-slate-200"
                        )}>
                          {task.status}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-650 font-sans leading-snug">
                        {task.action}
                      </p>
                      <div className="flex items-center justify-between text-[8.5px] text-slate-400 pt-1">
                        <span>Target: {getTaskHostname(task)}</span>
                        <span>Operator: Kaveesh</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Confirmation & Authorization Modal Dialog */}
      {selectedTask && modalType && (
        <Dialog isOpen={true} onClose={handleCloseModal}>
          <DialogHeader className="border-b border-slate-200 pb-3">
            <DialogTitle className="font-mono text-sm font-bold text-slate-800 flex items-center gap-1.5">
              <AlertTriangle className={cn(
                "h-4.5 w-4.5",
                modalType === "approve" ? "text-cyber-low animate-pulse" : "text-cyber-critical"
              )} />
              {modalType === "approve" ? "Mitigation Authorization check" : "Mitigation Rejection check"}
            </DialogTitle>
            <DialogDescription className="font-mono text-[8px] text-slate-400 mt-1 uppercase">
              GATES ID: {selectedTask.id} • POLICY EXECUTOR
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-3.5 text-xs">
            {modalType === "approve" ? (
              <>
                <p className="text-slate-500 font-sans leading-relaxed">
                  Confirming deployment will execute firewall triggers, script libraries rollbacks, or process quarantines. Please audit the comparative states below:
                </p>

                <div className="space-y-2.5 bg-slate-50 border border-slate-200 p-3.5 rounded-md font-mono text-[10px] text-slate-600 shadow-sm">
                  {/* Before */}
                  <div>
                    <span className="text-cyber-critical font-bold text-[9px] block">● BEFORE STATE:</span>
                    <p className="text-slate-800 mt-1">{comparisons?.before}</p>
                  </div>
                  {/* After */}
                  <div className="pt-2.5 border-t border-slate-200">
                    <span className="text-cyber-low font-bold text-[9px] block">✓ AFTER STATE:</span>
                    <p className="text-slate-800 mt-1">{comparisons?.after}</p>
                  </div>
                </div>

                {/* Impact Alert */}
                <div className="flex gap-2.5 bg-amber-50/50 border border-amber-100 p-3 rounded-md font-sans text-slate-600 shadow-sm">
                  <Info className="h-4 w-4 text-cyber-high shrink-0 mt-0.5" />
                  <div className="space-y-0.5 text-[10px] leading-relaxed">
                    <span className="font-bold text-slate-700 block uppercase text-[8px] tracking-wider">OPERATIONAL IMPACT ANALYSIS</span>
                    {comparisons?.impact}
                  </div>
                </div>

                <p className="font-mono text-[8px] text-slate-400 text-center uppercase tracking-wider pt-1">
                  Are you sure you want to authorize this action?
                </p>
              </>
            ) : (
              <>
                <p className="text-slate-500 font-sans leading-relaxed">
                  Rejecting this mitigation item will dismiss the recommended fix from the approval queue. The threat warning will remain unresolved inside telemetry logs.
                </p>
                <div className="bg-red-50 border border-red-150 p-3.5 rounded-md font-mono text-[10px] text-cyber-critical shadow-sm">
                  WARNING: Asset health score indices will continue to record critical vulnerabilities.
                </div>
              </>
            )}
          </div>

          {/* Modal Buttons */}
          <div className="flex gap-3 border-t border-slate-150 pt-3.5 justify-end">
            <Button
              variant="outline"
              size="sm"
              className="font-mono text-[9px] border-slate-200 text-slate-600 hover:bg-slate-50"
              onClick={handleCloseModal}
            >
              CANCEL
            </Button>
            <Button
              variant={modalType === "approve" ? "cyber" : "destructive"}
              size="sm"
              className="font-mono text-[9px]"
              onClick={handleConfirmAction}
            >
              {modalType === "approve" ? "AUTHORIZE & DEPLOY" : "CONFIRM REJECTION"}
            </Button>
          </div>
        </Dialog>
      )}
    </div>
  );
}

export default ApprovalQueuePage;
