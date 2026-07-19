import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { dashboardService } from "../../services/dashboardService";
import { findingsService } from "../../services/findingsService";
import { endpointService } from "../../services/endpointService";
import { attackGraphService } from "../../services/attackGraphService";
import { copilotService } from "../../services/copilotService";
import { approvalService } from "../../services/approvalService";
import { reportsService } from "../../services/reportsService";
import { settingsService } from "../../services/settingsService";
import { notificationsService } from "../../services/notificationsService";
import { IncidentStatus } from "../../types";

// 1. Dashboard queries hook
export function useDashboardData() {
  return useQuery({
    queryKey: ["dashboard"],
    queryFn: dashboardService.getDashboardData
  });
}

// 2. Findings queries hooks
export function useIncidentsData() {
  return useQuery({
    queryKey: ["incidents"],
    queryFn: findingsService.getIncidents
  });
}

export function useUpdateIncidentMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: IncidentStatus }) =>
      findingsService.updateIncidentStatus(id, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useResetTelemetryMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: findingsService.resetTelemetry,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["approvals"] });
    }
  });
}

// 3. Endpoints queries hooks
export function useEndpointsData() {
  return useQuery({
    queryKey: ["endpoints"],
    queryFn: endpointService.getEndpoints
  });
}

export function useEndpointDetailData(id: string) {
  return useQuery({
    queryKey: ["endpoint", id],
    queryFn: () => endpointService.getEndpointById(id),
    enabled: !!id
  });
}

export function useToggleIsolationMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => endpointService.toggleIsolation(id),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["endpoint", data.id] });
      queryClient.invalidateQueries({ queryKey: ["endpoints"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useTerminateProcessMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, pid }: { id: string; pid: number }) =>
      endpointService.terminateProcess(id, pid),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["endpoint", data.id] });
    }
  });
}

// 4. Attack Paths queries hooks
export function useAttackGraphData() {
  return useQuery({
    queryKey: ["attack-graph"],
    queryFn: attackGraphService.getGraphNodes
  });
}

// 5. Copilot queries hook
export function useCopilotMutation() {
  return useMutation({
    mutationFn: (prompt: string) => copilotService.sendPrompt(prompt)
  });
}

// 6. Approval Queue queries hooks
export function useApprovalsData() {
  return useQuery({
    queryKey: ["approvals"],
    queryFn: approvalService.getApprovals
  });
}

export function useResolveApprovalMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: "approved" | "rejected" }) =>
      approvalService.decide(id, status),

    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["approvals"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

// 7. Reports queries hooks
export function useReportsData() {
  return useQuery({
    queryKey: ["reports"],
    queryFn: reportsService.getReportsData
  });
}

export function useGenerateReportMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: reportsService.generateReport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reports"] });
    }
  });
}

// 8. Settings queries hooks
export function useSettingsData() {
  return useQuery({
    queryKey: ["settings"],
    queryFn: settingsService.getSettings
  });
}

export function useUpdateSettingsMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (settings: any) => settingsService.updateSettings(settings),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["settings"] });
    }
  });
}

// 9. Notifications query hook
export function useNotificationsData() {
  return useQuery({
    queryKey: ["notifications"],
    queryFn: notificationsService.getNotifications,
    refetchInterval: 5000
  });
}
