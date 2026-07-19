import { apiClient } from "./apiClient";
import { IncidentStatus } from "../types";

export const findingsService = {
  getIncidents: async () => {
    const res = await apiClient.get("/findings");
    return res.data;
  },
  updateIncidentStatus: async (id: string, status: IncidentStatus) => {
    const res = await apiClient.put(`/findings/${id}`, { status });
    return res.data;
  },
  resetTelemetry: async () => {
    const res = await apiClient.post("/findings/reset");
    return res.data;
  }
};
export default findingsService;
