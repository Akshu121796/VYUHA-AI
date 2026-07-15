import { apiClient } from "./apiClient";

export const approvalService = {
  getApprovals: async () => {
    const res = await apiClient.get("/approvals");
    return res.data;
  },
  resolveTask: async (id: string, status: "approved" | "rejected") => {
    const res = await apiClient.put(`/approvals/${id}`, { status });
    return res.data;
  }
};
export default approvalService;
