import { apiClient } from "./apiClient";

export const approvalService = {
  getApprovals: async () => {
    const res = await apiClient.get("/approvals");
    return res.data;
  },

  decide: async (
    id: string,
    decision: "approved" | "rejected"
  ) => {
    const res = await apiClient.patch(
      `/approvals/${id}/decide`,
      { decision }
    );
    return res.data;
  },

  apply: async (id: string) => {
    const res = await apiClient.post(`/approvals/${id}/apply`);
    return res.data;
  },

  verify: async (id: string) => {
    const res = await apiClient.post(`/approvals/${id}/verify`);
    return res.data;
  }
};

export default approvalService;