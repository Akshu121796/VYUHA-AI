import { apiClient } from "./apiClient";

export const dashboardService = {
  getDashboardData: async () => {
    const res = await apiClient.get("/dashboard");
    return res.data;
  }
};
