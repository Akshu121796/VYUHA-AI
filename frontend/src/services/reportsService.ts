import { apiClient } from "./apiClient";

export const reportsService = {
  getReportsData: async () => {
    const res = await apiClient.get("/reports");
    return res.data;
  },
  generateReport: async () => {
    const res = await apiClient.post("/reports");
    return res.data;
  }
};
export default reportsService;
