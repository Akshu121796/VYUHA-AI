import { apiClient } from "./apiClient";

export const settingsService = {
  getSettings: async () => {
    const res = await apiClient.get("/settings");
    return res.data;
  },
  updateSettings: async (settings: any) => {
    const res = await apiClient.put("/settings", settings);
    return res.data;
  }
};
export default settingsService;
