import { apiClient } from "./apiClient";

export const notificationsService = {
  getNotifications: async () => {
    const res = await apiClient.get("/notifications");
    return res.data;
  }
};
export default notificationsService;
