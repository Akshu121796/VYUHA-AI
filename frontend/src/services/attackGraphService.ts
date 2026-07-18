import { apiClient } from "./apiClient";

export const attackGraphService = {
  getGraphNodes: async () => {
    const res = await apiClient.get("/attack-paths");
    return res.data;
  }
};
export default attackGraphService;
