import { apiClient } from "./apiClient";

export const attackGraphService = {
  getGraphNodes: async () => {
    const res = await apiClient.get("/attack-graph");
    return res.data;
  }
};
export default attackGraphService;
