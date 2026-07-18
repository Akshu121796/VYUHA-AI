import { apiClient } from "./apiClient";

export const endpointService = {
  getEndpoints: async () => {
    const res = await apiClient.get("/assets");
    return res.data;
  },
  getEndpointById: async (id: string) => {
    const res = await apiClient.get(`/assets/${id}`);
    return res.data;
  },
  toggleIsolation: async (id: string) => {
    const res = await apiClient.put(`/assets/${id}/isolate`);
    return res.data;
  },
  terminateProcess: async (id: string, pid: number) => {
    const res = await apiClient.put(`/assets/${id}/terminate-process`, { pid });
    return res.data;
  }
};
export default endpointService;
