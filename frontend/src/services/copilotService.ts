import { apiClient } from "./apiClient";

export const copilotService = {
  sendPrompt: async (prompt: string) => {
    const res = await apiClient.post("/copilot", { prompt });
    return res.data;
  }
};
export default copilotService;
