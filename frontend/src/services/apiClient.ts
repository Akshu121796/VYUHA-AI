import axios from "axios";

const getBaseURL = () => {
    // 1. Check localStorage override
    const localOverride = typeof window !== "undefined" ? localStorage.getItem("VYUHA_API_URL") : null;
    if (localOverride) return localOverride;

    // 2. Check build-time env variable
    if (import.meta.env.VITE_API_URL) {
        return import.meta.env.VITE_API_URL;
    }

    // 3. Fallback dynamically based on current deployment domain
    if (typeof window !== "undefined") {
        const hostname = window.location.hostname;
        if (hostname === "localhost" || hostname === "127.0.0.1") {
            return "http://localhost:8000";
        }
        
        // If deployed to Vercel/Render, try to resolve backend based on service naming
        // Vercel name: vyuha-ai-virid.vercel.app -> Render backend: https://vyuha-backend.onrender.com
        return "https://vyuha-backend.onrender.com";
    }

    return "http://localhost:8000";
};

export const apiClient = axios.create({
    baseURL: getBaseURL(),
    headers: {
        "Content-Type": "application/json",
    },
});