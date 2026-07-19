import React, { createContext, useContext, useState, useEffect } from "react";
import { apiClient } from "../services/apiClient";

interface User {
  username: string;
  role: string;
  avatar: string;
  token?: string;
}

interface AuthContextType {
  user: User | null;
  login: (username: string, password: string, selectedRole?: "admin" | "analyst") => Promise<boolean>;
  logout: () => void;
  isAuthenticated: boolean;
  isLoading: boolean;
  updateUser: (updatedUser: Partial<User>) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const stored = localStorage.getItem("vyuha_auth_user");
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        setUser(parsed);
        
        // Sync profile dynamically from Supabase via backend
        apiClient.get("/settings")
          .then((res) => {
            if (res.data && res.data.profile) {
              const updated = {
                ...parsed,
                username: res.data.profile.name || parsed.username,
                role: res.data.profile.title || parsed.role,
              };
              localStorage.setItem("vyuha_auth_user", JSON.stringify(updated));
              setUser(updated);
            }
          })
          .catch((err) => {
            console.error("Failed to sync profile settings from backend:", err);
          });
      } catch (e) {
        localStorage.removeItem("vyuha_auth_user");
      }
    }
    setIsLoading(false);
  }, []);

  const login = async (username: string, password: string, selectedRole?: "admin" | "analyst"): Promise<boolean> => {
    setIsLoading(true);
    // Simulating authentication latency (800ms)
    await new Promise((resolve) => setTimeout(resolve, 800));

    // Support flexible credentials for demo purposes, default to SOC Admin Kaveesh
    const defaultUser: User = {
      username: username || "Kaveesh",
      role: selectedRole === "admin" ? "Administrator" : "Security Analyst",
      avatar: "https://api.dicebear.com/7.x/identicon/svg?seed=" + (username || "Kaveesh")
    };

    localStorage.setItem("vyuha_auth_user", JSON.stringify(defaultUser));
    setUser(defaultUser);
    setIsLoading(false);
    
    // Attempt background sync immediately after login to overwrite default if profile already exists in DB
    apiClient.get("/settings")
      .then((res) => {
        if (res.data && res.data.profile) {
          const updated = {
            ...defaultUser,
            username: res.data.profile.name || defaultUser.username,
            role: res.data.profile.title || defaultUser.role,
          };
          localStorage.setItem("vyuha_auth_user", JSON.stringify(updated));
          setUser(updated);
        }
      })
      .catch(() => {});

    return true;
  };

  const logout = () => {
    localStorage.removeItem("vyuha_auth_user");
    setUser(null);
  };

  const updateUser = (updatedFields: Partial<User>) => {
    setUser((prev) => {
      if (!prev) return null;
      const next = { ...prev, ...updatedFields };
      localStorage.setItem("vyuha_auth_user", JSON.stringify(next));
      return next;
    });
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, isAuthenticated: !!user, isLoading, updateUser }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

export default useAuth;
