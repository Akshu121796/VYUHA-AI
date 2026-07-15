import React, { createContext, useContext, useState, useEffect } from "react";

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
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const stored = localStorage.getItem("vyuha_auth_user");
    if (stored) {
      try {
        setUser(JSON.parse(stored));
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
    return true;
  };

  const logout = () => {
    localStorage.removeItem("vyuha_auth_user");
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, isAuthenticated: !!user, isLoading }}>
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
