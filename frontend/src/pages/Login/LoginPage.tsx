import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, Lock, User, Terminal, Eye, EyeOff, Activity, ShieldCheck, Brain, Crown } from "lucide-react";
import { useAuth } from "../../hooks/useAuth";
import { Button } from "../../components/ui/Button";
import { Input } from "../../components/ui/Input";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "../../components/ui/Card";
import { cn } from "../../utils/cn";

const CyberNetworkSVG = ({ accentColor = "blue" }: { accentColor?: "blue" | "purple" }) => (
  <svg
    className="absolute inset-0 h-full w-full opacity-[0.08] dark:opacity-[0.14] pointer-events-none"
    xmlns="http://www.w3.org/2000/svg"
  >
    <defs>
      <radialGradient id="grid-glow" cx="50%" cy="50%" r="50%">
        <stop offset="0%" stopColor={accentColor === "purple" ? "#a855f7" : "#2563eb"} stopOpacity="0.4" />
        <stop offset="100%" stopColor="transparent" stopOpacity="0" />
      </radialGradient>
      <linearGradient id="line-grad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stopColor={accentColor === "purple" ? "#a855f7" : "#3b82f6"} stopOpacity="0.15" />
        <stop offset="50%" stopColor={accentColor === "purple" ? "#d8b4fe" : "#8b5cf6"} stopOpacity="0.35" />
        <stop offset="100%" stopColor={accentColor === "purple" ? "#a855f7" : "#3b82f6"} stopOpacity="0.15" />
      </linearGradient>
    </defs>
    <rect width="100%" height="100%" fill="url(#grid-glow)" />
    
    {/* Grid Lines */}
    <path
      d="M0 40h1000M0 80h1000M0 120h1000M0 160h1000M0 200h1000M0 240h1000M0 280h1000M0 320h1000M0 360h1000M0 400h1000M0 440h1000M0 480h1000M0 520h1000M0 560h1000M0 600h1000M0 640h1000M0 680h1000M0 720h1000M0 760h1000M0 800h1000"
      stroke="rgba(148, 163, 184, 0.05)"
      strokeWidth="1"
    />
    <path
      d="M40 0v800M80 0v800M120 0v800M160 0v800M200 0v800M240 0v800M280 0v800M320 0v800M360 0v800M400 0v800M440 0v800M480 0v800M520 0v800M560 0v800M600 0v800M640 0v800M680 0v800M720 0v800M760 0v800M800 0v800"
      stroke="rgba(148, 163, 184, 0.05)"
      strokeWidth="1"
    />

    {/* Network Connections */}
    <g stroke="url(#line-grad)" strokeWidth="1.5" fill="none">
      <path d="M120 150 L240 280 L380 200 L490 350 L300 450 L120 150" />
      <path d="M240 280 L490 350 L580 180 M380 200 L580 180" />
      <path d="M300 450 L420 580 L600 520 L490 350" />
      <path d="M120 150 L80 320 L300 450" />
    </g>

    {/* Glow Dots */}
    <g fill={accentColor === "purple" ? "#a855f7" : "#3b82f6"}>
      <circle cx="120" cy="150" r="4" className="animate-pulse" />
      <circle cx="240" cy="280" r="5" />
      <circle cx="380" cy="200" r="4" />
      <circle cx="490" cy="350" r="6" />
      <circle cx="580" cy="180" r="4" />
      <circle cx="300" cy="450" r="5" />
      <circle cx="420" cy="580" r="4" />
      <circle cx="600" cy="520" r="5" />
      <circle cx="80" cy="320" r="4" />
    </g>
  </svg>
);

export interface LoginPageProps {
  title?: string;
  subtitle?: string;
  role?: "admin" | "analyst";
  accentColor?: "blue" | "purple";
  redirectPath?: string;
}

export function LoginPage({
  title = "Sign In to Vyuha",
  subtitle = "Enter administrative operator credentials to access operations workspace.",
  role = "admin",
  accentColor = "blue",
  redirectPath = "/"
}: LoginPageProps) {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) {
      navigate("/");
    }
  }, [isAuthenticated, navigate]);
  
  const [username, setUsername] = useState(role === "admin" ? "Admin_Kaveesh" : "Analyst_Kaveesh");
  const [password, setPassword] = useState("••••••••");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState("");
  
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError("Please fill in administrative credentials.");
      return;
    }

    setIsSubmitting(true);
    setError("");
    
    try {
      await login(username, password, role);
      navigate(redirectPath);
    } catch (err) {
      setError("Authentication rejected. Invalid credentials.");
      setIsSubmitting(false);
    }
  };

  return (
    <div className="relative min-h-screen w-full flex flex-col-reverse lg:flex-row bg-slate-50 dark:bg-[#0b1220] transition-colors duration-300">
      
      <div className="absolute inset-0 cyber-grid-overlay opacity-5 pointer-events-none" />

      <div className="hidden md:flex flex-col justify-between w-full lg:w-[45%] p-8 lg:p-16 border-t lg:border-t-0 lg:border-r border-slate-200/60 dark:border-slate-800/60 relative overflow-hidden bg-slate-900 text-white select-none">
        
        <CyberNetworkSVG accentColor={accentColor} />
        <div className={cn(
          "absolute top-1/4 left-1/4 -translate-x-1/2 -translate-y-1/2 w-[350px] h-[350px] blur-[120px] rounded-full pointer-events-none",
          accentColor === "purple" ? "bg-purple-600/10 dark:bg-purple-600/15" : "bg-blue-600/10 dark:bg-blue-600/15"
        )} />
        <div className={cn(
          "absolute bottom-1/4 right-1/4 translate-x-1/2 translate-y-1/2 w-[350px] h-[350px] blur-[120px] rounded-full pointer-events-none",
          accentColor === "purple" ? "bg-indigo-600/10 dark:bg-fuchsia-600/10" : "bg-indigo-600/10 dark:bg-purple-600/10"
        )} />

        <div className="relative z-10">
          <div className="flex items-center gap-3">
            <div className={cn(
              "flex h-11 w-11 items-center justify-center rounded-2xl border",
              accentColor === "purple" 
                ? "border-purple-500/20 bg-purple-600/10 text-purple-400 shadow-[0_0_20px_rgba(168,85,247,0.15)]"
                : "border-blue-500/20 bg-blue-600/10 text-blue-400 shadow-[0_0_20px_rgba(37,99,235,0.15)]"
            )}>
              {role === "admin" ? <Crown className="h-5.5 w-5.5" /> : <Shield className="h-5.5 w-5.5" />}
            </div>
            <span className="text-xl font-bold tracking-tight text-white">
              VYUHA<span className={accentColor === "purple" ? "text-purple-500" : "text-blue-500"}>.AI</span>
            </span>
          </div>
          <p className="mt-2 text-[10px] font-mono font-bold tracking-[0.25em] text-slate-400 uppercase">
            SECURE PLATFORM OPERATIONS // {role === "admin" ? "ADMIN" : "ANALYST"} SECTOR
          </p>
          <h2 className="mt-12 text-2xl lg:text-3xl font-semibold leading-tight tracking-tight text-slate-100 max-w-md font-sans">
            {role === "admin" 
              ? "Empowering security operations with real-time response."
              : "Deep threat investigation & AI Copilot diagnostics."}
          </h2>
          <p className="mt-3.5 text-sm text-slate-400 max-w-sm font-sans leading-relaxed">
            {role === "admin"
              ? "Transition from detection to containment instantly. Execute live attack path analyses, manage critical isolation gates, and guide analyst response workflows."
              : "Triage complex alerts, discover lateral movements, review file-less vulnerabilities, and interact with the AI Security Copilot."}
          </p>
        </div>

        <div className="relative z-10 my-10 space-y-4 max-w-lg">
          {role === "admin" ? (
            <>
              <div className="group relative rounded-2xl border border-white/5 bg-white/[0.02] p-5 backdrop-blur-md transition-all duration-300 hover:border-blue-500/25 hover:bg-white/[0.04] hover:shadow-[0_8px_30px_rgba(0,0,0,0.12)]">
                <div className="flex items-start gap-4">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-white/5 text-blue-400 group-hover:border-blue-500/20 group-hover:bg-blue-500/10 transition-all">
                    <Activity className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-200 group-hover:text-white transition-colors font-sans">Live Threat Visualization</h3>
                    <p className="mt-1 text-xs leading-relaxed text-slate-400 font-sans">
                      Analyze lateral threat movements, attack graphs, and endpoint behaviors in real-time.
                    </p>
                  </div>
                </div>
              </div>
              <div className="group relative rounded-2xl border border-white/5 bg-white/[0.02] p-5 backdrop-blur-md transition-all duration-300 hover:border-blue-500/25 hover:bg-white/[0.04] hover:shadow-[0_8px_30px_rgba(0,0,0,0.12)]">
                <div className="flex items-start gap-4">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-white/5 text-blue-400 group-hover:border-blue-500/20 group-hover:bg-blue-500/10 transition-all">
                    <ShieldCheck className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-200 group-hover:text-white transition-colors font-sans">Orchestrated Containment Gates</h3>
                    <p className="mt-1 text-xs leading-relaxed text-slate-400 font-sans">
                      Enforce strict approval gates and automated playbooks for critical network isolations.
                    </p>
                  </div>
                </div>
              </div>
              <div className="group relative rounded-2xl border border-white/5 bg-white/[0.02] p-5 backdrop-blur-md transition-all duration-300 hover:border-blue-500/25 hover:bg-white/[0.04] hover:shadow-[0_8px_30px_rgba(0,0,0,0.12)]">
                <div className="flex items-start gap-4">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-white/5 text-blue-400 group-hover:border-blue-500/20 group-hover:bg-blue-500/10 transition-all">
                    <Terminal className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-200 group-hover:text-white transition-colors font-sans">Global Security Policies</h3>
                    <p className="mt-1 text-xs leading-relaxed text-slate-400 font-sans">
                      Enforce organizational configuration, role credentials, policy compliance and audit tracking.
                    </p>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <>
              <div className="group relative rounded-2xl border border-white/5 bg-white/[0.02] p-5 backdrop-blur-md transition-all duration-300 hover:border-purple-500/25 hover:bg-white/[0.04] hover:shadow-[0_8px_30px_rgba(0,0,0,0.12)]">
                <div className="flex items-start gap-4">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-white/5 text-purple-400 group-hover:border-purple-500/20 group-hover:bg-purple-500/10 transition-all">
                    <Activity className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-200 group-hover:text-white transition-colors font-sans">Attack Path Investigations</h3>
                    <p className="mt-1 text-xs leading-relaxed text-slate-400 font-sans">
                      Walk through complex threat graphs and track attacker actions to find the root cause.
                    </p>
                  </div>
                </div>
              </div>
              <div className="group relative rounded-2xl border border-white/5 bg-white/[0.02] p-5 backdrop-blur-md transition-all duration-300 hover:border-purple-500/25 hover:bg-white/[0.04] hover:shadow-[0_8px_30px_rgba(0,0,0,0.12)]">
                <div className="flex items-start gap-4">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-white/5 text-purple-400 group-hover:border-purple-500/20 group-hover:bg-purple-500/10 transition-all">
                    <Brain className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-200 group-hover:text-white transition-colors font-sans">Copilot AI Diagnostics</h3>
                    <p className="mt-1 text-xs leading-relaxed text-slate-400 font-sans">
                      Resolve findings using LLM-guided context and automated playbook recommendations.
                    </p>
                  </div>
                </div>
              </div>
              <div className="group relative rounded-2xl border border-white/5 bg-white/[0.02] p-5 backdrop-blur-md transition-all duration-300 hover:border-purple-500/25 hover:bg-white/[0.04] hover:shadow-[0_8px_30px_rgba(0,0,0,0.12)]">
                <div className="flex items-start gap-4">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-white/5 text-purple-400 group-hover:border-purple-500/20 group-hover:bg-purple-500/10 transition-all">
                    <ShieldCheck className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-200 group-hover:text-white transition-colors font-sans">Vulnerability & Evidence Triage</h3>
                    <p className="mt-1 text-xs leading-relaxed text-slate-400 font-sans">
                      Review sandbox threat reports, file hashing metrics, and host endpoint details in real-time.
                    </p>
                  </div>
                </div>
              </div>
            </>
          )}
        </div>

        <div className="relative z-10 flex items-center justify-between text-[10px] font-mono text-slate-500">
          <span>CLASSIFIED SYSTEM // LEVEL-4 OPERATIONAL ACCESS</span>
          <span>CLIENT VERSION 2.4.0</span>
        </div>
      </div>

      <div className="flex-1 lg:w-[55%] flex flex-col justify-between p-6 md:p-8 lg:p-12 relative bg-slate-50/30 dark:bg-[#070d16] min-h-screen">
        
        <div className={cn(
          "absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[350px] h-[350px] blur-[120px] rounded-full pointer-events-none",
          accentColor === "purple" ? "bg-purple-650/[0.05] dark:bg-purple-600/[0.08]" : "bg-blue-650/[0.05] dark:bg-blue-600/[0.08]"
        )} />

        <div className="md:hidden flex items-center justify-between py-2 mb-6 relative z-10">
          <div className="flex items-center gap-2">
            <div className={cn(
              "flex h-9 w-9 items-center justify-center rounded-xl border text-white shadow-md",
              accentColor === "purple" ? "border-purple-500/20 bg-purple-600" : "border-blue-500/20 bg-blue-600"
            )}>
              {role === "admin" ? <Crown className="h-4.5 w-4.5" /> : <Shield className="h-4.5 w-4.5" />}
            </div>
            <span className="text-md font-bold tracking-tight text-slate-900 dark:text-slate-100">
              VYUHA<span className={accentColor === "purple" ? "text-purple-500" : "text-blue-500"}>.AI</span>
            </span>
          </div>
          <span className="text-[9px] font-mono font-semibold text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-900/50 px-2 py-0.5 rounded border border-slate-200/50 dark:border-slate-800/80">
            {role === "admin" ? "ADMIN" : "ANALYST"}
          </span>
        </div>

        <div className="my-auto w-full flex justify-center items-center relative z-10 py-8">
          <div className="w-full max-w-[440px]">
            <Card className="overflow-hidden border border-slate-200/70 dark:border-slate-800 bg-white/90 dark:bg-[#111827]/90 shadow-[0_24px_90px_-40px_rgba(15,23,42,0.22)] dark:shadow-[0_24px_90px_-40px_rgba(0,0,0,0.85)] backdrop-blur-md hover:border-slate-350 dark:hover:border-slate-700/80 transition-all duration-300 p-0 rounded-[24px]">
              
              <div className={cn(
                "h-1 bg-gradient-to-r",
                accentColor === "purple" ? "from-purple-500 via-purple-600 to-indigo-500" : "from-blue-500 via-blue-600 to-indigo-500"
              )} />
              
              <CardHeader className="pb-4 pt-8 text-center border-b-0 px-8 flex flex-col items-center">
                
                <div className={cn(
                  "mb-4 flex items-center gap-1.5 rounded-full px-3 py-1 text-[10px] font-bold tracking-wider uppercase border select-none",
                  accentColor === "purple"
                    ? "border-purple-500/20 bg-purple-500/10 text-purple-600 dark:text-purple-400"
                    : "border-blue-500/20 bg-blue-500/10 text-blue-600 dark:text-blue-400"
                )}>
                  {role === "admin" ? <Crown className="h-3 w-3" /> : <Shield className="h-3 w-3" />}
                  {role === "admin" ? "Administrator" : "Security Analyst"}
                </div>

                <CardTitle className="text-lg font-bold tracking-tight text-slate-900 dark:text-slate-100 font-sans">
                  {title}
                </CardTitle>
                <CardDescription className="mt-1.5 text-xs text-slate-500 dark:text-slate-400 font-sans leading-relaxed">
                  {subtitle}
                </CardDescription>
              </CardHeader>

              <form onSubmit={handleSubmit}>
                <CardContent className="space-y-5 px-8 py-2">
                  {error && (
                    <div className="rounded-xl border border-red-200/80 bg-red-50/80 dark:border-red-950/20 dark:bg-red-950/10 px-3.5 py-2.5 text-center text-[11px] text-red-655 dark:text-red-400 font-sans">
                      {error}
                    </div>
                  )}

                  <div className="space-y-2">
                    <label className="block text-[10px] font-bold text-slate-500 dark:text-slate-400 tracking-wider uppercase font-sans">
                      {role === "admin" ? "Operator Username" : "Analyst Username"}
                    </label>
                    <div className="relative">
                      <User className="absolute left-3.5 top-3.5 h-4 w-4 text-slate-400 dark:text-slate-500" />
                      <Input
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        className={cn(
                          "pl-10 font-mono text-xs border-slate-200/85 bg-slate-50/50 dark:border-slate-800 dark:bg-slate-900/40 text-slate-855 dark:text-slate-205 focus-visible:bg-white dark:focus-visible:bg-slate-950",
                          accentColor === "purple" 
                            ? "focus-visible:border-purple-500 focus-visible:shadow-[0_0_0_4px_rgba(168,85,247,0.15)]" 
                            : "focus-visible:border-blue-500 focus-visible:shadow-[0_0_0_4px_rgba(37,99,235,0.15)]"
                        )}
                        placeholder={role === "admin" ? "e.g. administrator" : "e.g. analyst"}
                        disabled={isSubmitting}
                        required
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <label className="block text-[10px] font-bold text-slate-500 dark:text-slate-400 tracking-wider uppercase font-sans">
                        {role === "admin" ? "Administrative Token" : "Analyst Access Token"}
                      </label>
                    </div>
                    <div className="relative">
                      <Lock className="absolute left-3.5 top-3.5 h-4 w-4 text-slate-400 dark:text-slate-500" />
                      <Input
                        type={showPassword ? "text" : "password"}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className={cn(
                          "pl-10 pr-10 font-mono text-xs border-slate-200/85 bg-slate-50/50 dark:border-slate-800 dark:bg-slate-900/40 text-slate-855 dark:text-slate-205 focus-visible:bg-white dark:focus-visible:bg-slate-950",
                          accentColor === "purple" 
                            ? "focus-visible:border-purple-500 focus-visible:shadow-[0_0_0_4px_rgba(168,85,247,0.15)]" 
                            : "focus-visible:border-blue-500 focus-visible:shadow-[0_0_0_4px_rgba(37,99,235,0.15)]"
                        )}
                        placeholder="••••••••"
                        disabled={isSubmitting}
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3.5 top-3.5 text-slate-400 hover:text-slate-650 dark:hover:text-slate-300 transition-colors focus:outline-none"
                        title={showPassword ? "Hide password" : "Show password"}
                      >
                        {showPassword ? (
                          <EyeOff className="h-4 w-4" />
                        ) : (
                          <Eye className="h-4 w-4" />
                        )}
                      </button>
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-1">
                    <label className="flex items-center gap-2 cursor-pointer select-none group">
                      <input
                        type="checkbox"
                        checked={rememberMe}
                        onChange={(e) => setRememberMe(e.target.checked)}
                        className={cn(
                          "h-4 w-4 rounded border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 focus:ring-opacity-20",
                          accentColor === "purple" ? "text-purple-600 focus:ring-purple-500" : "text-blue-600 focus:ring-blue-500"
                        )}
                      />
                      <span className="text-[11px] font-medium text-slate-500 dark:text-slate-400 group-hover:text-slate-700 dark:group-hover:text-slate-300 transition-colors font-sans">
                        Remember me
                      </span>
                    </label>

                    <button
                      type="button"
                      onClick={() => setError("Please contact system administrator to recover credentials.")}
                      className={cn(
                        "text-[11px] font-semibold hover:underline transition-all font-sans",
                        accentColor === "purple"
                          ? "text-purple-600 hover:text-purple-750 dark:text-purple-400 dark:hover:text-purple-300"
                          : "text-blue-600 hover:text-blue-750 dark:text-blue-400 dark:hover:text-blue-300"
                      )}
                    >
                      Forgot token?
                    </button>
                  </div>
                </CardContent>

                <CardFooter className="flex flex-col gap-3 pb-8 pt-6 border-t-0 bg-transparent px-8">
                  <Button
                    type="submit"
                    variant={accentColor === "purple" ? "neutral" : "default"}
                    size="lg"
                    className={cn(
                      "w-full text-[11px] font-bold tracking-[0.16em]",
                      accentColor === "purple" 
                        ? "bg-purple-600 border-transparent hover:bg-purple-700 hover:border-purple-650 text-white shadow-md active:scale-[0.99] transition-all" 
                        : ""
                    )}
                    disabled={isSubmitting}
                  >
                    {isSubmitting ? (
                      <span className="flex items-center gap-2">
                        <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white border-t-transparent" />
                        VERIFYING ACCESS...
                      </span>
                    ) : (
                      "SIGN IN"
                    )}
                  </Button>

                  <div className="flex items-center justify-center gap-1.5 text-[10px] text-slate-400 dark:text-slate-500 font-mono tracking-wide mt-2">
                    <Terminal className="h-3.5 w-3.5" />
                    <span>SECURE OPERATIONS WORKSPACE</span>
                  </div>
                </CardFooter>
              </form>
            </Card>
          </div>
        </div>

        <div className="flex items-center justify-between text-[10px] text-slate-400 dark:text-slate-500 py-2 border-t border-slate-200/10 dark:border-slate-800/40 relative z-10 font-sans">
          <span>&copy; {new Date().getFullYear()} VYUHA.AI. All rights reserved.</span>
          <span className="flex gap-4">
            <a href="#" className="hover:underline hover:text-slate-650 dark:hover:text-slate-350 transition-colors">Privacy</a>
            <a href="#" className="hover:underline hover:text-slate-650 dark:hover:text-slate-350 transition-colors">Terms</a>
          </span>
        </div>
      </div>
    </div>
  );
}

export default LoginPage;
