import React from "react";
import { AlertTriangle, RefreshCw, Clipboard } from "lucide-react";
import { Button } from "../../components/ui/Button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../components/ui/Card";
import { toast } from "sonner";

interface ErrorPageProps {
  error: Error | null;
  resetError: () => void;
}

export function ErrorPage({ error, resetError }: ErrorPageProps) {
  
  const handleCopyLogs = () => {
    const logText = `VYUHA.AI UI CRASH REPORT\nMessage: ${error?.message || "Unknown error"}\nStack: ${error?.stack || "No stack trace available"}`;
    navigator.clipboard.writeText(logText);
    toast.success("Crash logs copied to clipboard!");
  };

  const handleReboot = () => {
    resetError();
    window.location.href = "/";
  };

  return (
    <div className="min-h-screen w-screen bg-background flex items-center justify-center relative overflow-hidden select-none p-4 font-sans">
      {/* Grid overlay */}
      <div className="absolute inset-0 cyber-grid-overlay opacity-5 pointer-events-none" />
      
      {/* Glow background sphere */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[350px] h-[350px] bg-brand-darkBlue/75 blur-[100px] rounded-full pointer-events-none" />

      <Card className="max-w-lg w-full bg-white border border-slate-200 relative z-10 shadow-premium rounded-lg">
        {/* Critical crimson indicator border line */}
        <div className="absolute top-0 left-0 right-0 h-[1.5px] bg-cyber-critical" />

        <CardHeader className="pb-3 text-center">
          <AlertTriangle className="mx-auto h-12 w-12 text-cyber-critical animate-pulse" />
          <CardTitle className="font-mono text-sm font-bold text-slate-800 mt-4 uppercase tracking-wider">
            SYSTEM.RENDER_CRASH_DETECTION
          </CardTitle>
          <CardDescription className="text-slate-400 font-mono text-[9px] uppercase mt-1">
            Error Intercepted by VYUHA.AI SOC Boundary Guard
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-4 pt-0">
          <p className="text-xs text-slate-650 leading-relaxed text-center font-sans">
            An unhandled JavaScript rendering exception occurred inside this workspace. Details have been captured in the local SOC diagnostic console.
          </p>

          {/* Diagnostic Code Block */}
          <div className="border border-slate-800 bg-slate-950 p-3.5 rounded-md space-y-2 relative overflow-hidden shadow-md">
            <span className="text-[8px] font-mono text-slate-500 block uppercase font-bold">Error details</span>
            <pre className="font-mono text-[10px] text-slate-200 overflow-x-auto whitespace-pre-wrap max-h-[140px] leading-relaxed select-text">
              {error?.name || "Exception"}: {error?.message || "Unspecified client-side script error."}
              {"\n\n"}
              {error?.stack || "Stack trace logs omitted for production security."}
            </pre>
          </div>

          {/* Action buttons */}
          <div className="flex flex-col sm:flex-row gap-3 pt-2">
            <Button
              variant="outline"
              size="sm"
              className="flex-1 font-mono text-[10px] justify-center"
              onClick={handleCopyLogs}
            >
              <Clipboard className="mr-1.5 h-3.5 w-3.5" />
              COPY LOGS
            </Button>
            <Button
              variant="cyber"
              size="sm"
              className="flex-1 font-mono text-[10px] justify-center bg-red-50 text-cyber-critical border-red-200 hover:bg-red-100"
              onClick={handleReboot}
            >
              <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
              RE-BOOT SYSTEM UI
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export default ErrorPage;
