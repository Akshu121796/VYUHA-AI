import React from "react";
import { Hammer, Clock, ShieldAlert } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../components/ui/Card";

export function MaintenancePage() {
  return (
    <div className="min-h-screen w-screen bg-background flex items-center justify-center relative overflow-hidden select-none p-4 font-sans">
      {/* Grid overlay */}
      <div className="absolute inset-0 cyber-grid-overlay opacity-5 pointer-events-none" />
      
      {/* Glow background sphere */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[350px] h-[350px] bg-brand-darkBlue/75 blur-[100px] rounded-full pointer-events-none" />

      <Card className="max-w-md w-full bg-white border border-slate-200 relative z-10 shadow-premium rounded-lg">
        {/* Decorative Top Accent line */}
        <div className="absolute top-0 left-0 right-0 h-[1.5px] bg-cyber-primary" />

        <CardHeader className="pb-3 text-center">
          <Hammer className="mx-auto h-12 w-12 text-cyber-primary animate-pulse" />
          <CardTitle className="font-mono text-sm font-bold text-slate-800 mt-4 uppercase tracking-wider">
            SYSTEM.MAINTENANCE_LOCK
          </CardTitle>
          <CardDescription className="text-slate-400 font-mono text-[9px] uppercase mt-1">
            Scheduled Database Shard Optimizations In Progress
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-4 pt-0 text-center text-xs">
          <p className="text-slate-600 leading-relaxed font-sans px-4">
            VYUHA.AI console is currently offline. Threat sensors remain active in background containment modes.
          </p>

          {/* Downtime timer */}
          <div className="border border-slate-200 bg-slate-50 p-3.5 rounded-md font-mono text-[10.5px] space-y-1.5 w-fit mx-auto px-6 shadow-sm">
            <span className="text-[8px] text-slate-400 block uppercase font-bold">Estimated Restoration</span>
            <div className="flex items-center justify-center gap-1.5 text-cyber-primary font-bold">
              <Clock className="h-3.5 w-3.5" />
              <span>42 MINUTES REMAINING</span>
            </div>
          </div>

          {/* Contacts */}
          <div className="border-t border-slate-100 pt-4 flex items-center justify-center gap-2 font-mono text-[9.5px] text-slate-400">
            <ShieldAlert className="h-3.5 w-3.5 text-slate-400 shrink-0" />
            <span>Support: soc-ops@vyuha.ai • DC hotline: +1 888-VYUHA-SOC</span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export default MaintenancePage;
