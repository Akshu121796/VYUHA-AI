import React from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { AlertOctagon, CornerDownRight, Home } from "lucide-react";
import { Button } from "../../components/ui/Button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../components/ui/Card";

export function NotFoundPage() {
  const location = useLocation();
  const navigate = useNavigate();

  return (
    <div className="min-h-screen w-screen bg-background flex items-center justify-center relative overflow-hidden select-none p-4 font-sans">
      {/* Grid overlay */}
      <div className="absolute inset-0 cyber-grid-overlay opacity-5 pointer-events-none" />
      
      {/* Glow background sphere */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[350px] h-[350px] bg-brand-darkBlue/75 blur-[100px] rounded-full pointer-events-none" />

      <Card className="max-w-md w-full bg-white border border-slate-200 relative z-10 shadow-premium rounded-lg">
        <CardHeader className="pb-3 text-center">
          <AlertOctagon className="mx-auto h-12 w-12 text-cyber-high animate-pulse" />
          <CardTitle className="font-mono text-sm font-bold text-slate-800 mt-4 uppercase tracking-wider">
            SYSTEM.ROUTE_NOT_FOUND
          </CardTitle>
          <CardDescription className="text-slate-400 font-mono text-[9px] uppercase mt-1">
            Error Code 404 • Destination Path Invalid
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-4 pt-0">
          <p className="text-xs text-slate-600 leading-relaxed text-center font-sans">
            The telemetry path you requested does not exist or has been isolated at the boundary routers.
          </p>

          {/* Ingest Path Box */}
          <div className="border border-slate-200 bg-slate-50 p-3 rounded-md font-mono text-[10px] space-y-1 shadow-sm">
            <span className="text-[8px] text-slate-400 block uppercase font-bold">Requested Resource</span>
            <div className="flex items-center text-cyber-high">
              <CornerDownRight className="h-3 w-3 shrink-0 mr-1.5" />
              <span className="truncate">{location.pathname}</span>
            </div>
          </div>

          {/* Redirect button */}
          <Button
            variant="cyber"
            size="sm"
            className="w-full font-mono text-[10px] justify-center mt-2"
            onClick={() => navigate("/")}
          >
            <Home className="mr-1.5 h-3.5 w-3.5" />
            RETURN TO OPERATIONS HUB
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

export default NotFoundPage;
