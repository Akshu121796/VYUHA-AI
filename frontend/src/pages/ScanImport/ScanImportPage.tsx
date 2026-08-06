import React, { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { 
  FileUp, 
  Upload, 
  CheckCircle2, 
  AlertTriangle, 
  Network, 
  Loader2, 
  Shield,
  Zap,
  FileCode,
  Clock,
  Database,
  ShieldAlert,
  FileText
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../components/ui/Card";
import { Button } from "../../components/ui/Button";
import { Badge } from "../../components/ui/Badge";
import { findingsService } from "../../services/findingsService";
import { toast } from "sonner";
import { motion, AnimatePresence } from "framer-motion";

interface UploadSummary {
  assetsDiscovered: number;
  findingsImported: number;
  attackPathsGenerated: number;
  attackPatternsMatched: number;
  detectedScanType: string;
}

type PageState = "idle" | "uploading" | "success" | "error";

export interface SessionScanData {
  fileName: string;
  detectedType: string;
  importedTime: string;
  assets: number;
  findings: number;
  attackPaths: number;
}

export function ScanImportPage() {
  const navigate = useNavigate();
  const [importedScan, setImportedScan] = useState<SessionScanData | null>(() => {
    const saved = sessionStorage.getItem("vyuha_imported_scan");
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        return null;
      }
    }
    return null;
  });

  const [state, setState] = useState<PageState>(() => {
    const saved = sessionStorage.getItem("vyuha_imported_scan");
    return saved ? "success" : "idle";
  });

  const [dragActive, setDragActive] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [loadingStep, setLoadingStep] = useState(0);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Rotating loading messages to give a premium cyber SOC console feel
  const loadingMessages = [
    "Uploading report XML payload to console...",
    "Running integration pipeline script parser...",
    "Extracting host assets and structural topology...",
    "Querying NVD API and CISA KEV reference database...",
    "Executing AI-driven security finding classification...",
    "Rebuilding tactical network relationship map...",
    "Regenerating active attack path graph..."
  ];

  React.useEffect(() => {
    let interval: NodeJS.Timeout;
    if (state === "uploading") {
      setLoadingStep(0);
      interval = setInterval(() => {
        setLoadingStep((prev) => (prev + 1) % loadingMessages.length);
      }, 3500);
    }
    return () => clearInterval(interval);
  }, [state]);

  const processFile = async (file: File) => {
    if (!file) return;

    if (!file.name.endsWith(".xml")) {
      toast.error("Invalid file format. Please upload an XML report.");
      return;
    }

    setState("uploading");
    setErrorMessage("");

    try {
      const reader = new FileReader();
      reader.onload = async (e) => {
        const fileContent = e.target?.result as string;
        try {
          const result = await findingsService.uploadScan(fileContent);
          
          const scanData: SessionScanData = {
            fileName: file.name,
            detectedType: result.detectedScanType,
            importedTime: new Date().toLocaleString("en-US", {
              year: "numeric",
              month: "short",
              day: "numeric",
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
            }),
            assets: result.assetsDiscovered,
            findings: result.findingsImported,
            attackPaths: result.attackPathsGenerated,
          };
          
          sessionStorage.setItem("vyuha_imported_scan", JSON.stringify(scanData));
          setImportedScan(scanData);
          setState("success");
          toast.success("Telemetry report processed successfully.");
        } catch (err: any) {
          console.error(err);
          const errorText = err.response?.data?.error || err.message || "Failed to process scan report.";
          setErrorMessage(errorText);
          setState("error");
          toast.error("Telemetry import failed.");
        }
      };
      reader.readAsText(file);
    } catch (err: any) {
      console.error(err);
      setErrorMessage(err.message || "File reading failed.");
      setState("error");
    }
  };

  const handleClearScan = () => {
    sessionStorage.removeItem("vyuha_imported_scan");
    setImportedScan(null);
    setState("idle");
  };

  // Drag & Drop event handlers
  const handleDrag = (e: React.DragEvent, active: boolean) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(active);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0]);
    }
  };

  return (
    <div className="max-w-xl mx-auto flex flex-col justify-center min-h-[75vh] space-y-6">
      {/* Header Info */}
      <div className="text-center space-y-2">
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100 flex items-center justify-center gap-2">
          <FileUp className="h-6 w-6 text-cyber-primary" />
          Import Security Scan
        </h1>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Upload an Nmap or OpenVAS XML report. VYUHA.AI automatically detects the scan type and generates assets, findings and attack paths.
        </p>
      </div>

      <AnimatePresence mode="wait">
        {state === "idle" && (
          <motion.div
            key="idle"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            transition={{ duration: 0.25 }}
          >
            <Card className="bg-white/60 dark:bg-slate-900/60 backdrop-blur border border-slate-200/50 dark:border-slate-800/50 transition-premium shadow-md">
              <CardContent className="p-8">
                <div
                  onDragOver={(e) => handleDrag(e, true)}
                  onDragLeave={(e) => handleDrag(e, false)}
                  onDrop={handleDrop}
                  className={`border-2 border-dashed rounded-2xl p-10 flex flex-col items-center justify-center text-center cursor-pointer transition-all duration-300 ${
                    dragActive 
                      ? "border-cyber-primary bg-blue-50/20 dark:bg-blue-950/10 scale-[1.02]" 
                      : "border-slate-200 dark:border-slate-800 hover:border-cyber-primary/75 hover:bg-slate-50/30 dark:hover:bg-slate-950/20"
                  }`}
                  onClick={() => fileInputRef.current?.click()}
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".xml"
                    onChange={handleFileChange}
                    className="hidden"
                  />
                  
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-blue-50 dark:bg-blue-950/40 text-cyber-primary border border-blue-100 dark:border-blue-900/30 mb-4">
                    <Upload className={`h-6 w-6 transition-colors ${dragActive ? "text-cyber-primary" : "text-slate-400"}`} />
                  </div>

                  <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                    Drag & Drop XML file here
                  </p>
                  <p className="text-xs text-slate-400 dark:text-slate-500 my-1">
                    or
                  </p>
                  <Button 
                    variant="outline" 
                    size="sm" 
                    onClick={(e) => {
                      e.stopPropagation();
                      fileInputRef.current?.click();
                    }}
                    className="mt-1 text-xs"
                  >
                    Browse File
                  </Button>
                </div>

                <div className="mt-6 pt-4 border-t border-slate-100 dark:border-slate-800/60 text-center">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500 block mb-2">
                    Supported:
                  </span>
                  <div className="flex items-center justify-center gap-6 text-xs text-slate-650 font-mono">
                    <span className="flex items-center gap-1.5">
                      <FileCode className="h-3.5 w-3.5 text-blue-500" />
                      Nmap XML
                    </span>
                    <span className="flex items-center gap-1.5">
                      <FileCode className="h-3.5 w-3.5 text-purple-500" />
                      OpenVAS XML
                    </span>
                  </div>
                </div>

                <div className="mt-4 flex items-center justify-center gap-1 text-[10px] text-slate-500 font-mono">
                  <Shield className="h-3.5 w-3.5 text-emerald-500" />
                  Secure Sandbox Ingest
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}

        {state === "uploading" && (
          <motion.div
            key="uploading"
            initial={{ opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.96 }}
            transition={{ duration: 0.2 }}
            className="flex flex-col items-center justify-center p-12 border border-slate-200/50 dark:border-slate-800/50 bg-white/60 dark:bg-slate-900/60 backdrop-blur rounded-[24px]"
          >
            <div className="relative flex items-center justify-center mb-6">
              <div className="absolute h-16 w-16 rounded-full border-4 border-blue-500/10 dark:border-blue-500/5 animate-pulse" />
              <Loader2 className="h-10 w-10 text-cyber-primary animate-spin" />
            </div>
            
            <h3 className="text-base font-bold text-slate-900 dark:text-slate-150 tracking-tight">
              Analyzing Vulnerability Telemetry
            </h3>
            
            <div className="h-5 overflow-hidden mt-2 relative w-64 text-center">
              <AnimatePresence mode="wait">
                <motion.p
                  key={loadingStep}
                  initial={{ y: 15, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  exit={{ y: -15, opacity: 0 }}
                  transition={{ duration: 0.3 }}
                  className="text-xs text-slate-500 dark:text-slate-400 font-mono"
                >
                  {loadingMessages[loadingStep]}
                </motion.p>
              </AnimatePresence>
            </div>

            {/* Premium progress line */}
            <div className="w-56 bg-slate-100 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden mt-6">
              <motion.div 
                className="bg-cyber-primary h-full rounded-full"
                initial={{ width: "5%" }}
                animate={{ width: "95%" }}
                transition={{ duration: 15, ease: "easeOut" }}
              />
            </div>
          </motion.div>
        )}

        {state === "success" && importedScan && (
          <motion.div
            key="success"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            transition={{ duration: 0.25 }}
            className="space-y-6"
          >
            <Card className="bg-white/80 dark:bg-slate-900/80 border border-slate-200/50 dark:border-slate-800/50 shadow-md">
              <div className="p-6 border-b border-slate-100 dark:border-slate-800/60 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-50 dark:bg-emerald-950/40 text-emerald-500 border border-emerald-100 dark:border-emerald-900/30">
                    <CheckCircle2 className="h-5 w-5" />
                  </div>
                  <div>
                    <CardTitle className="text-base font-bold">Current Scan</CardTitle>
                    <CardDescription className="text-xs">
                      Active security telemetry session.
                    </CardDescription>
                  </div>
                </div>
                <Badge variant="primary" className="font-mono text-[9px] uppercase tracking-wider">
                  Active Session
                </Badge>
              </div>

              <CardContent className="p-6 space-y-6">
                {/* Scan Metadata */}
                <div className="space-y-3.5 bg-slate-50/50 dark:bg-slate-950/20 border border-slate-100 dark:border-slate-800/50 p-4.5 rounded-2xl">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
                      <FileText className="h-3.5 w-3.5 text-blue-500" />
                      File Name
                    </span>
                    <span className="font-semibold text-slate-850 dark:text-slate-200 truncate max-w-[250px]" title={importedScan.fileName}>
                      {importedScan.fileName}
                    </span>
                  </div>
                  
                  <div className="flex items-center justify-between text-xs font-mono border-t border-slate-100/50 dark:border-slate-800/30 pt-3">
                    <span className="text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
                      <Shield className="h-3.5 w-3.5 text-purple-500" />
                      Detected Type
                    </span>
                    <Badge variant="secondary" className="font-semibold">
                      {importedScan.detectedType}
                    </Badge>
                  </div>

                  <div className="flex items-center justify-between text-xs font-mono border-t border-slate-100/50 dark:border-slate-800/30 pt-3">
                    <span className="text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
                      <Clock className="h-3.5 w-3.5 text-amber-500" />
                      Imported Time
                    </span>
                    <span className="text-slate-800 dark:text-slate-350 font-medium">
                      {importedScan.importedTime}
                    </span>
                  </div>
                </div>

                {/* Scan Metrics */}
                <div>
                  <h3 className="text-[10px] uppercase tracking-widest text-slate-400 dark:text-slate-500 font-bold mb-3">
                    Key Metrics
                  </h3>

                  <div className="grid grid-cols-3 gap-3">
                    {/* Assets */}
                    <div className="bg-slate-50/50 dark:bg-slate-950/30 border border-slate-100 dark:border-slate-800/60 p-4 rounded-xl flex flex-col justify-between transition-all hover:bg-slate-50 dark:hover:bg-slate-950/50">
                      <span className="text-[10px] uppercase font-semibold text-slate-500 dark:text-slate-400 font-sans flex items-center gap-1">
                        <Database className="h-3 w-3 text-cyan-500" />
                        Assets
                      </span>
                      <span className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-2">
                        {importedScan.assets}
                      </span>
                    </div>

                    {/* Findings */}
                    <div className="bg-slate-50/50 dark:bg-slate-950/30 border border-slate-100 dark:border-slate-800/60 p-4 rounded-xl flex flex-col justify-between transition-all hover:bg-slate-50 dark:hover:bg-slate-950/50">
                      <span className="text-[10px] uppercase font-semibold text-slate-500 dark:text-slate-400 font-sans flex items-center gap-1">
                        <ShieldAlert className="h-3 w-3 text-rose-500" />
                        Findings
                      </span>
                      <span className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-2">
                        {importedScan.findings}
                      </span>
                    </div>

                    {/* Attack Paths */}
                    <div className="bg-slate-50/50 dark:bg-slate-950/30 border border-slate-100 dark:border-slate-800/60 p-4 rounded-xl flex flex-col justify-between transition-all hover:bg-slate-50 dark:hover:bg-slate-950/50">
                      <span className="text-[10px] uppercase font-semibold text-slate-500 dark:text-slate-400 font-sans flex items-center gap-1">
                        <Network className="h-3 w-3 text-indigo-500" />
                        Attack Paths
                      </span>
                      <span className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-2">
                        {importedScan.attackPaths}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex flex-col items-center justify-center p-5 border border-blue-100/50 dark:border-blue-900/30 bg-blue-50/10 dark:bg-blue-950/10 rounded-2xl">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-50 dark:bg-blue-950/40 text-cyber-primary border border-blue-100 dark:border-blue-900/30 mb-2">
                    <Zap className="h-4 w-4" />
                  </div>
                  <p className="text-xs text-slate-700 dark:text-slate-350 text-center font-medium">
                    Attack graphs have been automatically updated based on the imported vulnerabilities and assets.
                  </p>
                  
                  <div className="flex flex-col sm:flex-row gap-3 w-full mt-4 justify-center">
                    <Button
                      onClick={() => navigate("/graph")}
                      variant="default"
                      className="gap-2 font-semibold flex-1 justify-center"
                    >
                      <Network className="h-4 w-4" />
                      Open Attack Graph
                    </Button>
                    <Button
                      onClick={handleClearScan}
                      variant="outline"
                      className="gap-2 font-semibold flex-1 justify-center border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300"
                    >
                      <FileUp className="h-4 w-4" />
                      Import New Scan
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}

        {state === "error" && (
          <motion.div
            key="error"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            transition={{ duration: 0.25 }}
          >
            <Card className="bg-white/80 dark:bg-slate-900/80 border border-red-200/50 dark:border-red-900/50">
              <CardHeader className="pb-4">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-red-50 dark:bg-red-950/40 text-red-500 border border-red-100 dark:border-red-900/30 mb-2">
                  <AlertTriangle className="h-5 w-5" />
                </div>
                <CardTitle className="text-base font-bold text-red-600 dark:text-red-400">Import Failure</CardTitle>
                <CardDescription className="text-xs">
                  An error occurred while executing the parser pipeline.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="bg-red-50/50 dark:bg-red-950/15 border border-red-100/50 dark:border-red-900/30 p-4 rounded-xl">
                  <p className="text-xs font-mono text-red-700 dark:text-red-400 whitespace-pre-wrap">
                    {errorMessage}
                  </p>
                </div>
                <div className="flex gap-3">
                  <Button 
                    onClick={() => setState("idle")}
                    variant="neutral"
                  >
                    Try Again
                  </Button>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default ScanImportPage;
