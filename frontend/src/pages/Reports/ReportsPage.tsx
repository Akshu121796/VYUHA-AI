import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { 
  FileText, 
  Download, 
  CheckCircle, 
  ShieldAlert, 
  BookOpen, 
  FileSpreadsheet,
  Plus,
  ArrowLeft
} from "lucide-react";
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  LineChart, 
  Line, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip as ChartTooltip, 
  Legend 
} from "recharts";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../components/ui/Card";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { Skeleton } from "../../components/ui/Skeleton";
import { useReportsData, useGenerateReportMutation } from "../../hooks/queries/useVyuhaQueries";
import { cn } from "../../utils/cn";
import { toast } from "sonner";

export function ReportsPage() {
  const navigate = useNavigate();
  const { data, isLoading } = useReportsData();
  const generateReport = useGenerateReportMutation();
  
  const [isGenerating, setIsGenerating] = useState(false);
  const [progress, setProgress] = useState(0);

  if (isLoading || !data) {
    return (
      <div className="space-y-6">
        <div className="h-10 w-48 bg-slate-200/60 animate-pulse rounded-md" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Skeleton className="h-[100px] w-full rounded-md" />
          <Skeleton className="h-[100px] w-full rounded-md" />
          <Skeleton className="h-[100px] w-full rounded-md" />
        </div>
        <Skeleton className="h-[280px] w-full mt-4 rounded-md" />
      </div>
    );
  }

  const { reports } = data;

  // Chart 1: Severity Trends (AreaChart)
  const severityTrendData = [
    { name: "Jan", Critical: 12, High: 25, Medium: 35 },
    { name: "Feb", Critical: 8, High: 18, Medium: 28 },
    { name: "Mar", Critical: 14, High: 22, Medium: 30 },
    { name: "Apr", Critical: 5, High: 15, Medium: 22 },
    { name: "May", Critical: 3, High: 10, Medium: 18 },
    { name: "Jun", Critical: 1, High: 5, Medium: 12 }
  ];

  // Chart 2: Risk Trend (LineChart)
  const riskTrendData = [
    { name: "Jan", score: 8.8 },
    { name: "Feb", score: 7.9 },
    { name: "Mar", score: 7.2 },
    { name: "Apr", score: 5.5 },
    { name: "May", score: 4.8 },
    { name: "Jun", score: 3.2 }
  ];

  // Chart 3: Resolved Findings (BarChart)
  const resolvedData = [
    { name: "Jan", Resolved: 12, Active: 20 },
    { name: "Feb", Resolved: 15, Active: 18 },
    { name: "Mar", Resolved: 22, Active: 15 },
    { name: "Apr", Resolved: 25, Active: 8 },
    { name: "May", Resolved: 30, Active: 5 },
    { name: "Jun", Resolved: 35, Active: 2 }
  ];

  const handleGenerateReport = () => {
    setIsGenerating(true);
    setProgress(0);

    const interval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 90) {
          clearInterval(interval);
          return 90;
        }
        return prev + 15;
      });
    }, 150);

    setTimeout(() => {
      generateReport.mutate(undefined, {
        onSuccess: () => {
          clearInterval(interval);
          setProgress(100);
          setTimeout(() => {
            setIsGenerating(false);
            setProgress(0);
            toast.success("Security Audit Report generated successfully!");
          }, 400);
        }
      });
    }, 1200);
  };

  const handleDownload = (id: string, format: "PDF" | "CSV") => {
    toast.success(`Downloading ${format} file for report ${id}...`);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-3 border-b border-slate-200/70 pb-5 dark:border-slate-800/70 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 font-sans dark:text-slate-100">
            Reports & Compliance
          </h1>
          <p className="mt-1 text-xs text-slate-500 font-sans dark:text-slate-400">
            Generate and export SOC security compliance summaries and threat trends.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" className="h-7 w-7 text-slate-400" onClick={() => navigate("/")}>
            <ArrowLeft className="h-4 w-4" />
          </Button>

          {isGenerating ? (
            <div className="w-[185px] rounded-xl border border-slate-200 bg-slate-50 p-2.5 text-center font-mono text-[9px] shadow-sm select-none dark:border-slate-700 dark:bg-slate-900">
              <div className="h-1 bg-slate-200 rounded-full overflow-hidden mb-1.5">
                <div className="h-full bg-brand-accent transition-all duration-100" style={{ width: `${progress}%` }} />
              </div>
              <span className="text-slate-500 font-bold">COMPILING METRICS: {progress}%</span>
            </div>
          ) : (
            <Button variant="cyber" size="sm" className="font-mono text-[10px]" onClick={handleGenerateReport}>
              <Plus className="mr-1.5 h-3.5 w-3.5" />
              GENERATE REPORT
            </Button>
          )}
        </div>
      </div>

      {/* Row 1: 3 Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        
        {/* Card 1: Total Reports */}
        <Card hoverable className="rounded-lg">
          <CardContent className="p-5 flex items-center justify-between">
            <div className="space-y-1 select-none">
              <span className="text-[9px] font-mono uppercase tracking-wider text-slate-450 block font-semibold">Total Reports</span>
              <span className="text-2xl font-bold font-mono tracking-tight text-cyber-primary block">{reports.length}</span>
              <span className="text-[9px] font-mono text-slate-400 block">Generated in session</span>
            </div>
            <div className="h-9 w-9 bg-blue-50 border border-blue-100 text-cyber-primary flex items-center justify-center rounded">
              <BookOpen className="h-4.5 w-4.5" />
            </div>
          </CardContent>
        </Card>

        {/* Card 2: Weekly Summary */}
        <Card hoverable className="rounded-lg">
          <CardContent className="p-5 flex items-center justify-between">
            <div className="space-y-1 select-none">
              <span className="text-[9px] font-mono uppercase tracking-wider text-slate-455 block font-semibold">Weekly Summary</span>
              <span className="text-sm font-bold font-mono tracking-tight text-slate-800 block">3 CRIT • 4 HIGH</span>
              <span className="text-[9px] font-mono text-cyber-low block font-semibold">✓ 6 incidents contained</span>
            </div>
            <div className="h-9 w-9 bg-red-50 border border-red-100 text-cyber-critical flex items-center justify-center rounded">
              <ShieldAlert className="h-4.5 w-4.5 animate-pulse" />
            </div>
          </CardContent>
        </Card>

        {/* Card 3: Monthly Summary */}
        <Card hoverable className="rounded-lg">
          <CardContent className="p-5 flex items-center justify-between">
            <div className="space-y-1 select-none">
              <span className="text-[9px] font-mono uppercase tracking-wider text-slate-450 block font-semibold">Monthly Summary</span>
              <span className="text-sm font-semibold font-mono tracking-tight text-cyber-low block">91% ISO27001 SCORE</span>
              <span className="text-[9px] font-mono text-slate-400 block">SOC2 Compliant state</span>
            </div>
            <div className="h-9 w-9 bg-green-50 border border-green-100 text-cyber-low flex items-center justify-center rounded">
              <CheckCircle className="h-4.5 w-4.5" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Row 2: Charts (Severity Trends & Risk Trend) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Severity Trends (AreaChart) */}
        <Card className="rounded-lg shadow-card">
          <CardHeader>
            <CardTitle className="text-slate-800">Severity Trends</CardTitle>
            <CardDescription>Monthly volume changes of Critical and High threats</CardDescription>
          </CardHeader>
          <CardContent className="h-[220px] pt-4 p-4.5">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={severityTrendData}>
                <defs>
                  <linearGradient id="c1" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.06}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="c2" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.06}/>
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                <XAxis dataKey="name" stroke="#94a3b8" fontSize={9} tickLine={false} axisLine={false} />
                <YAxis stroke="#94a3b8" fontSize={9} tickLine={false} axisLine={false} />
                <ChartTooltip 
                  contentStyle={{ backgroundColor: "#ffffff", borderColor: "#e5e7eb", borderRadius: "6px", fontSize: "10px", fontFamily: "monospace" }} 
                  itemStyle={{ color: "#0f172a" }}
                />
                <Legend verticalAlign="top" height={36} iconType="circle" wrapperStyle={{ fontSize: "10px", fontFamily: "monospace", paddingBottom: "10px" }} />
                <Area type="monotone" dataKey="Critical" stroke="#ef4444" strokeWidth={1.5} fill="url(#c1)" />
                <Area type="monotone" dataKey="High" stroke="#f59e0b" strokeWidth={1.5} fill="url(#c2)" />
                <Area type="monotone" dataKey="Medium" stroke="#eab308" strokeWidth={1.5} fill="transparent" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Risk Trend (LineChart) */}
        <Card className="rounded-lg shadow-card">
          <CardHeader>
            <CardTitle className="text-slate-800">Environmental Risk score Trend</CardTitle>
            <CardDescription>Total calculated CVSS host threat exposure over 6 months</CardDescription>
          </CardHeader>
          <CardContent className="h-[220px] pt-4 p-4.5">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={riskTrendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                <XAxis dataKey="name" stroke="#94a3b8" fontSize={9} tickLine={false} axisLine={false} />
                <YAxis stroke="#94a3b8" fontSize={9} tickLine={false} axisLine={false} />
                <ChartTooltip 
                  contentStyle={{ backgroundColor: "#ffffff", borderColor: "#e5e7eb", borderRadius: "6px", fontSize: "10px", fontFamily: "monospace" }} 
                  itemStyle={{ color: "#0f172a" }}
                />
                <Line type="monotone" dataKey="score" stroke="#2563eb" strokeWidth={2} activeDot={{ r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Row 3: Resolved Findings (BarChart) & Generated Table split */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        
        {/* Resolved Findings BarChart (1/3 width) */}
        <div className="lg:col-span-1">
          <Card className="rounded-lg shadow-card">
            <CardHeader>
              <CardTitle className="text-slate-800">Resolved vs Active</CardTitle>
              <CardDescription>Detections containment success indexes</CardDescription>
            </CardHeader>
            <CardContent className="h-[220px] pt-4 p-4.5">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={resolvedData} barGap={4} barSize={12}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                  <XAxis dataKey="name" stroke="#94a3b8" fontSize={9} tickLine={false} axisLine={false} />
                  <YAxis stroke="#94a3b8" fontSize={9} tickLine={false} axisLine={false} />
                  <ChartTooltip 
                    contentStyle={{ backgroundColor: "#ffffff", borderColor: "#e5e7eb", borderRadius: "6px", fontSize: "10px", fontFamily: "monospace" }} 
                    itemStyle={{ color: "#0f172a" }}
                  />
                  <Legend verticalAlign="top" height={36} wrapperStyle={{ fontSize: "10px", fontFamily: "monospace" }} />
                  <Bar dataKey="Resolved" fill="#22c55e" radius={[3, 3, 0, 0]} />
                  <Bar dataKey="Active" fill="#ef4444" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </div>

        {/* Generated Reports Table (2/3 width) */}
        <div className="lg:col-span-2 space-y-4">
          <h2 className="text-xs font-mono font-bold tracking-wider text-slate-400 uppercase pl-1">
            Generated Document Exporters
          </h2>

          <Card className="border-slate-200 bg-white rounded-lg shadow-card overflow-hidden">
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left border-collapse">
                  <thead className="bg-slate-50/50 border-b border-slate-200 font-mono text-slate-500 uppercase tracking-wider">
                    <tr>
                      <th className="p-3.5 pl-4 font-semibold">Report ID</th>
                      <th className="p-3.5 font-semibold">Document Title</th>
                      <th className="p-3.5 font-semibold">File Specs</th>
                      <th className="p-3.5 font-semibold">Downloads</th>
                      <th className="p-3.5 text-right pr-4 font-semibold">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-mono text-slate-650 bg-white">
                    {isGenerating && (
                      <tr>
                        <td colSpan={5} className="p-4 bg-slate-50/10">
                          <Skeleton className="h-8 w-full rounded" />
                        </td>
                      </tr>
                    )}
                    {reports.map((rep: { id: string; title: string; format: string; size: string; downloadCount: number }) => (
                      <tr key={rep.id} className="hover:bg-slate-50/50 transition-premium">
                        <td className="p-3.5 pl-4 font-bold text-slate-800">{rep.id}</td>
                        <td className="p-3.5 font-sans font-semibold text-slate-800">{rep.title}</td>
                        <td className="p-3.5">
                          <span className="text-[10px] bg-slate-50 border border-slate-200 px-1.5 py-0.5 rounded text-slate-500 font-semibold shadow-sm">
                            {rep.format} • {rep.size}
                          </span>
                        </td>
                        <td className="p-3.5 pl-6">{rep.downloadCount}</td>
                        <td className="p-3.5 text-right pr-4 flex justify-end gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-6.5 text-[9px] font-mono px-2"
                            onClick={() => handleDownload(rep.id, "PDF")}
                          >
                            <Download className="mr-1 h-3 w-3" />
                            PDF
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6.5 text-[9px] font-mono px-2"
                            onClick={() => handleDownload(rep.id, "CSV")}
                          >
                            <FileSpreadsheet className="mr-1 h-3 w-3 text-slate-400" />
                            CSV
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

export default ReportsPage;
