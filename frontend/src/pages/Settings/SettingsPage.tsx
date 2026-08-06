import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { 
  User, 
  Sun, 
  Moon, 
  Bell, 
  Key, 
  ShieldCheck, 
  UserCheck, 
  Lock, 
  Eye, 
  EyeOff,
  Copy,
  Plus,
  Trash2,
  ArrowLeft
} from "lucide-react";
import { useAuth } from "../../hooks/useAuth";
import { useSettingsData, useUpdateSettingsMutation } from "../../hooks/queries/useVyuhaQueries";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../../components/ui/Card";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { Input } from "../../components/ui/Input";
import { Skeleton } from "../../components/ui/Skeleton";
import { cn } from "../../utils/cn";
import { toast } from "sonner";

interface ApiKeyItem {
  id: string;
  name: string;
  key: string;
  created: string;
  status: "active" | "revoked";
}

export function SettingsPage() {
  const navigate = useNavigate();
  const { user, updateUser } = useAuth();
  const { data: settings, isLoading } = useSettingsData();
  const updateSettings = useUpdateSettingsMutation();
  
  // Active configuration Tab
  const [activeTab, setActiveTab] = useState<"profile" | "theme" | "notifications" | "api" | "preferences" | "role" | "security">("profile");

  // Profile forms state
  const [profileName, setProfileName] = useState(user?.username || "Kaveesh");
  const [profileEmail, setProfileEmail] = useState("kaveesh@vyuha.ai");
  const [profileTitle, setProfileTitle] = useState("Senior SOC Analyst");

  // Theme states
  const [themeContrast, setThemeContrast] = useState<"standard" | "high">("standard");

  // Notifications webhooks state
  const [slackWebhook, setSlackWebhook] = useState("https://hooks.slack.com/services/T00/B00/X00");
  const [syslogServer, setSyslogServer] = useState("10.120.50.44:514");

  // API Keys state
  const [showKeyId, setShowKeyId] = useState<string | null>(null);
  const [apiKeys, setApiKeys] = useState<ApiKeyItem[]>([
    { id: "key-1", name: "Palo Alto Edge Collector", key: "vyuha_live_pk_88d29a1a44c4b223", created: "2026-06-12", status: "active" },
    { id: "key-2", name: "Sentinel Workstation Agent", key: "vyuha_live_pk_12d09f3b14a2b918", created: "2026-07-02", status: "active" }
  ]);

  // Preferences toggles
  const [autoIsolateCriticals, setAutoIsolateCriticals] = useState(true);
  const [allowLateralBlockGates, setAllowLateralBlockGates] = useState(false);

  // Security password resets
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [enable2Fa, setEnable2Fa] = useState(true);

  // Sync profile details when loaded from React Query
  useEffect(() => {
    if (settings) {
      setProfileName(settings.profile.name);
      setProfileEmail(settings.profile.email);
      setProfileTitle(settings.profile.title);
      setThemeContrast(settings.theme.contrast);
      setSlackWebhook(settings.notifications.slack);
      setSyslogServer(settings.notifications.syslog);
      setAutoIsolateCriticals(settings.preferences.autoIsolate);
      setAllowLateralBlockGates(settings.preferences.blockLateral);
      setEnable2Fa(settings.security.enable2Fa);
    }
  }, [settings]);

  if (isLoading || !settings) {
    return (
      <div className="space-y-6">
        <div className="h-10 w-48 bg-slate-200/60 animate-pulse rounded-md" />
        <div className="grid grid-cols-1 xl:grid-cols-4 gap-6 items-start mt-4">
          <Skeleton className="h-[200px] w-full xl:col-span-1 rounded-md" />
          <Skeleton className="h-[300px] w-full xl:col-span-3 rounded-md" />
        </div>
      </div>
    );
  }

  const handleSaveSettings = (section: string) => {
    updateSettings.mutate({
      profile: { name: profileName, email: profileEmail, title: profileTitle },
      theme: { contrast: themeContrast },
      notifications: { slack: slackWebhook, syslog: syslogServer },
      preferences: { autoIsolate: autoIsolateCriticals, blockLateral: allowLateralBlockGates },
      security: { enable2Fa }
    }, {
      onSuccess: () => {
        toast.success(`Settings for "${section}" updated successfully.`);
        if (section === "Profile") {
          updateUser({
            username: profileName,
            role: profileTitle
          });
        }
      }
    });
  };

  const handleCopyKey = (key: string) => {
    navigator.clipboard.writeText(key);
    toast.success("API key copied to clipboard!");
  };

  const handleGenerateKey = () => {
    const newId = `key-${apiKeys.length + 1}`;
    const newKey: ApiKeyItem = {
      id: newId,
      name: "New Threat Sensor Ingest",
      key: `vyuha_live_pk_${Math.random().toString(16).substring(2, 10)}b881b229`,
      created: new Date().toISOString().split("T")[0],
      status: "active"
    };
    setApiKeys([...apiKeys, newKey]);
    toast.success("New API key generated.");
  };

  const handleRevokeKey = (id: string) => {
    setApiKeys(prev => prev.map(k => k.id === id ? { ...k, status: "revoked" as const } : k));
    toast.error("API key revoked.");
  };

  // Clearances list
  const clearances = [
    { title: "Device Scan Data Triaging", desc: "Read and review host directory profiles and process handles." },
    { title: "PowerShell process execution", desc: "Quarantine processes and trigger administrative shells." },
    { title: "Boundary firewall overrides", desc: "Authorize Palo Alto edge IP block rules." }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 border-b border-slate-200/70 pb-5 dark:border-slate-800/70 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 font-sans dark:text-slate-100">
            Settings & Configurations
          </h1>
          <p className="mt-1 text-xs text-slate-500 font-sans dark:text-slate-400">
            Configure security profiles, webhook integrations, autonomous threat settings, and API ingestion keys.
          </p>
        </div>
        <div>
          <Button variant="ghost" size="icon" className="h-7 w-7 text-slate-400" onClick={() => navigate("/")}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Main split tab container */}
      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6 items-start">
        
        {/* Left Navigation tab list (1/4 width) */}
        <div className="xl:col-span-1 space-y-1 rounded-[20px] border border-slate-200/80 bg-slate-50/80 p-2.5 font-mono text-xs shadow-sm select-none dark:border-slate-800 dark:bg-slate-950/70">
          
          <button
            onClick={() => setActiveTab("profile")}
            className={cn(
              "w-full text-left rounded p-2.5 transition-premium flex items-center space-x-2.5 cursor-pointer",
              activeTab === "profile" 
                ? "bg-white text-slate-900 font-semibold border-l-2 border-brand-accent pl-2.5 shadow-sm" 
                : "text-slate-500 hover:bg-white/60 hover:text-slate-900"
            )}
          >
            <User className="h-4 w-4 text-slate-400" />
            <span>Profile settings</span>
          </button>

          <button
            onClick={() => setActiveTab("theme")}
            className={cn(
              "w-full text-left rounded p-2.5 transition-premium flex items-center space-x-2.5 cursor-pointer",
              activeTab === "theme" 
                ? "bg-white text-slate-900 font-semibold border-l-2 border-brand-accent pl-2.5 shadow-sm" 
                : "text-slate-500 hover:bg-white/60 hover:text-slate-900"
            )}
          >
            <Sun className="h-4 w-4 text-slate-400" />
            <span>Theme controls</span>
          </button>

          <button
            onClick={() => setActiveTab("notifications")}
            className={cn(
              "w-full text-left rounded p-2.5 transition-premium flex items-center space-x-2.5 cursor-pointer",
              activeTab === "notifications" 
                ? "bg-white text-slate-900 font-semibold border-l-2 border-brand-accent pl-2.5 shadow-sm" 
                : "text-slate-500 hover:bg-white/60 hover:text-slate-900"
            )}
          >
            <Bell className="h-4 w-4 text-slate-400" />
            <span>Notifications webhooks</span>
          </button>

          <button
            onClick={() => setActiveTab("api")}
            className={cn(
              "w-full text-left rounded p-2.5 transition-premium flex items-center space-x-2.5 cursor-pointer",
              activeTab === "api" 
                ? "bg-white text-slate-900 font-semibold border-l-2 border-brand-accent pl-2.5 shadow-sm" 
                : "text-slate-500 hover:bg-white/60 hover:text-slate-900"
            )}
          >
            <Key className="h-4 w-4 text-slate-400" />
            <span>API Ingest keys</span>
          </button>

          <button
            onClick={() => setActiveTab("preferences")}
            className={cn(
              "w-full text-left rounded p-2.5 transition-premium flex items-center space-x-2.5 cursor-pointer",
              activeTab === "preferences" 
                ? "bg-white text-slate-900 font-semibold border-l-2 border-brand-accent pl-2.5 shadow-sm" 
                : "text-slate-500 hover:bg-white/60 hover:text-slate-900"
            )}
          >
            <ShieldCheck className="h-4 w-4 text-slate-400" />
            <span>Preferences policies</span>
          </button>

          <button
            onClick={() => setActiveTab("role")}
            className={cn(
              "w-full text-left rounded p-2.5 transition-premium flex items-center space-x-2.5 cursor-pointer",
              activeTab === "role" 
                ? "bg-white text-slate-900 font-semibold border-l-2 border-brand-accent pl-2.5 shadow-sm" 
                : "text-slate-500 hover:bg-white/60 hover:text-slate-900"
            )}
          >
            <UserCheck className="h-4 w-4 text-slate-400" />
            <span>Role clearances</span>
          </button>

          <button
            onClick={() => setActiveTab("security")}
            className={cn(
              "w-full text-left rounded p-2.5 transition-premium flex items-center space-x-2.5 cursor-pointer",
              activeTab === "security" 
                ? "bg-white text-slate-900 font-semibold border-l-2 border-brand-accent pl-2.5 shadow-sm" 
                : "text-slate-500 hover:bg-white/60 hover:text-slate-900"
            )}
          >
            <Lock className="h-4 w-4 text-slate-400" />
            <span>Security & 2FA</span>
          </button>
        </div>

        {/* Right Active tab Forms Panel (3/4 width) */}
        <div className="xl:col-span-3 space-y-6">
          
          {/* PROFILE TAB */}
          {activeTab === "profile" && (
            <Card className="rounded-lg shadow-card bg-white border-slate-200">
              <CardHeader>
                <CardTitle className="text-slate-800">Operator Profile</CardTitle>
                <CardDescription>Update your workstation identify context.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono uppercase text-slate-450 block font-semibold">Operator Name</span>
                    <Input value={profileName} onChange={(e) => setProfileName(e.target.value)} className="text-xs font-mono border-slate-200 bg-slate-50/50" />
                  </div>
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono uppercase text-slate-450 block font-semibold">Email Address</span>
                    <Input value={profileEmail} onChange={(e) => setProfileEmail(e.target.value)} className="text-xs font-mono border-slate-200 bg-slate-50/50" />
                  </div>
                  <div className="space-y-1 md:col-span-2">
                    <span className="text-[10px] font-mono uppercase text-slate-450 block font-semibold">SOC Title</span>
                    <Input value={profileTitle} onChange={(e) => setProfileTitle(e.target.value)} className="text-xs font-mono border-slate-200 bg-slate-50/50" />
                  </div>
                </div>
                <div className="pt-3 border-t border-slate-100 flex justify-end">
                  <Button variant="cyber" size="sm" className="font-mono text-[10px]" onClick={() => handleSaveSettings("Profile")}>
                    SAVE PROFILE
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* THEME TAB */}
          {activeTab === "theme" && (
            <Card className="rounded-lg shadow-card bg-white border-slate-200">
              <CardHeader>
                <CardTitle className="text-slate-800">Theme & Contrast controls</CardTitle>
                <CardDescription>Select visual style layouts for operations monitoring.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 select-none">
                  {/* Standard theme */}
                  <div 
                    onClick={() => {
                      setThemeContrast("standard");
                      document.documentElement.classList.remove("high-contrast");
                      toast.success("Standard Light theme activated.");
                    }}
                    className={cn(
                      "p-4 border rounded-md cursor-pointer transition-premium flex flex-col justify-between h-28",
                      themeContrast === "standard" 
                        ? "border-brand-accent bg-blue-50/10 shadow-sm" 
                        : "border-slate-200 bg-slate-50/50 hover:bg-slate-50 hover:border-slate-350"
                    )}
                  >
                    <div className="flex items-center space-x-2">
                      <Sun className="h-4 w-4 text-cyber-primary" />
                      <span className="font-mono text-xs font-bold text-slate-800">Standard Light Theme</span>
                    </div>
                    <span className="text-[10px] text-slate-500 font-sans leading-relaxed">
                      Sleek slate borders with subtle shadows for premium layouts.
                    </span>
                  </div>

                  {/* High contrast theme */}
                  <div 
                    onClick={() => {
                      setThemeContrast("high");
                      document.documentElement.classList.add("high-contrast");
                      toast.success("High Contrast Light theme activated.");
                    }}
                    className={cn(
                      "p-4 border rounded-md cursor-pointer transition-premium flex flex-col justify-between h-28",
                      themeContrast === "high" 
                        ? "border-brand-accent bg-blue-50/10 shadow-sm" 
                        : "border-slate-200 bg-slate-55/50 hover:bg-slate-100 hover:border-slate-350"
                    )}
                  >
                    <div className="flex items-center space-x-2">
                      <Sun className="h-4 w-4 text-cyber-high" />
                      <span className="font-mono text-xs font-bold text-slate-800">Tactical High Contrast</span>
                    </div>
                    <span className="text-[10px] text-slate-555 font-sans leading-relaxed">
                      Thicker borders with maximum contrast ratio for accessibility checks.
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* NOTIFICATIONS TAB */}
          {activeTab === "notifications" && (
            <Card className="rounded-lg shadow-card bg-white border-slate-200">
              <CardHeader>
                <CardTitle className="text-slate-800">Webhook Bindings & Alerts</CardTitle>
                <CardDescription>Ingest threat indicators into external communication channels.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-4">
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono uppercase text-slate-450 block font-semibold">Slack Ingestion URL</span>
                    <Input value={slackWebhook} onChange={(e) => setSlackWebhook(e.target.value)} className="text-xs font-mono border-slate-200 bg-slate-50/50" />
                  </div>
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono uppercase text-slate-450 block font-semibold">Syslog Server bindings</span>
                    <Input value={syslogServer} onChange={(e) => setSyslogServer(e.target.value)} className="text-xs font-mono border-slate-200 bg-slate-50/50" />
                  </div>
                </div>
                <div className="pt-3 border-t border-slate-100 flex justify-end">
                  <Button variant="cyber" size="sm" className="font-mono text-[10px]" onClick={() => handleSaveSettings("Webhooks")}>
                    SAVE WEBHOOKS
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* API KEYS TAB */}
          {activeTab === "api" && (
            <Card className="rounded-lg shadow-card bg-white border-slate-200 overflow-hidden">
              <CardHeader className="flex flex-row items-center justify-between pb-3">
                <div>
                  <CardTitle className="text-slate-800">Ingestion API Keys</CardTitle>
                  <CardDescription>Sensor tokens deploying localized log checking signatures.</CardDescription>
                </div>
                <Button variant="outline" size="sm" className="font-mono text-[9px] h-7 border-slate-200" onClick={handleGenerateKey}>
                  <Plus className="mr-1 h-3.5 w-3.5 text-slate-400" />
                  NEW KEY
                </Button>
              </CardHeader>
              <CardContent className="p-0 border-t border-slate-200 select-none bg-white">
                <div className="overflow-x-auto">
                  <table className="w-full text-xs text-left border-collapse">
                    <thead className="bg-slate-50/50 font-mono text-slate-555 border-b border-slate-200 uppercase tracking-wider">
                      <tr>
                        <th className="p-3.5 pl-4 font-semibold">Collector Name</th>
                        <th className="p-3.5 font-semibold">API Token key</th>
                        <th className="p-3.5 font-semibold">Created</th>
                        <th className="p-3.5 font-semibold">Status</th>
                        <th className="p-3.5 text-right pr-4 font-semibold">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-mono text-slate-600 bg-white">
                      {apiKeys.map(k => (
                        <tr key={k.id} className={cn("hover:bg-slate-50/50 transition-premium", k.status === "revoked" && "opacity-50")}>
                          <td className="p-3.5 pl-4 font-sans font-semibold text-slate-800">{k.name}</td>
                          <td className="p-3.5 font-mono">
                            <div className="flex items-center space-x-2">
                              <span>{showKeyId === k.id ? k.key : "••••••••••••••••••••••••"}</span>
                              <button 
                                onClick={() => setShowKeyId(showKeyId === k.id ? null : k.id)} 
                                className="text-slate-400 hover:text-slate-900 p-0.5 cursor-pointer"
                              >
                                {showKeyId === k.id ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                              </button>
                            </div>
                          </td>
                          <td className="p-3.5 text-slate-500">{k.created}</td>
                          <td className="p-3.5">
                            <span className={cn(
                              "px-1.5 py-0.5 rounded border text-[9px] font-bold uppercase",
                              k.status === "active" 
                                ? "bg-green-50 text-cyber-low border-green-150" 
                                : "bg-slate-50 text-slate-450 border-slate-200"
                            )}>
                              {k.status}
                            </span>
                          </td>
                          <td className="p-3.5 text-right pr-4 flex justify-end gap-2.5">
                            {k.status === "active" && (
                              <>
                                <button 
                                  onClick={() => handleCopyKey(k.key)}
                                  className="text-slate-400 hover:text-cyber-primary p-0.5 cursor-pointer"
                                  title="Copy"
                                >
                                  <Copy className="h-3.5 w-3.5" />
                                </button>
                                <button 
                                  onClick={() => handleRevokeKey(k.id)}
                                  className="text-slate-400 hover:text-cyber-critical p-0.5 cursor-pointer"
                                  title="Revoke"
                                >
                                  <Trash2 className="h-3.5 w-3.5" />
                                </button>
                              </>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}

          {/* PREFERENCES TAB */}
          {activeTab === "preferences" && (
            <Card className="rounded-lg shadow-card bg-white border-slate-200">
              <CardHeader>
                <CardTitle className="text-slate-800">Autonomous Playbook Overrides</CardTitle>
                <CardDescription>Select warning thresholds before launching automated agent isolations.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-4">
                  {/* Auto Isolate toggle */}
                  <div className="flex items-center justify-between p-3 border border-slate-200 bg-slate-50 rounded-md select-none shadow-sm">
                    <div className="space-y-0.5">
                      <span className="text-xs font-semibold text-slate-850">Enforce Automated quarantine</span>
                      <span className="text-[10px] text-slate-500 block font-sans">
                        Automatically isolate hosts from production VLAN segments upon matching critical ransomware.
                      </span>
                    </div>
                    <button
                      onClick={() => {
                        setAutoIsolateCriticals(prev => !prev);
                        handleSaveSettings("Autonomous Isolation");
                      }}
                      className={cn(
                        "w-10 h-5.5 rounded-full p-0.5 transition-colors duration-200 focus:outline-none cursor-pointer shrink-0",
                        autoIsolateCriticals ? "bg-cyber-primary" : "bg-slate-200"
                      )}
                    >
                      <div className={cn(
                        "w-4.5 h-4.5 bg-white shadow rounded-full transition-transform duration-200",
                        autoIsolateCriticals ? "translate-x-4.5" : "translate-x-0"
                      )} />
                    </button>
                  </div>

                  {/* Allow lateral blocks */}
                  <div className="flex items-center justify-between p-3 border border-slate-200 bg-slate-50 rounded-md select-none shadow-sm">
                    <div className="space-y-0.5">
                      <span className="text-xs font-semibold text-slate-850">Automatic lateral route blocks</span>
                      <span className="text-[10px] text-slate-500 block font-sans">
                        Block segment-to-segment RDP gateways if lateral credential dump vectors are logged.
                      </span>
                    </div>
                    <button
                      onClick={() => {
                        setAllowLateralBlockGates(prev => !prev);
                        handleSaveSettings("Lateral Segment blocks");
                      }}
                      className={cn(
                        "w-10 h-5.5 rounded-full p-0.5 transition-colors duration-200 focus:outline-none cursor-pointer shrink-0",
                        allowLateralBlockGates ? "bg-cyber-primary" : "bg-slate-200"
                      )}
                    >
                      <div className={cn(
                        "w-4.5 h-4.5 bg-white shadow rounded-full transition-transform duration-200",
                        allowLateralBlockGates ? "translate-x-4.5" : "translate-x-0"
                      )} />
                    </button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* ROLE TAB */}
          {activeTab === "role" && (
            <div className="space-y-4 select-none">
              <h3 className="text-xs font-mono font-bold tracking-wider text-slate-400 uppercase flex items-center gap-1.5 pl-1">
                <UserCheck className="h-4 w-4 text-cyber-primary" /> Active Operator clearances
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {clearances.map((c, idx) => (
                  <Card key={idx} className="bg-white border-slate-200 rounded-lg shadow-card flex flex-col justify-between min-h-[140px]">
                    <CardHeader className="pb-2">
                      <CardTitle className="font-mono text-[10.5px] leading-tight text-slate-800">{c.title}</CardTitle>
                    </CardHeader>
                    <CardContent className="p-4 pt-0 text-[10px] text-slate-600 font-sans leading-relaxed">
                      {c.desc}
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}

          {/* SECURITY TAB */}
          {activeTab === "security" && (
            <Card className="rounded-lg shadow-card bg-white border-slate-200">
              <CardHeader>
                <CardTitle className="text-slate-800">Security & Password resets</CardTitle>
                <CardDescription>Reset operator passwords and configure 2-factor authentication keys.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3.5">
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono uppercase text-slate-450 block font-semibold">Current password</span>
                    <Input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} className="text-xs font-mono border-slate-200 bg-slate-50/50" />
                  </div>
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono uppercase text-slate-450 block font-semibold">New password</span>
                    <Input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} className="text-xs font-mono border-slate-200 bg-slate-50/50" />
                  </div>
                  
                  {/* 2FA Toggle */}
                  <div className="flex items-center justify-between p-3 border border-slate-200 bg-slate-50 rounded-md select-none shadow-sm">
                    <div className="space-y-0.5">
                      <span className="text-xs font-semibold text-slate-850">Enforce Multi-Factor (2FA)</span>
                      <span className="text-[10px] text-slate-500 block font-sans">
                        Mandate physical security key validations during operator login gates.
                      </span>
                    </div>
                    <button
                      onClick={() => {
                        setEnable2Fa(prev => !prev);
                        handleSaveSettings("2FA Enforcements");
                      }}
                      className={cn(
                        "w-10 h-5.5 rounded-full p-0.5 transition-colors duration-200 focus:outline-none cursor-pointer shrink-0",
                        enable2Fa ? "bg-cyber-primary" : "bg-slate-200"
                      )}
                    >
                      <div className={cn(
                        "w-4.5 h-4.5 bg-white shadow rounded-full transition-transform duration-200",
                        enable2Fa ? "translate-x-4.5" : "translate-x-0"
                      )} />
                    </button>
                  </div>
                </div>
                <div className="pt-3 border-t border-slate-100 flex justify-end">
                  <Button variant="cyber" size="sm" className="font-mono text-[10px]" onClick={() => handleSaveSettings("Passwords Profile")}>
                    UPDATE CREDENTIALS
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

        </div>
      </div>
    </div>
  );
}

export default SettingsPage;
