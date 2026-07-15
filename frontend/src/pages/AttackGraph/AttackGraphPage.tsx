import React, { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  NodeProps,
  MarkerType
} from "reactflow";
import "reactflow/dist/style.css";
import { 
  Key, 
  Terminal, 
  ShieldAlert, 
  Network, 
  ShieldCheck, 
  ArrowLeft, 
  Sparkles, 
  Flame, 
  CornerDownRight, 
  Compass
} from "lucide-react";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { cn } from "../../utils/cn";
import { toast } from "sonner";

// Node Interface details
interface AttackNodeData {
  id: string;
  subtitle: string;
  label: string;
  severity: "critical" | "high" | "medium" | "low";
  icon: React.ReactNode;
  tooltip: string;
  ip: string;
  description: string;
  mitigations: string[];
}

// Custom React Flow Node Component
const CustomAttackNode = ({ data }: NodeProps<AttackNodeData>) => {
  return (
    <div className={cn(
      "px-4 py-3 rounded-md bg-white border flex items-center space-x-3 text-left max-w-[220px] select-none group relative transition-premium shadow-card hover:shadow-premium",
      data.severity === "critical" && "border-slate-200 hover:border-cyber-critical shadow-[0_4px_12px_rgba(239,68,68,0.05)]",
      data.severity === "high" && "border-slate-200 hover:border-cyber-high shadow-[0_4px_12px_rgba(249,115,22,0.05)]",
      data.severity === "medium" && "border-slate-200 hover:border-cyber-medium shadow-[0_4px_12px_rgba(234,179,8,0.05)]",
      data.severity === "low" && "border-slate-200 hover:border-cyber-low shadow-[0_4px_12px_rgba(34,197,94,0.05)]"
    )}>
      {/* Target port connections */}
      {data.id !== "weak-credentials" && (
        <Handle 
          type="target" 
          position={Position.Left} 
          style={{ background: "#2563eb", border: "1.5px solid #ffffff", width: 8, height: 8 }} 
        />
      )}

      {/* Side color ribbon */}
      <span className={cn(
        "absolute left-0 top-2 bottom-2 w-[3px] rounded-r",
        data.severity === "critical" && "bg-cyber-critical",
        data.severity === "high" && "bg-cyber-high",
        data.severity === "medium" && "bg-cyber-medium",
        data.severity === "low" && "bg-cyber-low"
      )} />

      {/* Node Icon */}
      <div className={cn(
        "h-8 w-8 rounded flex items-center justify-center border shrink-0 ml-1",
        data.severity === "critical" && "bg-red-50 border-red-100 text-cyber-critical",
        data.severity === "high" && "bg-amber-50 border-amber-100 text-cyber-high",
        data.severity === "medium" && "bg-yellow-50 border-yellow-100 text-cyber-medium",
        data.severity === "low" && "bg-green-50 border-green-100 text-cyber-low"
      )}>
        {data.icon}
      </div>

      {/* Node details */}
      <div className="min-w-0 flex-1">
        <span className="text-[8px] font-mono text-slate-400 uppercase tracking-wider block leading-none">
          {data.subtitle}
        </span>
        <span className="text-[11px] font-bold font-sans text-slate-800 mt-1 block leading-none truncate">
          {data.label}
        </span>
      </div>

      {/* Source port connections */}
      {data.id !== "domain-admin" && (
        <Handle 
          type="source" 
          position={Position.Right} 
          style={{ background: "#2563eb", border: "1.5px solid #ffffff", width: 8, height: 8 }} 
        />
      )}

      {/* Dynamic Hover Tooltip Bubble */}
      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-3.5 w-52 p-2.5 rounded-md bg-slate-900 border border-slate-800 text-[10px] font-sans text-slate-200 leading-relaxed opacity-0 pointer-events-none group-hover:opacity-100 transition-opacity z-50 shadow-premium text-center">
        <span className="font-mono text-[8px] uppercase font-bold text-cyber-primary block mb-1">DETECTION OVERVIEW</span>
        {data.tooltip}
        <div className="absolute top-full left-1/2 -translate-x-1/2 border-4 border-transparent border-t-slate-900" />
      </div>
    </div>
  );
};

export function AttackGraphPage() {
  const navigate = useNavigate();

  // Custom components registration for React Flow
  const nodeTypes = useMemo(() => ({
    attackNode: CustomAttackNode
  }), []);

  // Attack sequence data mapping
  const initialNodesData: AttackNodeData[] = [
    {
      id: "weak-credentials",
      subtitle: "Initial Access",
      label: "Weak Credentials",
      severity: "high",
      icon: <Key className="h-4 w-4" />,
      tooltip: "External SSH login logged on web-prod-ubuntu-01 matching public dictionaries.",
      ip: "185.220.101.44 (WAN)",
      description: "Threat actor performed credential brute-forcing targeting active directory external accounts. Credentials matching administrative wordlists were successfully authenticated.",
      mitigations: [
        "Deploy Palo Alto IP firewall block",
        "Enforce active multi-factor verification",
        "Force domain credentials rollback"
      ]
    },
    {
      id: "privilege-escalation",
      subtitle: "Privilege Escalation",
      label: "Privilege Escalation",
      severity: "critical",
      icon: <Terminal className="h-4 w-4" />,
      tooltip: "Exploitation of CVE-2024-3094 to execute bash root shells on web-prod-ubuntu-01.",
      ip: "web-prod-ubuntu-01 (10.120.40.8)",
      description: "Attacker exploited a supply-chain backdoor (CVE-2024-3094) inside xz-utils compilation. Backdoor hooks enabled remote root terminal commands execution without security checks.",
      mitigations: [
        "Quarantine host web-prod-ubuntu-01",
        "Roll back library dependencies to 5.4.1",
        "Terminate active bash console processes"
      ]
    },
    {
      id: "credential-dumping",
      subtitle: "Credential Access",
      label: "Credential Dumping",
      severity: "critical",
      icon: <ShieldAlert className="h-4 w-4 animate-pulse" />,
      tooltip: "LSASS process memory read handles queried on ad-dc-windows-01 domain server.",
      ip: "ad-dc-windows-01 (10.120.40.2)",
      description: "Attacker executed administrative LSASS memory dumps on the Active Directory domain controller workstation. Process credentials retrieved to obtain domain keys.",
      mitigations: [
        "Enable LSA protection registry keys",
        "Invalidate DC Kerberos auth keys",
        "Quarantine host ad-dc-windows-01"
      ]
    },
    {
      id: "lateral-movement",
      subtitle: "Lateral Movement",
      label: "Lateral Movement",
      severity: "high",
      icon: <Network className="h-4 w-4" />,
      tooltip: "Secured RDP connections logged between web server groups and domain controller hosts.",
      ip: "VLAN-Segment (10.120.40.0/24)",
      description: "Attacker leveraged compromised credentials to establish internal RDP sessions from web production segments into domain management segments.",
      mitigations: [
        "Sever RDP session routes",
        "Enforce localized firewall segment blocks",
        "Trigger credentials rollbacks"
      ]
    },
    {
      id: "domain-admin",
      subtitle: "Exfiltration & Impact",
      label: "Domain Admin",
      severity: "critical",
      icon: <ShieldCheck className="h-4 w-4" />,
      tooltip: "Threat actor captures Domain Admin registry credentials. Full domain compromise imminent.",
      ip: "ad-dc-windows-01 (Active Directory Forest)",
      description: "Threat actor achieves full Domain Controller authorization, gaining unrestricted administrative read/write access controls over local directory assets.",
      mitigations: [
        "Execute disaster recovery schemas",
        "Trigger global SOC incident responses",
        "Invalidate active directory trust forest"
      ]
    }
  ];

  const [selectedNodeId, setSelectedNodeId] = useState<string>("privilege-escalation");

  // React Flow initial nodes setup
  const initialNodes = initialNodesData.map(node => ({
    id: node.id,
    type: "attackNode",
    data: node,
    position: 
      node.id === "weak-credentials" ? { x: 40, y: 150 } :
      node.id === "privilege-escalation" ? { x: 280, y: 150 } :
      node.id === "credential-dumping" ? { x: 520, y: 40 } :
      node.id === "lateral-movement" ? { x: 520, y: 260 } :
      { x: 760, y: 150 }
  }));

  // React Flow initial edges setup
  const initialEdges = [
    { 
      id: "e-weak-priv", 
      source: "weak-credentials", 
      target: "privilege-escalation", 
      animated: true,
      style: { stroke: "#f59e0b", strokeWidth: 2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#f59e0b" }
    },
    { 
      id: "e-priv-dump", 
      source: "privilege-escalation", 
      target: "credential-dumping", 
      animated: true,
      style: { stroke: "#ef4444", strokeWidth: 2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#ef4444" }
    },
    { 
      id: "e-priv-lat", 
      source: "privilege-escalation", 
      target: "lateral-movement", 
      animated: true,
      style: { stroke: "#f59e0b", strokeWidth: 2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#f59e0b" }
    },
    { 
      id: "e-dump-admin", 
      source: "credential-dumping", 
      target: "domain-admin", 
      animated: true,
      style: { stroke: "#ef4444", strokeWidth: 2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#ef4444" }
    },
    { 
      id: "e-lat-admin", 
      source: "lateral-movement", 
      target: "domain-admin", 
      animated: true,
      style: { stroke: "#ef4444", strokeWidth: 2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#ef4444" }
    }
  ];

  const [rfNodes, setRfNodes, onNodesChange] = useNodesState(initialNodes);
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Retrieve selected node context
  const selectedNode = useMemo(() => {
    return initialNodesData.find(n => n.id === selectedNodeId) || initialNodesData[1];
  }, [selectedNodeId]);

  const handleTriggerPlaybook = (mitigation: string) => {
    toast.success(`Action successfully initialized: "${mitigation}"`);
  };

  return (
    <div className="space-y-6 flex flex-col h-[calc(100vh-100px)]">
      {/* Page Header */}
      <div className="flex justify-between items-center border-b border-slate-200 pb-4 shrink-0">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 font-sans">
            Attack Path Analyst
          </h1>
          <p className="text-xs text-brand-secondary mt-1 font-sans">
            Visual attack path analysis mapping credential compromise, privilege escalation, and lateral containment gates.
          </p>
        </div>
        <div>
          <Button variant="ghost" size="icon" className="h-7 w-7 text-slate-400" onClick={() => navigate("/")}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
          <p className="text-[9px] font-mono font-semibold uppercase tracking-wider text-slate-400">Threat stages</p>
          <p className="mt-1 text-lg font-semibold text-slate-900">5 chained vectors</p>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
          <p className="text-[9px] font-mono font-semibold uppercase tracking-wider text-slate-400">Critical nodes</p>
          <p className="mt-1 text-lg font-semibold text-cyber-critical">3 elevated paths</p>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
          <p className="text-[9px] font-mono font-semibold uppercase tracking-wider text-slate-400">Containment readiness</p>
          <p className="mt-1 text-lg font-semibold text-cyber-low">92% prepared</p>
        </div>
      </div>

      {/* Split visualizer grids */}
      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6 flex-1 min-h-0 items-stretch">
        
        {/* React Flow Visualizer (3/4 width) */}
        <div className="xl:col-span-3 border border-slate-200 bg-white rounded-lg relative overflow-hidden flex flex-col min-h-[400px] shadow-card">
          {/* Subtle grid background overlay */}
          <div className="absolute inset-0 cyber-grid-overlay opacity-5 pointer-events-none z-0" />
          
          <div className="absolute top-3 left-3 z-10 flex items-center gap-2 bg-white/80 border border-slate-200 p-2 rounded shadow-sm select-none backdrop-blur-sm">
            <Flame className="h-4 w-4 text-cyber-critical animate-pulse" />
            <span className="text-[10px] font-mono font-bold text-slate-800 uppercase tracking-wider">LIVE PROPAGATION CHAIN</span>
          </div>

          {/* Interactive React Flow area */}
          <div className="flex-1 min-h-0 relative z-10 font-sans">
            <ReactFlow
              nodes={rfNodes}
              edges={rfEdges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              nodeTypes={nodeTypes}
              onNodeClick={(_, node) => setSelectedNodeId(node.id)}
              fitView
              zoomOnScroll
              zoomOnPinch
              panOnDrag
              attributionPosition="bottom-left"
            >
              <Background color="#cbd5e1" gap={20} size={1} />
              <Controls className="bg-white border border-slate-200 text-slate-500 rounded-md shadow-sm [&_button]:border-slate-100 [&_button]:bg-white [&_button]:text-slate-500 [&_button:hover]:bg-slate-50" />
              <MiniMap 
                nodeColor={(node) => {
                  const data = node.data as AttackNodeData;
                  if (data?.severity === "critical") return "#ef4444";
                  if (data?.severity === "high") return "#f59e0b";
                  return "#2563eb";
                }}
                maskColor="rgba(248, 250, 252, 0.7)"
                style={{ background: "#ffffff", border: "1px solid #e2e8f0", borderRadius: 6 }}
                className="border-slate-200"
              />
            </ReactFlow>
          </div>
        </div>

        {/* Floating Mitigation Console (1/4 width) */}
        <div className="xl:col-span-1 flex flex-col justify-between border border-slate-200 bg-white rounded-lg p-4.5 relative overflow-y-auto shadow-card">
          {/* Top border color matching selected node severity */}
          <div className={cn(
            "absolute top-0 left-0 right-0 h-[1.5px]",
            selectedNode.severity === "critical" && "bg-cyber-critical",
            selectedNode.severity === "high" && "bg-cyber-high"
          )} />

          <div className="space-y-4">
            {/* Header Section */}
            <div>
              <span className="font-mono text-[9px] uppercase tracking-wider text-slate-400 block">Threat Stage Inspector</span>
              <h3 className="text-sm font-bold font-sans text-slate-800 mt-1 leading-tight">{selectedNode.label}</h3>
              <div className="flex items-center gap-2 mt-2">
                <Badge severity={selectedNode.severity}>{selectedNode.severity}</Badge>
                <span className="font-mono text-[9px] text-slate-500 bg-slate-50 border border-slate-200 px-1.5 py-0.5 rounded truncate max-w-[130px]">
                  {selectedNode.ip}
                </span>
              </div>
            </div>

            {/* Description */}
            <div className="font-sans text-[11px] text-slate-600 bg-slate-50 border border-slate-200 p-3 rounded-md leading-relaxed">
              {selectedNode.description}
            </div>

            {/* Mitigations Playbook list */}
            <div className="space-y-2.5">
              <h4 className="text-[9px] font-mono font-bold tracking-wider text-slate-400 uppercase flex items-center gap-1.5">
                <CornerDownRight className="h-3.5 w-3.5 text-cyber-primary" /> Recommended Playbooks
              </h4>
              
              <div className="space-y-2">
                {selectedNode.mitigations.map((mit, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleTriggerPlaybook(mit)}
                    className="w-full text-left p-2.5 bg-slate-50/50 border border-slate-200 hover:border-brand-accent/40 rounded-md text-[10px] font-mono text-slate-600 hover:text-slate-900 hover:bg-slate-50 flex items-center justify-between transition-all cursor-pointer group shadow-sm"
                  >
                    <span className="truncate max-w-[170px]">{mit}</span>
                    <Sparkles className="h-3 w-3 text-slate-450 group-hover:text-brand-accent transition-colors" />
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Footer Triage action */}
          <div className="pt-4 border-t border-slate-100 mt-4 shrink-0">
            <Button
              variant="cyber"
              size="sm"
              className="w-full text-xs font-mono justify-center"
              onClick={() => navigate(`/copilot?query=mitigate+${selectedNodeId}`)}
            >
              <Compass className="mr-1.5 h-3.5 w-3.5" />
              DEPLOY MITIGATION WIZARD
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default AttackGraphPage;
