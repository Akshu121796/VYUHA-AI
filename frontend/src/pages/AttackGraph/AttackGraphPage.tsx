import React, { useState, useMemo, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import ReactFlow, {
  Background,
  Controls,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  NodeProps,
  MarkerType,
  ReactFlowProvider,
  useReactFlow
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
  Compass,
  Monitor,
  FileUp
} from "lucide-react";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { cn } from "../../utils/cn";
import { toast } from "sonner";
import { useAttackGraphData, useIncidentsData } from "../../hooks/queries/useVyuhaQueries";
import dagre from "dagre";
import { attackGraphService } from "../../services/attackGraphService";
import { apiClient } from "../../services/apiClient";

// Intercept graph nodes API calls to prevent loading stale DB graphs when 0 paths generated or session is empty
const originalGetGraphNodes = attackGraphService.getGraphNodes;
attackGraphService.getGraphNodes = async () => {
  const hasActiveSession = sessionStorage.getItem("importedAt") !== null;
  const attackPathsGeneratedStr = sessionStorage.getItem("attackPathsGenerated");
  const attackPathsGenerated = attackPathsGeneratedStr !== null ? parseInt(attackPathsGeneratedStr, 10) : 0;
  const scanId = sessionStorage.getItem("scanId");

  if (!hasActiveSession || attackPathsGenerated <= 0) {
    return { nodes: [], edges: [], chains: [] };
  }

  if (scanId) {
    const res = await apiClient.get(`/attack-paths?scanId=${scanId}`);
    return res.data;
  }

  return originalGetGraphNodes();
};


// Node Interface details
interface AttackNodeData {
  id: string;
  subtitle: string;
  label: string;
  severity: "critical" | "high" | "medium" | "low";
  icon: string;
  ip: string;
  description: string;
  findingsCount: number;
  opacity: number;
  cves: string[];
  tactics: string[];
  isInSelectedChain: boolean;
  isNodeSelected: boolean;
  isHighlighted: boolean;
}

// Icon mapping registry for backend-driven serialization keys
const ICON_MAP: Record<string, React.ReactNode> = {
  "key": <Key className="h-3.5 w-3.5" />,
  "terminal": <Terminal className="h-3.5 w-3.5" />,
  "shield-alert": <ShieldAlert className="h-3.5 w-3.5" />,
  "network": <Network className="h-3.5 w-3.5" />,
  "shield-check": <ShieldCheck className="h-3.5 w-3.5" />
};

// Helper to resolve icon key based on asset type
function getIconForAsset(type: string): string {
  const t = type.toLowerCase();
  if (t.includes("web") || t.includes("portal")) return "terminal";
  if (t.includes("db") || t.includes("postgres") || t.includes("database") || t.includes("mysql") || t.includes("sql")) return "shield-alert";
  if (t.includes("domain") || t.includes("controller") || t.includes("admin")) return "shield-check";
  if (t.includes("app") || t.includes("application") || t.includes("auth")) return "network";
  return "key";
}

// Custom React Flow Node Component (Dark, Compact, hover tooltip enabled)
const CustomAttackNode = ({ data }: NodeProps<AttackNodeData>) => {
  const renderIcon = () => {
    return ICON_MAP[data.icon] || <ShieldAlert className="h-3.5 w-3.5" />;
  };

  const isInChain = data.isInSelectedChain;
  const isSelected = data.isNodeSelected;
  const isHighlighted = data.isHighlighted;

  return (
    <div 
      style={{ opacity: isHighlighted ? 1.0 : 0.25 }}
      className={cn(
        "px-3 py-2.5 rounded-lg border text-left min-w-[210px] w-auto select-none group relative transition-all shadow-md cursor-pointer",
        "bg-slate-900",
        isHighlighted
          ? (isInChain 
              ? "border-red-500 shadow-[0_0_12px_rgba(239,68,68,0.25)]" 
              : "border-blue-500/70 shadow-[0_0_12px_rgba(59,130,246,0.15)]")
          : "border-slate-800",
        isSelected && "ring-2 ring-blue-400 ring-offset-2 ring-offset-slate-950"
      )}
    >
      <Handle 
        type="target" 
        position={Position.Left} 
        style={{ background: isInChain ? "#ef4444" : "#3b82f6", border: "1.5px solid #0f172a", width: 7, height: 7 }} 
      />

      <div className="flex items-center space-x-2.5">
        {/* Pulsing indicator dot */}
        <span className={cn(
          "h-2 w-2 rounded-full shrink-0",
          isInChain ? "bg-red-500 animate-pulse" : "bg-blue-400"
        )} />

        {/* Node details */}
        <div className="min-w-0 flex-1">
          <span className="text-[11px] font-bold text-slate-100 block leading-tight truncate">
            {data.label}
          </span>
          <span className="text-[8.5px] font-mono text-slate-400 block mt-0.5 leading-none truncate">
            {data.subtitle}
          </span>
        </div>

        {/* Findings Badge */}
        <div className={cn(
          "px-1.5 py-0.5 rounded text-[9.5px] font-bold font-mono shrink-0",
          isInChain ? "bg-red-500/10 text-red-400 border border-red-500/20" : "bg-slate-800 text-slate-300 border border-slate-700"
        )}>
          {data.findingsCount}
        </div>
      </div>

      <Handle 
        type="source" 
        position={Position.Right} 
        style={{ background: isInChain ? "#ef4444" : "#3b82f6", border: "1.5px solid #0f172a", width: 7, height: 7 }} 
      />

      {/* Rich Hover Tooltip */}
      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-3.5 w-64 p-3 rounded-lg bg-slate-950 border border-slate-800 text-[10px] text-slate-200 leading-normal opacity-0 pointer-events-none group-hover:opacity-100 transition-opacity z-50 shadow-premium">
        <div className="border-b border-slate-800 pb-1.5 mb-1.5 flex justify-between items-center">
          <span className="font-mono text-[8px] uppercase font-bold text-blue-400">DEVICE SCAN DATA</span>
          <span className="text-[8px] font-mono text-slate-400">{data.ip}</span>
        </div>
        
        <div className="space-y-1.5 font-sans text-left">
          <p><strong className="text-slate-455 font-mono text-[9px]">Device Name:</strong> <span className="text-slate-100 font-semibold">{data.label}</span></p>
          <p><strong className="text-slate-455 font-mono text-[9px]">Type:</strong> {data.subtitle}</p>
          <p><strong className="text-slate-455 font-mono text-[9px]">Severity:</strong> <span className={cn(
            "uppercase font-semibold",
            data.severity === "critical" && "text-red-400",
            data.severity === "high" && "text-orange-400",
            data.severity === "medium" && "text-yellow-400",
            data.severity === "low" && "text-green-400"
          )}>{data.severity}</span></p>
          <p><strong className="text-slate-455 font-mono text-[9px]">Open Security Issues:</strong> {data.findingsCount}</p>
          
          {data.cves && data.cves.length > 0 && (
            <div className="pt-1 border-t border-slate-900 mt-1">
              <strong className="text-slate-455 font-mono text-[8.5px] block mb-1">
                CVEs <span className="inline-flex items-center justify-center cursor-help text-blue-500 hover:text-blue-400 dark:text-blue-400 dark:hover:text-blue-300 font-bold ml-1.5 text-[13px] select-none transition-colors align-middle" title="A publicly known software security weakness.">ⓘ</span>:
              </strong>
              <div className="flex flex-wrap gap-1 max-h-16 overflow-y-auto">
                {data.cves.map((cve: string, idx: number) => (
                  <span key={idx} className="text-[8px] font-mono bg-red-950/40 text-red-300 border border-red-900/30 px-1 rounded">
                    {cve}
                  </span>
                ))}
              </div>
            </div>
          )}

          {data.tactics && data.tactics.length > 0 && (
            <div className="pt-1 border-t border-slate-900 mt-1">
              <strong className="text-slate-455 font-mono text-[8.5px] block mb-1">
                Attack Methods <span className="inline-flex items-center justify-center cursor-help text-blue-500 hover:text-blue-400 dark:text-blue-400 dark:hover:text-blue-300 font-bold ml-1.5 text-[13px] select-none transition-colors align-middle" title="An industry framework describing common attacker methods.">ⓘ</span>:
              </strong>
              <div className="flex flex-wrap gap-1 max-h-16 overflow-y-auto">
                {data.tactics.map((tactic: string, idx: number) => (
                  <span key={idx} className="text-[8px] font-mono bg-blue-950/40 text-blue-300 border border-blue-900/30 px-1 rounded">
                    {tactic}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
        <div className="absolute top-full left-1/2 -translate-x-1/2 border-4 border-transparent border-t-slate-950" />
      </div>
    </div>
  );
};

// Dagre layout function for automatic placement in LR hierarchy
const dagreLayout = async (nodes: any[], edges: any[]) => {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  const isLargeGraph = nodes.length > 15;
  const nodeWidth = 220;
  const nodeHeight = 60;
  
  // Custom horizontal/vertical spacing
  const ranksep = isLargeGraph ? 220 : 150; // horizontal spacing between layers
  const nodesep = isLargeGraph ? 95 : 60;   // vertical spacing between sibling nodes

  dagreGraph.setGraph({
    rankdir: "LR", // left-to-right hierarchical layout
    ranksep,
    nodesep,
    marginx: 50,
    marginy: 50
  });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: nodeWidth, height: nodeHeight });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  try {
    dagre.layout(dagreGraph);
    return nodes.map((node) => {
      const nodeWithPosition = dagreGraph.node(node.id);
      return {
        ...node,
        position: {
          x: nodeWithPosition.x - nodeWidth / 2,
          y: nodeWithPosition.y - nodeHeight / 2
        }
      };
    });
  } catch (err) {
    console.error("Dagre layout failed", err);
    return nodes.map((node, idx) => ({
      ...node,
      position: {
        x: idx * 250,
        y: 100
      }
    }));
  }
};

// React Flow Canvas Wrapper Component
interface CanvasProps {
  rfNodes: any[];
  rfEdges: any[];
  onNodesChange: any;
  onEdgesChange: any;
  nodeTypes: any;
  handleNodeClick: (id: string) => void;
  handleEdgeClick: (edge: any) => void;
}

function AttackGraphCanvas({
  rfNodes,
  rfEdges,
  onNodesChange,
  onEdgesChange,
  nodeTypes,
  handleNodeClick,
  handleEdgeClick
}: CanvasProps) {
  const { fitView } = useReactFlow();

  // Automatically adapt viewport scale when nodes refresh or selection changes
  useEffect(() => {
    if (rfNodes.length > 0) {
      const timer = setTimeout(() => {
        const highlightedNodes = rfNodes.filter(n => n.data.isHighlighted);
        if (highlightedNodes.length > 0 && highlightedNodes.length < rfNodes.length) {
          fitView({ nodes: highlightedNodes, padding: 0.3, duration: 400 });
        } else {
          fitView({ padding: 0.2, duration: 400 });
        }
      }, 80);
      return () => clearTimeout(timer);
    }
  }, [rfNodes, fitView]);

  return (
    <ReactFlow
      nodes={rfNodes}
      edges={rfEdges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      nodeTypes={nodeTypes}
      onNodeClick={(_, node) => handleNodeClick(node.id)}
      onEdgeClick={(_, edge) => handleEdgeClick(edge)}
      zoomOnScroll
      zoomOnPinch
      panOnDrag
      fitView
      attributionPosition="bottom-left"
    >
      <Background color="#1e293b" gap={20} size={1} />
      <Controls className="bg-slate-900 border border-slate-800 text-slate-400 rounded-md shadow-md [&_button]:border-slate-800 [&_button]:bg-slate-900 [&_button]:text-slate-400 [&_button:hover]:bg-slate-800" />
    </ReactFlow>
  );
}

export function AttackGraphPage() {
  const navigate = useNavigate();
  const hasActiveSession = sessionStorage.getItem("importedAt") !== null;
  const scanId = sessionStorage.getItem("scanId");
  const findingsImportedStr = sessionStorage.getItem("findingsImported");
  const findingsImported = findingsImportedStr !== null ? parseInt(findingsImportedStr, 10) : 0;
  const attackPathsGeneratedStr = sessionStorage.getItem("attackPathsGenerated");
  const attackPathsGenerated = attackPathsGeneratedStr !== null ? parseInt(attackPathsGeneratedStr, 10) : 0;
  const detectedScanType = sessionStorage.getItem("detectedScanType") || "Unknown";
  const importedAt = sessionStorage.getItem("importedAt");

  let fileName = "";
  let assetsDiscovered = 0;
  let importedTimeStr = "";
  const savedScan = sessionStorage.getItem("vyuha_imported_scan");
  if (savedScan) {
    try {
      const parsed = JSON.parse(savedScan);
      fileName = parsed.fileName || "";
      assetsDiscovered = parsed.assetsDiscovered || 0;
      importedTimeStr = parsed.importedTime || "";
    } catch (e) {
      console.error(e);
    }
  }

  const displayImportedTime = importedTimeStr || (importedAt ? new Date(importedAt).toLocaleString() : "");
  const isEmptyState = !hasActiveSession || attackPathsGenerated <= 0;


  const { data: responseData, isLoading } = useAttackGraphData();
  const { data: incidentsData } = useIncidentsData();

  const nodeTypes = useMemo(() => ({
    attackNode: CustomAttackNode
  }), []);

  const [selectedChainId, setSelectedChainId] = useState<string>("all");
  const [selectedNodeId, setSelectedNodeId] = useState<string>("all");
  const [devMode, setDevMode] = useState<boolean>(false);
  const [selectedEdge, setSelectedEdge] = useState<any>(null);

  const [rfNodes, setRfNodes, onNodesChange] = useNodesState([]);
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState([]);

  const mapChain = (c: any) => {
    const mapTacticStr = (t: string) => {
      if (t === "Credential Access") return "Credential Theft";
      if (t === "Initial Access") return "Initial Entry";
      if (t === "Privilege Escalation") return "Elevated Access";
      if (t === "Lateral Movement") return "Moving Between Devices";
      if (t === "Defense Evasion") return "Avoiding Detection";
      if (t === "Persistence") return "Staying Inside Network";
      if (t === "Discovery") return "Network Discovery";
      if (t === "Execution") return "Code Execution";
      if (t === "Collection") return "Data Collection";
      if (t === "Exfiltration") return "Data Theft";
      return t;
    };

    return {
      ...c,
      patternName: (c.patternName || "")
        .replace("Attack Chain:", "Attack Sequence:")
        .replace("Web Exploit Chain:", "Web Exploit Sequence:")
        .replace("Service Exposure Chain:", "Service Exposure Sequence:")
        .replace("Lateral Pivot Chain:", "Lateral Pivot Sequence:")
        .replace("Lateral Movement", "Moving Between Devices"),
      description: (c.description || "")
        .replace("entry point", "starting device")
        .replace("targets", "targets device")
        .replace("vulnerability", "weakness")
        .replace("vulnerabilities", "weaknesses"),
      remediations: (c.remediations || []).map((r: string) => {
        return r.replace("vulnerabilities", "weaknesses").replace("vulnerability", "weakness").replace("assets", "devices").replace("asset", "device");
      }),
      path: (c.path || []).map((p: any) => ({
        ...p,
        assetType: p.assetType ? p.assetType.replace("Server", "Device") : "Device",
        tactics: (p.tactics || []).map(mapTacticStr)
      }))
    };
  };

  // Safely extract chains and edges from custom backend layout wrapper
  const chains = useMemo(() => {
    let list = responseData?.chains || [];
    if (hasActiveSession && scanId) {
      list = list.filter((c: any) => c.scanId === scanId);
    }
    return list.map(mapChain);
  }, [responseData, hasActiveSession, scanId]);

  // Union list of unique assets across all threat vectors
  const uniqueAssetsList = useMemo(() => {
    const rawNodes = responseData?.nodes || [];
    const mapTacticStr = (t: string) => {
      if (t === "Credential Access") return "Credential Theft";
      if (t === "Initial Access") return "Initial Entry";
      if (t === "Privilege Escalation") return "Elevated Access";
      if (t === "Lateral Movement") return "Moving Between Devices";
      if (t === "Defense Evasion") return "Avoiding Detection";
      if (t === "Persistence") return "Staying Inside Network";
      if (t === "Discovery") return "Network Discovery";
      if (t === "Execution") return "Code Execution";
      if (t === "Collection") return "Data Collection";
      if (t === "Exfiltration") return "Data Theft";
      return t;
    };

    let filtered = rawNodes;
    if (hasActiveSession && scanId) {
      const activeAssetIds = new Set<string>();
      activeAssetIds.add("internet-node");
      chains.forEach((c: any) => {
        c.path?.forEach((p: any) => {
          if (p.id) activeAssetIds.add(p.id);
        });
      });
      filtered = rawNodes.filter((node: any) => activeAssetIds.has(node.id));
    }

    return filtered.map((node: any) => ({
      ...node,
      assetType: node.assetType ? node.assetType.replace("Server", "Device") : "Device",
      tactics: (node.tactics || []).map(mapTacticStr)
    }));
  }, [responseData, chains, hasActiveSession, scanId]);

  const backendEdges = useMemo(() => {
    const rawEdges = responseData?.edges || [];
    if (hasActiveSession && scanId) {
      const activeAssetIds = new Set<string>();
      activeAssetIds.add("internet-node");
      chains.forEach((c: any) => {
        c.path?.forEach((p: any) => {
          if (p.id) activeAssetIds.add(p.id);
        });
      });
      return rawEdges.filter((edge: any) => activeAssetIds.has(edge.source) && activeAssetIds.has(edge.target));
    }
    return rawEdges;
  }, [responseData, chains, hasActiveSession, scanId]);

  useEffect(() => {
    if (chains.length > 0 && selectedChainId === "all") {
      const saved = sessionStorage.getItem("vyuha_imported_scan");
      if (saved) {
        try {
          const parsed = JSON.parse(saved);
          if (parsed && parsed.scanId) {
            const matched = chains.find((c: any) => c.scanId === parsed.scanId);
            if (matched) {
              setSelectedChainId(matched.id);
            }
          }
        } catch (e) {
          console.error(e);
        }
      }
    }
  }, [chains, selectedChainId]);

  // Sync nodes and edges on change in findings/selection states
  useEffect(() => {
    if (!responseData || !responseData.nodes || responseData.nodes.length === 0) return;

    const activeChain = selectedChainId === "all" ? null : chains.find((c: any) => c.id === selectedChainId);

    // Track neighbor sets for node-selection highlighting
    const neighbors = new Set<string>();
    const connectingEdges = new Set<string>();

    const targetNodeId = selectedNodeId === "all" ? "" : selectedNodeId;

    // Map React Flow nodes
    const rawNodes = uniqueAssetsList.map((asset: any) => {
      const isInChain = activeChain 
        ? activeChain.path.some((n: any) => n.id === asset.id) 
        : asset.isInAttackChain;
      
      // Determine dynamic highlighting flags
      const isNodeSelected = targetNodeId === asset.id;
      let isNeighbor = false;

      backendEdges.forEach((edge: any) => {
        if (targetNodeId) {
          if (edge.source === targetNodeId && edge.target === asset.id) {
            isNeighbor = true;
            connectingEdges.add(`edge-${edge.source}-${edge.target}`);
          }
          if (edge.target === targetNodeId && edge.source === asset.id) {
            isNeighbor = true;
            connectingEdges.add(`edge-${edge.source}-${edge.target}`);
          }
        }
      });

      let isHighlighted = true;
      if (targetNodeId) {
        isHighlighted = isNodeSelected || isNeighbor;
      } else if (activeChain) {
        isHighlighted = isInChain;
      }

      return {
        id: asset.id,
        type: "attackNode",
        data: {
          id: asset.id,
          subtitle: asset.assetType,
          label: asset.assetName,
          severity: asset.severity || "medium",
          findingsCount: asset.findings || 0,
          ip: asset.ip || "0.0.0.0",
          description: asset.description || `Active scan data security issues on ${asset.assetName}.`,
          cves: asset.cves || [],
          tactics: asset.tactics || [],
          isInSelectedChain: isInChain,
          isNodeSelected,
          isHighlighted
        },
        position: { x: 0, y: 0 }
      };
    });

    // Build unique edges from inferred backend edges list to reuse common edges
    const uniqueEdgesMap = new Map<string, any>();
    backendEdges.forEach((edge: any) => {
      const edgeId = `edge-${edge.source}-${edge.target}`;
      if (!uniqueEdgesMap.has(edgeId)) {
        const isSelectedChain = activeChain 
          ? activeChain.path.some((n: any) => n.id === edge.source) && activeChain.path.some((n: any) => n.id === edge.target)
          : chains.some((c: any) => c.path.some((n: any) => n.id === edge.source) && c.path.some((n: any) => n.id === edge.target));
        
        const targetNode = uniqueAssetsList.find((n: any) => n.id === edge.target);
        const strokeColor = isSelectedChain 
          ? (targetNode?.severity === "critical" ? "#ef4444" : "#f59e0b") 
          : "#4a5a80";
        
        let edgeOpacity = 0.8;
        if (targetNodeId) {
          edgeOpacity = (edge.source === targetNodeId || edge.target === targetNodeId) ? 1.0 : 0.15;
        } else if (activeChain) {
          edgeOpacity = isSelectedChain ? 1.0 : 0.15;
        }

        uniqueEdgesMap.set(edgeId, {
          id: edgeId,
          source: edge.source,
          target: edge.target,
          animated: activeChain ? isSelectedChain : false,
          style: { 
            stroke: strokeColor, 
            strokeWidth: isSelectedChain ? 2.5 : 1.5,
            opacity: edgeOpacity
          },
          markerEnd: { 
            type: MarkerType.ArrowClosed, 
            color: strokeColor,
            width: 16,
            height: 16
          },
          data: {
            reason: edge.reason,
            rule: edge.rule,
            cves: edge.cves || [],
            findings: edge.findings || []
          }
        });
      }
    });
    const edges = Array.from(uniqueEdgesMap.values());

    let active = true;
    dagreLayout(rawNodes, edges).then((layoutedNodes) => {
      if (active) {
        setRfNodes(layoutedNodes);
        setRfEdges(edges);
      }
    });

    return () => {
      active = false;
    };
  }, [chains, backendEdges, selectedChainId, selectedNodeId, uniqueAssetsList, responseData, setRfNodes, setRfEdges]);

  // Aggregate selected threat vector details for inspector panel
  const selectedChain = useMemo(() => {
    if (!chains || !Array.isArray(chains) || chains.length === 0) {
      return {
        id: "none",
        patternName: "No Threat Vector",
        severity: "Low",
        likelihood: "Low",
        businessImpact: "Low",
        description: "No attack paths could be inferred from the current scan.",
        mitreTechniques: [],
        path: [],
        remediations: []
      };
    }
    
    if (selectedChainId === "all") {
      const allMitre = new Set<string>();
      const allRemediations = new Set<string>();
      
      chains.forEach((c: any) => {
        c.mitreTechniques?.forEach((t: string) => allMitre.add(t));
        c.remediations?.forEach((r: string) => allRemediations.add(r));
      });

      return {
        id: "all",
        patternName: "All Threat Vectors",
        severity: "High",
        likelihood: "High",
        businessImpact: "Critical",
        description: "Composite visual map containing all dynamically inferred attack paths and vulnerability dependencies across live assets.",
        mitreTechniques: Array.from(allMitre),
        path: uniqueAssetsList.filter((a: any) => a.isInAttackChain).map((a: any) => ({ assetName: a.assetName })),
        remediations: Array.from(allRemediations).slice(0, 5)
      };
    }

    return chains.find((c: any) => c.id === selectedChainId) || chains[0];
  }, [chains, selectedChainId, uniqueAssetsList]);

  const handleNodeClick = (nodeId: string) => {
    setSelectedNodeId((prev) => (prev === nodeId ? "all" : nodeId));
    // Auto-select first matching chain containing the node to align details
    if (chains && selectedNodeId !== nodeId) {
      const matched = chains.find((c: any) => c.path.some((n: any) => n.id === nodeId));
      if (matched) {
        setSelectedChainId(matched.id);
      }
    }
    setSelectedEdge(null);
  };

  const handleEdgeClick = (edge: any) => {
    if (devMode) {
      setSelectedEdge(edge);
    }
  };

  const handleTriggerPlaybook = (mitigation: string) => {
    toast.success(`Action successfully initialized: "${mitigation}"`);
  };

  // Metric Computations
  const threatStagesVal = useMemo(() => {
    const total = chains?.length || 0;
    return `${total} detected vector${total === 1 ? "" : "s"}`;
  }, [chains]);

  const criticalNodesVal = useMemo(() => {
    const criticalCount = uniqueAssetsList.filter((a: any) => a.severity.toLowerCase() === "critical").length;
    return `${criticalCount} critical node${criticalCount === 1 ? "" : "s"}`;
  }, [uniqueAssetsList]);

  const containmentReadinessVal = useMemo(() => {
    if (!incidentsData || incidentsData.length === 0) return "100% prepared";
    const total = incidentsData.length;
    const mitigated = incidentsData.filter((i: any) => i.status === "resolved" || i.status === "suppressed" || i.status === "mitigated").length;
    const percentage = Math.round((mitigated / total) * 100);
    return `${percentage}% prepared`;
  }, [incidentsData]);

  if (!isEmptyState && (isLoading || !responseData)) {
    return (
      <div className="space-y-6 flex flex-col h-[calc(100vh-100px)] justify-center items-center font-mono">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyber-primary" />
        <p className="text-xs text-slate-400 mt-3">Loading dynamic attack routes...</p>
      </div>
    );
  }

  if (!isEmptyState && chains.length === 0) {
    return (
      <div className="space-y-6 flex flex-col h-[calc(100vh-100px)] justify-center items-center font-mono text-center">
        <p className="text-sm text-slate-400 font-sans">No attack routes were found in the network.</p>
        <Button variant="ghost" size="sm" onClick={() => navigate("/")} className="mt-2 text-xs">
          Return to Dashboard
        </Button>
      </div>
    );
  }

  if (!selectedChain) return null;

  return (
    <div className="space-y-5 flex flex-col h-[calc(100vh-100px)] overflow-hidden">
      {/* Header */}
      <div className="flex justify-between items-center border-b border-slate-200 pb-3 shrink-0 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-slate-900 font-sans dark:text-slate-100">
              {hasActiveSession && fileName ? `Attack Routes • ${fileName}` : "Attack Routes"}
            </h1>
            {hasActiveSession && (
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[8px] font-bold tracking-wider bg-cyber-primary/10 text-cyber-primary border border-cyber-primary/20 uppercase">
                ACTIVE INVESTIGATION
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 mt-0.5 font-sans dark:text-slate-400">
            Visual attack route analysis mapping credential theft, elevated access, and protection status.
          </p>
        </div>
        <div>
          <Button variant="ghost" size="icon" className="h-7 w-7 text-slate-400" onClick={() => navigate("/")}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {!hasActiveSession ? (
        <div className="flex-1 flex flex-col items-center justify-center text-center p-8 bg-slate-900 border border-slate-800 rounded-2xl my-auto">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-slate-800 text-slate-400 border border-slate-700 mb-4">
            <ShieldAlert className="h-6 w-6 text-cyber-primary animate-pulse" />
          </div>
          <h3 className="text-base font-bold text-slate-200">
            No active investigation.
          </h3>
          <p className="text-xs text-slate-400 mt-1 max-w-sm">
            Import a security scan to trace weakness pathways and propagation maps.
          </p>
          <Button 
            onClick={() => navigate("/scan-import")} 
            className="mt-4 gap-2 font-semibold bg-cyber-primary text-white"
          >
            <FileUp className="h-4 w-4" />
            Import Security Scan
          </Button>
        </div>
      ) : (
        <>
          {/* Active Investigation Context Header */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 flex flex-col md:flex-row md:items-center md:justify-between gap-3 shrink-0">
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyber-primary/10 text-cyber-primary border border-cyber-primary/20 shrink-0">
                <Network className="h-4.5 w-4.5" />
              </div>
              <div>
                <span className="text-[9px] font-mono text-slate-500 uppercase tracking-wider block leading-none">Current Scan</span>
                <span className="text-xs font-semibold text-slate-200 mt-0.5 block truncate max-w-[200px]" title={fileName}>
                  {fileName || "Unnamed Scan"}
                </span>
              </div>
            </div>
            
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 md:gap-6 border-t md:border-t-0 md:border-l border-slate-800 pt-2 md:pt-0 md:pl-6 flex-1">
              <div>
                <span className="text-[9px] font-mono text-slate-500 block uppercase leading-none">Scan Type</span>
                <span className="text-[11px] font-semibold text-slate-300 font-mono mt-0.5 block">{detectedScanType}</span>
              </div>
              <div>
                <span className="text-[9px] font-mono text-slate-500 block uppercase leading-none">Imported Time</span>
                <span className="text-[11px] font-semibold text-slate-350 mt-0.5 block">{displayImportedTime}</span>
              </div>
              <div>
                <span className="text-[9px] font-mono text-slate-500 block uppercase leading-none">Devices</span>
                <span className="text-[11px] font-semibold text-slate-350 font-mono mt-0.5 block">{assetsDiscovered}</span>
              </div>
              <div>
                <span className="text-[9px] font-mono text-slate-500 block uppercase leading-none">Security Issues</span>
                <span className="text-[11px] font-semibold text-slate-350 font-mono mt-0.5 block">{findingsImported}</span>
              </div>
              <div>
                <span className="text-[9px] font-mono text-slate-500 block uppercase leading-none">Attack Routes</span>
                <span className="text-[11px] font-semibold text-slate-350 font-mono mt-0.5 block">{attackPathsGenerated}</span>
              </div>
            </div>
          </div>

          {/* Metrics Row */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 shrink-0">
            <div className="rounded-xl border border-slate-200 bg-white p-3 shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <p className="text-[9px] font-mono font-semibold uppercase tracking-wider text-slate-400">Attack Routes Found</p>
              <p className="mt-0.5 text-lg font-semibold text-slate-900 dark:text-slate-100">{threatStagesVal}</p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-3 shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <p className="text-[9px] font-mono font-semibold uppercase tracking-wider text-slate-400">High-Risk Devices</p>
              <p className="mt-0.5 text-lg font-semibold text-cyber-critical">{criticalNodesVal}</p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-3 shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <p className="text-[9px] font-mono font-semibold uppercase tracking-wider text-slate-400">Protection Status</p>
              <p className="mt-0.5 text-lg font-semibold text-cyber-low">{containmentReadinessVal}</p>
            </div>
          </div>


      {/* Primary Split container */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 flex-1 min-h-0 items-stretch">
               {/* Visualizer Canvas Area (75% width) */}
        <div className="xl:col-span-9 border border-slate-200 bg-slate-950 rounded-xl relative overflow-hidden flex flex-col min-h-[450px] shadow-card dark:border-slate-850">
          <div className="absolute top-3 left-3 z-10 flex items-center gap-2 bg-slate-900 border border-slate-800 p-2 rounded-lg shadow-md select-none">
            <Flame className="h-4 w-4 text-cyber-critical animate-pulse" />
            <span className="text-[10px] font-mono font-bold text-slate-100 uppercase tracking-wider">Attack Flow</span>
          </div>
 
          {/* Selector dropdown */}
          {!isEmptyState && (
            <div className="absolute top-3 right-3 z-10 flex items-center gap-2 bg-slate-900 border border-slate-800 p-1.5 px-3 rounded-lg shadow-md select-none">
              <Sparkles className="h-3.5 w-3.5 text-blue-400" />
              <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">Attack Route:</span>
              <select
                value={selectedChainId}
                onChange={(e) => {
                  setSelectedChainId(e.target.value);
                  setSelectedNodeId("all");
                  setSelectedEdge(null);
                }}
                className="text-[10px] font-sans bg-transparent border-none outline-none font-semibold text-slate-100 cursor-pointer focus:ring-0"
              >
                <option value="all" className="bg-slate-900 text-slate-100">Show All Attack Routes</option>
                {chains.map((c: any) => (
                  <option key={c.id} value={c.id} className="bg-slate-900 text-slate-100">
                    {c.patternName} ({c.severity})
                  </option>
                ))}
              </select>
            </div>
          )}
 
          {isEmptyState ? (
            <div className="flex-1 flex flex-col items-center justify-center text-center p-8 bg-slate-950">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-slate-900 text-slate-400 border border-slate-800 mb-4 animate-pulse">
                <Network className="h-6 w-6" />
              </div>
              <p className="text-sm font-semibold text-slate-200">
                No attack routes could be inferred from the current scan.
              </p>
            </div>
          ) : (
            <div className="flex-1 min-h-0 relative">
              <ReactFlowProvider>
                <AttackGraphCanvas
                  rfNodes={rfNodes}
                  rfEdges={rfEdges}
                  onNodesChange={onNodesChange}
                  onEdgesChange={onEdgesChange}
                  nodeTypes={nodeTypes}
                  handleNodeClick={handleNodeClick}
                  handleEdgeClick={handleEdgeClick}
                />
              </ReactFlowProvider>
            </div>
          )}

          {/* Developer Debug Edge Inspector floating box */}
          {devMode && selectedEdge && (
            <div className="absolute bottom-4 left-4 z-20 bg-slate-900 border border-slate-850 p-4 rounded-xl shadow-premium text-xs text-slate-300 md:w-[380px] select-none text-left">
              <div className="flex justify-between items-center border-b border-slate-800 pb-2 mb-2">
                <span className="font-mono font-bold text-blue-400 uppercase tracking-wider text-[9.5px]">Edge Justification Analysis</span>
                <button 
                  onClick={() => setSelectedEdge(null)} 
                  className="text-slate-500 hover:text-slate-200 text-base font-bold leading-none cursor-pointer"
                >
                  ×
                </button>
              </div>
              <div className="space-y-2 font-sans">
                <p>
                  <strong className="text-slate-450 font-mono text-[9px] uppercase tracking-wider block">Source Node:</strong> 
                  <span className="text-slate-100 font-semibold">{rfNodes.find(n => n.id === selectedEdge.source)?.data.label || selectedEdge.source}</span>
                </p>
                <p>
                  <strong className="text-slate-450 font-mono text-[9px] uppercase tracking-wider block">Destination Node:</strong> 
                  <span className="text-slate-100 font-semibold">{rfNodes.find(n => n.id === selectedEdge.target)?.data.label || selectedEdge.target}</span>
                </p>
                <p>
                  <strong className="text-slate-455 font-mono text-[9px] uppercase tracking-wider block">Inference Rule Used:</strong> 
                  <span className="text-blue-300 font-semibold">{selectedEdge.data?.rule || "Generic Lateral Pivot"}</span>
                </p>
                <p>
                  <strong className="text-slate-455 font-mono text-[9px] uppercase tracking-wider block">Evidence Reason:</strong> 
                  <span className="text-slate-250 leading-relaxed block bg-slate-950/40 p-2 border border-slate-850 rounded-md mt-0.5 break-words">
                    {selectedEdge.data?.reason}
                  </span>
                </p>
                
                {selectedEdge.data?.cves && selectedEdge.data.cves.length > 0 && (
                  <div className="pt-1">
                    <strong className="text-slate-450 font-mono text-[9px] uppercase tracking-wider block mb-1">CVEs Involved:</strong>
                    <div className="flex flex-wrap gap-1 max-h-14 overflow-y-auto">
                      {selectedEdge.data.cves.map((cve: string, idx: number) => (
                        <span key={idx} className="text-[8.5px] font-mono bg-red-950/40 text-red-300 border border-red-900/30 px-1.5 py-0.5 rounded">
                          {cve}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>        {/* Dynamic Inspector Panel (25% width, scrolling enabled, overflow safe) */}
        <div className="xl:col-span-3 flex flex-col justify-between border border-slate-200 bg-slate-905 rounded-xl p-4.5 relative overflow-hidden h-full shadow-card dark:border-slate-800 dark:bg-slate-950 w-full min-w-0">
          <div className={cn(
            "absolute top-0 left-0 right-0 h-[2px]",
            selectedChain.severity.toLowerCase() === "critical" ? "bg-cyber-critical" : "bg-cyber-high"
          )} />

          <div className="flex-1 overflow-y-auto pr-1 space-y-5 max-h-[calc(100vh-180px)] w-full min-w-0">
            {/* Header info */}
            <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-850 bg-slate-50 dark:bg-slate-900/40 w-full">
              <span className="font-mono text-[9px] uppercase tracking-wider text-slate-400 block font-semibold">Selected Attack Details</span>
              <h3 className="text-[13px] font-bold font-sans text-slate-800 dark:text-slate-100 mt-1 leading-snug break-words whitespace-normal w-full">
                {selectedChain.patternName}
              </h3>
              <div className="flex flex-wrap gap-1.5 mt-2.5">
                <Badge severity={selectedChain.severity.toLowerCase() as any}>{selectedChain.severity}</Badge>
                {selectedChain.likelihood && (
                  <span className="font-mono text-[8.5px] text-slate-500 bg-white border border-slate-200 px-1.5 py-0.5 rounded dark:bg-slate-950 dark:border-slate-800 dark:text-slate-405">
                    Chance of Attack: {selectedChain.likelihood}
                  </span>
                )}
                {selectedChain.businessImpact && (
                  <span className="font-mono text-[8.5px] text-slate-500 bg-white border border-slate-200 px-1.5 py-0.5 rounded dark:bg-slate-950 dark:border-slate-800 dark:text-slate-405">
                    Damage Potential: {selectedChain.businessImpact}
                  </span>
                )}
                <span className="font-mono text-[8.5px] text-slate-500 bg-white border border-slate-200 px-1.5 py-0.5 rounded dark:bg-slate-950 dark:border-slate-800 dark:text-slate-405">
                  Overall Risk <span className="inline-flex items-center justify-center cursor-help text-blue-500 hover:text-blue-400 dark:text-blue-400 dark:hover:text-blue-300 font-bold ml-1.5 text-[13px] select-none transition-colors align-middle" title="A number estimating how serious this issue is.">ⓘ</span>: {(selectedChain.severity.toLowerCase() === "critical" ? 9.5 : selectedChain.severity.toLowerCase() === "high" ? 8.8 : selectedChain.severity.toLowerCase() === "medium" ? 6.5 : 3.2).toFixed(1)}
                </span>
              </div>
            </div>
 
            {/* Description */}
            {selectedChain.description && (
              <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-850 bg-slate-50 dark:bg-slate-900/40 space-y-1.5 w-full">
                <strong className="text-slate-700 dark:text-slate-350 block font-mono text-[9px] uppercase">Route Description</strong>
                <p className="font-sans text-[11.5px] text-slate-600 dark:text-slate-400 break-words whitespace-normal w-full leading-relaxed">
                  {selectedChain.description}
                </p>
              </div>
            )}
 
            {/* MITRE Techniques */}
            {selectedChain.mitreTechniques && selectedChain.mitreTechniques.length > 0 && (
              <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-850 bg-slate-50 dark:bg-slate-900/40 space-y-2 w-full">
                <span className="font-mono text-[9px] uppercase tracking-wider text-slate-455 block font-bold dark:text-slate-400">
                  Attack Techniques <span className="inline-flex items-center justify-center cursor-help text-blue-500 hover:text-blue-400 dark:text-blue-400 dark:hover:text-blue-300 font-bold ml-1.5 text-[13px] select-none transition-colors align-middle" title="A method commonly used by attackers. Also references the MITRE ATT&CK framework.">ⓘ</span>
                </span>
                <div className="flex flex-wrap gap-1.5 max-h-28 overflow-y-auto w-full pr-1">
                  {selectedChain.mitreTechniques.map((tech: string, idx: number) => {
                    const code = tech.split(" - ")[0];
                    return (
                      <span key={idx} className="text-[9px] font-mono bg-white border border-slate-200 text-slate-700 px-2 py-0.5 rounded dark:bg-slate-950 dark:border-slate-800 dark:text-slate-350 break-all max-w-full" title={tech}>
                        {code}
                      </span>
                    );
                  })}
                </div>
              </div>
            )}
 
            {/* Assets Involved */}
            {selectedChain.path && selectedChain.path.length > 0 && (
              <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-850 bg-slate-50 dark:bg-slate-900/40 space-y-2 w-full">
                <span className="font-mono text-[9px] uppercase tracking-wider text-slate-455 block font-bold dark:text-slate-400">Devices Involved</span>
                <div className="flex flex-col items-center bg-white border border-slate-200 p-2.5 rounded-lg dark:bg-slate-950 dark:border-slate-800 gap-1 text-[9.5px] font-mono text-slate-650 dark:text-slate-350 select-none max-h-40 overflow-y-auto w-full pr-1">
                  {selectedChain.path.map((node: any, idx: number) => (
                    <React.Fragment key={idx}>
                      {idx > 0 && <span className="text-slate-400 font-bold shrink-0">↓</span>}
                      <span className="text-slate-800 font-bold dark:text-slate-200 break-all whitespace-normal text-center max-w-full">{node.assetName}</span>
                    </React.Fragment>
                  ))}
                </div>
              </div>
            )}
 
            {/* Recommendations */}
            {selectedChain.remediations && selectedChain.remediations.length > 0 && (
              <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-850 bg-slate-50 dark:bg-slate-900/40 space-y-2.5 w-full">
                <h4 className="text-[9px] font-mono font-bold tracking-wider text-slate-455 uppercase flex items-center gap-1.5 dark:text-slate-400">
                  <CornerDownRight className="h-3.5 w-3.5 text-blue-500 shrink-0" /> Recommended Fixes
                </h4>
                
                <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1 w-full">
                  {selectedChain.remediations.map((mit: string, idx: number) => (
                    <button
                      key={idx}
                      onClick={() => handleTriggerPlaybook(mit)}
                      className="w-full text-left p-2.5 bg-white border border-slate-200 hover:border-blue-500/45 rounded-lg text-[9.5px] font-mono text-slate-650 hover:text-slate-900 hover:bg-slate-950 flex items-center justify-between transition-all cursor-pointer group shadow-sm dark:bg-slate-950 dark:border-slate-800 dark:text-slate-400 dark:hover:text-slate-200 dark:hover:bg-slate-900 min-w-0"
                    >
                      <span className="whitespace-normal break-words pr-2 leading-relaxed min-w-0 flex-1">{mit}</span>
                      <Sparkles className="h-3 w-3 text-slate-400 group-hover:text-blue-500 shrink-0" />
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
 
          {/* Action button */}
          <div className="pt-3 border-t border-slate-100 dark:border-slate-850 shrink-0 mt-3">
            <Button
              variant="cyber"
              size="sm"
              className="w-full text-xs font-mono justify-center"
              onClick={() => navigate(`/copilot?query=mitigate+${selectedChain.id}`)}
            >
              <Compass className="mr-1.5 h-3.5 w-3.5" />
              Start Protection Guide
            </Button>
          </div>
        </div>

      </div>
    </>
    )}
    </div>
  );
}

export default AttackGraphPage;
