import { FastifyInstance } from "fastify";
import { authenticate } from "../core/auth";
import { db } from "../core/db";
import PDFDocument from "pdfkit";

export let localReports = [
  { id: "REP-2026-001", title: "Executive SOC2 Audit Compliance Report", timestamp: "03:42:00 Z", size: "4.2 MB", format: "PDF", downloadCount: 14 },
  { id: "REP-2026-002", title: "Boundary Palo Alto Firewall Log Feed", timestamp: "03:02:00 Z", size: "18.5 MB", format: "CSV", downloadCount: 22 },
  { id: "REP-2026-003", title: "ISO27001 Access Management Audit Log", timestamp: "02:15:00 Z", size: "2.1 MB", format: "PDF", downloadCount: 8 }
];

function mapCategory(vulnCategory: string | null | undefined): string {
  if (!vulnCategory) return "Uncategorized";
  const catMap: Record<string, string> = {
    "weak_credential": "Credential Access",
    "unpatched_service": "Initial Access",
    "misconfiguration": "Misconfiguration",
    "privilege_escalation_vuln": "Privilege Escalation",
    "lateral_movement_vector": "Lateral Movement"
  };
  return catMap[vulnCategory] || vulnCategory;
}

function escapeCSV(val: any): string {
  if (val === undefined || val === null) return "";
  const str = String(val);
  if (str.includes(",") || str.includes('"') || str.includes("\n")) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function buildPDFBuffer(findings: any[], assets: any[], approvals: any[], reportTitle: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 40, size: "A4", bufferPages: true });
      const chunks: Buffer[] = [];
      
      doc.on("data", (chunk) => chunks.push(chunk));
      doc.on("end", () => resolve(Buffer.concat(chunks)));
      doc.on("error", (err) => reject(err));
      
      // Title Block
      doc.font("Helvetica-Bold").fontSize(18).fillColor("#0f172a").text("VYUHA AI SOC Security Report", { align: "center" });
      doc.font("Helvetica-Bold").fontSize(12).fillColor("#2563eb").text(reportTitle, { align: "center" });
      doc.moveDown(1.5);
      
      // Date info
      const timeStr = new Date().toUTCString();
      
      // 1. Executive Summary Box
      doc.font("Helvetica-Bold").fontSize(12).fillColor("#0f172a").text("1. Executive Summary");
      doc.moveTo(40, doc.y + 2).lineTo(555, doc.y + 2).strokeColor("#cbd5e1").lineWidth(1).stroke();
      doc.moveDown(0.8);
      
      const totalFindings = findings.length;
      const criticalCount = findings.filter(f => f.severity?.toLowerCase() === "critical").length;
      const highCount = findings.filter(f => f.severity?.toLowerCase() === "high").length;
      const mediumCount = findings.filter(f => f.severity?.toLowerCase() === "medium").length;
      const lowCount = findings.filter(f => f.severity?.toLowerCase() === "low").length;
      const assetsScanned = assets.length;
      const pendingApprovals = approvals.filter(a => a.status === "pending").length;
      
      doc.font("Helvetica").fontSize(10).fillColor("#334155");
      const summaryItems = [
        `Generated Time: ${timeStr}`,
        `Total Findings: ${totalFindings}`,
        `Critical Findings: ${criticalCount}`,
        `High Findings: ${highCount}`,
        `Medium Findings: ${mediumCount}`,
        `Low Findings: ${lowCount}`,
        `Assets Scanned: ${assetsScanned}`,
        `Pending Approvals: ${pendingApprovals}`
      ];
      
      summaryItems.forEach(item => {
        doc.text(`• ${item}`, { indent: 15 });
        doc.moveDown(0.3);
      });
      doc.moveDown(1.5);
      
      // 2. Findings Table
      doc.font("Helvetica-Bold").fontSize(12).fillColor("#0f172a").text("2. Findings Table");
      doc.moveTo(40, doc.y + 2).lineTo(555, doc.y + 2).strokeColor("#cbd5e1").lineWidth(1).stroke();
      doc.moveDown(0.8);
      
      // autoTable columnStyles definitions (fixed widths)
      const findingsColumnStyles = {
        id: { x: 40, width: 85 },
        asset: { x: 130, width: 90 },
        cve: { x: 225, width: 60 },
        severity: { x: 290, width: 45 },
        cvss: { x: 340, width: 25 },
        riskScore: { x: 370, width: 40 },
        status: { x: 415, width: 40 },
        category: { x: 460, width: 95 }
      };

      // Header row
      let y = doc.y;
      doc.font("Helvetica-Bold").fontSize(8).fillColor("#475569");
      doc.text("Finding ID", findingsColumnStyles.id.x, y, { width: findingsColumnStyles.id.width });
      doc.text("Asset", findingsColumnStyles.asset.x, y, { width: findingsColumnStyles.asset.width });
      doc.text("CVE", findingsColumnStyles.cve.x, y, { width: findingsColumnStyles.cve.width });
      doc.text("Severity", findingsColumnStyles.severity.x, y, { width: findingsColumnStyles.severity.width });
      doc.text("CVSS", findingsColumnStyles.cvss.x, y, { width: findingsColumnStyles.cvss.width });
      doc.text("Risk Score", findingsColumnStyles.riskScore.x, y, { width: findingsColumnStyles.riskScore.width });
      doc.text("Status", findingsColumnStyles.status.x, y, { width: findingsColumnStyles.status.width });
      doc.text("Category", findingsColumnStyles.category.x, y, { width: findingsColumnStyles.category.width });
      
      y += 12;
      doc.moveTo(40, y).lineTo(555, y).strokeColor("#cbd5e1").lineWidth(0.5).stroke();
      y += 8;
      
      doc.font("Helvetica").fontSize(8).fillColor("#0f172a");
      findings.forEach((f) => {
        const hostnameText = f.hostname || "unknown";
        const cveText = f.cve_id || "N/A";
        const sevText = (f.severity || "LOW").toUpperCase();
        const cvssText = String(f.cvss_score || 0);
        const riskText = String(f.risk_score || 0);
        const statusText = f.status || "open";
        const categoryText = f.category || "Uncategorized";

        // Display only first 8 chars followed by "..."
        const idShort = (f.id || "").substring(0, 8) + "...";
        const hId = doc.heightOfString(idShort, { width: findingsColumnStyles.id.width });
        const hAsset = doc.heightOfString(hostnameText, { width: findingsColumnStyles.asset.width });
        const hCve = doc.heightOfString(cveText, { width: findingsColumnStyles.cve.width });
        const hSev = doc.heightOfString(sevText, { width: findingsColumnStyles.severity.width });
        const hCvss = doc.heightOfString(cvssText, { width: findingsColumnStyles.cvss.width });
        const hRisk = doc.heightOfString(riskText, { width: findingsColumnStyles.riskScore.width });
        const hStatus = doc.heightOfString(statusText, { width: findingsColumnStyles.status.width });
        const hCat = doc.heightOfString(categoryText, { width: findingsColumnStyles.category.width });
        
        const rowHeight = Math.max(hId, hAsset, hCve, hSev, hCvss, hRisk, hStatus, hCat);

        if (y + rowHeight > 750) {
          doc.addPage();
          y = 50;
          
          doc.font("Helvetica-Bold").fontSize(8).fillColor("#475569");
          doc.text("Finding ID", findingsColumnStyles.id.x, y, { width: findingsColumnStyles.id.width });
          doc.text("Asset", findingsColumnStyles.asset.x, y, { width: findingsColumnStyles.asset.width });
          doc.text("CVE", findingsColumnStyles.cve.x, y, { width: findingsColumnStyles.cve.width });
          doc.text("Severity", findingsColumnStyles.severity.x, y, { width: findingsColumnStyles.severity.width });
          doc.text("CVSS", findingsColumnStyles.cvss.x, y, { width: findingsColumnStyles.cvss.width });
          doc.text("Risk Score", findingsColumnStyles.riskScore.x, y, { width: findingsColumnStyles.riskScore.width });
          doc.text("Status", findingsColumnStyles.status.x, y, { width: findingsColumnStyles.status.width });
          doc.text("Category", findingsColumnStyles.category.x, y, { width: findingsColumnStyles.category.width });
          y += 12;
          doc.moveTo(40, y).lineTo(555, y).strokeColor("#cbd5e1").lineWidth(0.5).stroke();
          y += 8;
          doc.font("Helvetica").fontSize(8).fillColor("#0f172a");
        }
        
        doc.text(idShort, findingsColumnStyles.id.x, y, { width: findingsColumnStyles.id.width });
        doc.text(hostnameText, findingsColumnStyles.asset.x, y, { width: findingsColumnStyles.asset.width });
        doc.text(cveText, findingsColumnStyles.cve.x, y, { width: findingsColumnStyles.cve.width });
        
        // Severity color
        const sevLower = (f.severity || "low").toLowerCase();
        let sevColor = "#10b981"; // green
        if (sevLower === "critical") sevColor = "#ef4444";
        else if (sevLower === "high") sevColor = "#f59e0b";
        else if (sevLower === "medium") sevColor = "#ca8a04";
        
        doc.fillColor(sevColor).font("Helvetica-Bold").text(sevText, findingsColumnStyles.severity.x, y, { width: findingsColumnStyles.severity.width });
        doc.fillColor("#0f172a").font("Helvetica");
        
        doc.text(cvssText, findingsColumnStyles.cvss.x, y, { width: findingsColumnStyles.cvss.width });
        doc.text(riskText, findingsColumnStyles.riskScore.x, y, { width: findingsColumnStyles.riskScore.width });
        doc.text(statusText, findingsColumnStyles.status.x, y, { width: findingsColumnStyles.status.width });
        doc.text(categoryText, findingsColumnStyles.category.x, y, { width: findingsColumnStyles.category.width });
        
        y += rowHeight + 6;
      });
      doc.y = y + 8;
      doc.x = 40;
      
      // 3. Assets Section
      if (doc.y > 730) {
        doc.addPage();
      }
      doc.font("Helvetica-Bold").fontSize(12).fillColor("#0f172a")
        .text("3. Scanned Assets", 40, doc.y);
      doc.moveTo(40, doc.y + 2).lineTo(555, doc.y + 2).strokeColor("#cbd5e1").lineWidth(1).stroke();
      doc.moveDown(0.8);
      
      // autoTable columnStyles definitions (fixed widths)
      const assetsColumnStyles = {
        hostname: { x: 40, width: 150 },
        ip: { x: 200, width: 100 },
        criticality: { x: 310, width: 100 },
        os: { x: 420, width: 135 }
      };

      y = doc.y;
      doc.font("Helvetica-Bold").fontSize(8).fillColor("#475569");
      doc.text("Hostname", assetsColumnStyles.hostname.x, y, { width: assetsColumnStyles.hostname.width });
      doc.text("IP", assetsColumnStyles.ip.x, y, { width: assetsColumnStyles.ip.width });
      doc.text("Criticality", assetsColumnStyles.criticality.x, y, { width: assetsColumnStyles.criticality.width });
      doc.text("OS", assetsColumnStyles.os.x, y, { width: assetsColumnStyles.os.width });
      
      y += 12;
      doc.moveTo(40, y).lineTo(555, y).strokeColor("#cbd5e1").lineWidth(0.5).stroke();
      y += 8;
      
      doc.font("Helvetica").fontSize(8).fillColor("#0f172a");
      assets.forEach((a) => {
        const hostnameText = a.hostname || "unknown";
        const ipText = a.ip_address || "0.0.0.0";
        const critText = (a.criticality || "LOW").toUpperCase();
        const osText = a.os_type || "Ubuntu Server";

        const hHost = doc.heightOfString(hostnameText, { width: assetsColumnStyles.hostname.width });
        const hIp = doc.heightOfString(ipText, { width: assetsColumnStyles.ip.width });
        const hCrit = doc.heightOfString(critText, { width: assetsColumnStyles.criticality.width });
        const hOs = doc.heightOfString(osText, { width: assetsColumnStyles.os.width });
        
        const rowHeight = Math.max(hHost, hIp, hCrit, hOs);

        if (y + rowHeight > 750) {
          doc.addPage();
          y = 50;
          
          doc.font("Helvetica-Bold").fontSize(8).fillColor("#475569");
          doc.text("Hostname", assetsColumnStyles.hostname.x, y, { width: assetsColumnStyles.hostname.width });
          doc.text("IP", assetsColumnStyles.ip.x, y, { width: assetsColumnStyles.ip.width });
          doc.text("Criticality", assetsColumnStyles.criticality.x, y, { width: assetsColumnStyles.criticality.width });
          doc.text("OS", assetsColumnStyles.os.x, y, { width: assetsColumnStyles.os.width });
          y += 12;
          doc.moveTo(40, y).lineTo(555, y).strokeColor("#cbd5e1").lineWidth(0.5).stroke();
          y += 8;
          doc.font("Helvetica").fontSize(8).fillColor("#0f172a");
        }
        
        doc.text(hostnameText, assetsColumnStyles.hostname.x, y, { width: assetsColumnStyles.hostname.width });
        doc.text(ipText, assetsColumnStyles.ip.x, y, { width: assetsColumnStyles.ip.width });
        
        // Criticality style
        const critLower = (a.criticality || "low").toLowerCase();
        let critColor = "#64748b";
        if (critLower === "critical" || critLower === "high") critColor = "#ef4444";
        doc.fillColor(critColor).font("Helvetica-Bold").text(critText, assetsColumnStyles.criticality.x, y, { width: assetsColumnStyles.criticality.width });
        doc.fillColor("#0f172a").font("Helvetica");
        
        doc.text(osText, assetsColumnStyles.os.x, y, { width: assetsColumnStyles.os.width });
        y += rowHeight + 6;
      });
      doc.y = y + 8;
      
      // 4. Approval Summary Section
      if (doc.y > 730) {
        doc.addPage();
      }
      doc.font("Helvetica-Bold").fontSize(12).fillColor("#0f172a")
        .text("4. Containment Action Approvals", 40, doc.y);
      doc.moveTo(40, doc.y + 2).lineTo(555, doc.y + 2).strokeColor("#cbd5e1").lineWidth(1).stroke();
      doc.moveDown(0.8);
      
      const approvedCount = approvals.filter(a => a.status === "approved").length;
      const rejectedCount = approvals.filter(a => a.status === "rejected").length;
      const pendingCount = approvals.filter(a => a.status === "pending").length;
      
      doc.font("Helvetica").fontSize(10).fillColor("#334155")
        .text(`Approved: ${approvedCount}`, 40, doc.y, { indent: 15 });
      doc.moveDown(0.3);
      doc.text(`Rejected: ${rejectedCount}`, 40, doc.y, { indent: 15 });
      doc.moveDown(0.3);  
      doc.text(`Pending: ${pendingCount}`, 40, doc.y, { indent: 15 });
      doc.moveDown(1.5);
      
      // Footer: Printed on all pages
      let pages = doc.bufferedPageRange();
      for (let i = 0; i < pages.count; i++) {
        doc.switchToPage(i);
        const oldBottomMargin = doc.page.margins.bottom;
        doc.page.margins.bottom = 0;
        doc.font("Helvetica").fontSize(8).fillColor("#94a3b8");
        doc.text(
          "Generated by VYUHA AI SOC Console",
          40,
          800,
          { align: "center", width: 512 }
        );
        doc.page.margins.bottom = oldBottomMargin;
      }
      
      doc.end();
    } catch (e) {
      reject(e);
    }
  });
}

export default async function reportsRoutes(app: FastifyInstance) {
  app.get(
    "/reports",
    { preHandler: authenticate },
    async (req, reply) => {
      return {
        compliance: [
          { id: "COMP-001", name: "ISO 27001", status: "compliant", score: 91 },
          { id: "COMP-002", name: "SOC2 Type II", status: "compliant", score: 95 },
          { id: "COMP-003", name: "GDPR Access", status: "compliant", score: 88 }
        ],
        reports: localReports
      };
    }
  );

  app.post(
    "/reports",
    { preHandler: authenticate },
    async (req, reply) => {
      const { format = "PDF" } = (req.body as any) || {};
      const newId = `REP-2026-00${localReports.length + 1}`;
      const newReport = {
        id: newId,
        title: format === "CSV" ? "Boundary Palo Alto Firewall Log Feed" : "Executive CISO Threat Audit Summary",
        timestamp: "Just Now",
        size: format === "CSV" ? "12.4 MB" : "3.1 MB",
        format: format,
        downloadCount: 0
      };

      if (req.user) {
        await db.from("audit_log").insert({
          action: "report_generated",
          performed_by: req.user.id,
          details: { report_id: newId, title: newReport.title }
        });
      }

      localReports = [newReport, ...localReports];
      return newReport;
    }
  );

  app.get<{ Params: { id: string }; Querystring: { format?: string } }>(
    "/reports/:id/download",
    { preHandler: authenticate },
    async (req, reply) => {
      const report = localReports.find(r => r.id === req.params.id);
      if (!report) {
        return reply.code(404).send({ error: "Report not found" });
      }

      report.downloadCount += 1;

      const format = req.query.format || report.format;
      const filename = `${report.title.replace(/\s+/g, "_")}_${report.id}.${format.toLowerCase()}`;

      try {
        // Query live Supabase telemetry
        const [findingsRes, assetsRes, approvalsRes] = await Promise.all([
          db.from("findings").select("*"),
          db.from("assets").select("*"),
          db.from("approvals").select("*")
        ]);

        const findings = findingsRes.data || [];
        const assets = assetsRes.data || [];
        const approvals = approvalsRes.data || [];

        const assetsMap = new Map(assets.map(a => [a.id, a]));
        const findingsWithAsset = findings.map(f => {
          const asset = f.asset_id ? assetsMap.get(f.asset_id) : null;
          return {
            id: f.id,
            asset_id: f.asset_id || "",
            hostname: asset ? asset.hostname : "unknown",
            ip: asset ? asset.ip_address || "0.0.0.0" : "0.0.0.0",
            cve_id: f.cve_id || "N/A",
            severity: f.severity || "low",
            cvss_score: f.cvss_score || 0,
            risk_score: f.risk_score || 0,
            category: mapCategory(f.vuln_category),
            status: f.status || "open",
            detected_at: f.detected_at || new Date().toISOString()
          };
        });

        if (format === "PDF") {
          const pdfBuffer = await buildPDFBuffer(findingsWithAsset, assets, approvals, report.title);
          reply.header("Content-Type", "application/pdf");
          reply.header("Content-Length", pdfBuffer.length);
          reply.header("Content-Disposition", `attachment; filename="${filename}"`);
          return reply.send(pdfBuffer);
        } else {
          // Expose actual findings to CSV
          const headers = [
            "Finding ID",
            "Asset",
            "Hostname",
            "IP",
            "CVE",
            "Severity",
            "CVSS",
            "Risk Score",
            "Category",
            "Status",
            "Detected Time"
          ];
          const rows = findingsWithAsset.map(f => [
            f.id,
            f.asset_id,
            f.hostname,
            f.ip,
            f.cve_id,
            f.severity,
            f.cvss_score,
            f.risk_score,
            f.category,
            f.status,
            f.detected_at
          ].map(escapeCSV).join(","));

          const csvContent = [headers.join(","), ...rows].join("\n");
          const csvBuffer = Buffer.from(csvContent, "utf-8");
          reply.header("Content-Type", "text/csv; charset=utf-8");
          reply.header("Content-Length", csvBuffer.length);
          reply.header("Content-Disposition", `attachment; filename="${filename}"`);
          return reply.send(csvBuffer);
        }
      } catch (err: any) {
        console.error(err);
        return reply.code(500).send({ error: "Failed to compile report: " + err.message });
      }
    }
  );
}
