'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {
  ArrowLeft,
  Download,
  Printer,
  Share2,
  Copy,
  Check,
  X,
  FileText,
  AlertTriangle,
  TrendingUp,
  BarChart3,
  Shield,
  Calendar,
  Building2,
  Loader2,
  AlertCircle,
} from 'lucide-react';
import { cn, formatDate, formatDateTime } from '@/lib/utils';
import { ScoreGauge } from '@/components/ScoreGauge';
import { reportsApi, dashboardApi, scansApi, findingsApi } from '@/lib/api';
import type { Report } from '@/types';
import { jsPDF } from 'jspdf';

interface ExtendedReport extends Report {
  projectName?: string;
  summary?: {
    overallScore: number;
    projectsScanned: number;
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
  findings?: {
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    projectName: string;
    file: string;
    line: number;
  }[];
  projectBreakdown?: {
    projectName: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }[];
  trendData?: {
    date: string;
    score: number;
    findings: number;
  }[];
}

const reportTypeLabels: Record<string, string> = {
  security_summary: 'Summary',
  scan_detail: 'Detailed Report',
  compliance: 'Compliance',
  vulnerability: 'Vulnerability',
  executive: 'Executive Summary',
};

export default function ReportDetailPage() {
  const params = useParams();
  const reportId = params.id as string;
  const [report, setReport] = useState<ExtendedReport | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showShareModal, setShowShareModal] = useState(false);

  useEffect(() => {
    fetchReport();
  }, [reportId]);

  async function fetchReport() {
    try {
      setIsLoading(true);
      setError(null);
      const data = await reportsApi.get(reportId);
      setReport(data as ExtendedReport);
    } catch (err) {
      console.error('Failed to fetch report:', err);
      setError(err instanceof Error ? err.message : 'Failed to load report');
    } finally {
      setIsLoading(false);
    }
  }

  const handleDownload = async () => {
    if (!report) return;
    try {
      // Fetch live data based on report type
      let dashboardSummary: Record<string, unknown> | null = null;
      let findingsList: Array<Record<string, unknown>> = [];
      let findingsSummary: Record<string, number> | null = null;
      let scanData: Record<string, unknown> | null = null;

      if (report.reportType === 'scan_detail' && report.scanId) {
        // Scan-specific report: fetch scan details + findings
        const [scan, findingsResult] = await Promise.all([
          scansApi.get(report.scanId).catch(() => null),
          scansApi.getFindings(report.scanId, { limit: 200 }).catch(() => null),
        ]);
        if (scan) scanData = scan as unknown as Record<string, unknown>;
        if (findingsResult) {
          const fr = findingsResult as unknown as Record<string, unknown>;
          findingsList = (fr.data || []) as Array<Record<string, unknown>>;
        }
      } else {
        // Cross-project summary (security_summary, executive, etc.)
        const [summary, findingsResult] = await Promise.all([
          dashboardApi.getSummary().catch(() => null),
          findingsApi.list({ limit: 100 }).catch(() => null),
        ]);
        if (summary) dashboardSummary = summary as unknown as Record<string, unknown>;
        if (findingsResult) {
          const fr = findingsResult as unknown as Record<string, unknown>;
          findingsList = (fr.data || []) as Array<Record<string, unknown>>;
          findingsSummary = (fr.summary || null) as Record<string, number> | null;
        }
      }

      const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
      const pageWidth = doc.internal.pageSize.getWidth();
      const pageHeight = doc.internal.pageSize.getHeight();
      const margin = 20;
      const contentWidth = pageWidth - margin * 2;
      let y = margin;

      const checkPageBreak = (needed: number) => {
        if (y + needed > pageHeight - margin) {
          doc.addPage();
          y = margin;
        }
      };

      // --- Header bar ---
      doc.setFillColor(15, 23, 42); // slate-900
      doc.rect(0, 0, pageWidth, 40, 'F');
      doc.setFillColor(56, 189, 248); // sky-400 accent line
      doc.rect(0, 40, pageWidth, 1.5, 'F');

      doc.setTextColor(255, 255, 255);
      doc.setFontSize(22);
      doc.setFont('helvetica', 'bold');
      doc.text('Code Hardener', margin, 18);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');
      doc.text('Security Assurance Platform', margin, 26);
      doc.setFontSize(9);
      doc.text(`Generated: ${formatDateTime(report.generatedAt || report.createdAt)}`, pageWidth - margin, 18, { align: 'right' });
      doc.text(`Report ID: ${report.id.slice(0, 8)}...`, pageWidth - margin, 26, { align: 'right' });

      y = 52;

      // --- Report Title ---
      doc.setTextColor(15, 23, 42);
      doc.setFontSize(18);
      doc.setFont('helvetica', 'bold');
      doc.text(report.title, margin, y);
      y += 8;

      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(100, 116, 139); // slate-500
      const meta = [
        `Type: ${reportTypeLabels[report.reportType] || report.reportType}`,
        report.projectName ? `Project: ${report.projectName}` : 'Scope: All Projects',
        report.format ? `Format: ${report.format.toUpperCase()}` : '',
      ].filter(Boolean).join('  |  ');
      doc.text(meta, margin, y);
      y += 10;

      // Divider
      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.5);
      doc.line(margin, y, pageWidth - margin, y);
      y += 8;

      // --- Scan detail report ---
      if (scanData) {
        const fc = (scanData.findingsCount || {}) as Record<string, number>;

        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(15, 23, 42);
        doc.text('Scan Summary', margin, y);
        y += 8;

        doc.setFontSize(10);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(51, 65, 85);

        const scanInfo = [
          ['Status', String(scanData.status || 'N/A')],
          ['Profile', String(scanData.profile || 'standard')],
          ['Branch', String(scanData.branch || 'N/A')],
          ['Score', String(scanData.score ?? 'N/A')],
          ['Quality Level', String(scanData.qualityLevel || 'N/A')],
          ['Duration', scanData.duration ? `${scanData.duration}s` : 'N/A'],
          ['Started', scanData.startedAt ? formatDateTime(String(scanData.startedAt)) : 'N/A'],
          ['Completed', scanData.completedAt ? formatDateTime(String(scanData.completedAt)) : 'N/A'],
        ];

        for (const [label, value] of scanInfo) {
          doc.setFont('helvetica', 'bold');
          doc.text(`${label}:`, margin, y);
          doc.setFont('helvetica', 'normal');
          doc.text(value, margin + 35, y);
          y += 5.5;
        }
        y += 4;

        // Severity breakdown box
        checkPageBreak(30);
        doc.setFillColor(248, 250, 252); // slate-50
        doc.roundedRect(margin, y, contentWidth, 24, 2, 2, 'F');

        const severities = [
          { label: 'Critical', count: fc.critical || 0, color: [220, 38, 38] },
          { label: 'High', count: fc.high || 0, color: [249, 115, 22] },
          { label: 'Medium', count: fc.medium || 0, color: [234, 179, 8] },
          { label: 'Low', count: fc.low || 0, color: [148, 163, 184] },
          { label: 'Info', count: fc.info || 0, color: [100, 116, 139] },
        ];

        const boxWidth = contentWidth / severities.length;
        severities.forEach((sev, i) => {
          const cx = margin + boxWidth * i + boxWidth / 2;
          doc.setFontSize(16);
          doc.setFont('helvetica', 'bold');
          doc.setTextColor(sev.color[0], sev.color[1], sev.color[2]);
          doc.text(String(sev.count), cx, y + 10, { align: 'center' });
          doc.setFontSize(8);
          doc.setFont('helvetica', 'normal');
          doc.setTextColor(100, 116, 139);
          doc.text(sev.label, cx, y + 17, { align: 'center' });
        });

        y += 32;
      }

      // --- Cross-project security overview ---
      if (dashboardSummary) {
        const openFindings = (dashboardSummary.openFindings || {}) as Record<string, number>;

        // Security Score section
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(15, 23, 42);
        doc.text('Security Overview', margin, y);
        y += 8;

        // Score highlight box
        checkPageBreak(30);
        doc.setFillColor(248, 250, 252);
        doc.roundedRect(margin, y, contentWidth, 20, 2, 2, 'F');

        const score = Number(dashboardSummary.qualityScore || 0);
        const scoreColor: [number, number, number] = score >= 800 ? [34, 197, 94] : score >= 500 ? [234, 179, 8] : [220, 38, 38];
        doc.setFontSize(24);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(scoreColor[0], scoreColor[1], scoreColor[2]);
        doc.text(String(score), margin + 10, y + 14);
        doc.setFontSize(9);
        doc.setTextColor(100, 116, 139);
        doc.setFont('helvetica', 'normal');
        doc.text('/ 1000  Security Score', margin + 35, y + 14);

        const trend = String(dashboardSummary.scoreTrend || 'stable');
        const trendLabel = trend === 'up' ? 'Improving' : trend === 'down' ? 'Declining' : 'Stable';
        doc.text(`Trend: ${trendLabel}`, pageWidth - margin - 10, y + 14, { align: 'right' });
        y += 28;

        doc.setFontSize(10);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(51, 65, 85);

        const summaryItems = [
          ['Total Projects', String(dashboardSummary.projectCount || 0)],
          ['Scans This Month', String(dashboardSummary.scansThisMonth || 0)],
          ['Open Findings', String(openFindings.total || 0)],
          ['Critical', String(openFindings.critical || 0)],
          ['High', String(openFindings.high || 0)],
          ['Medium', String(openFindings.medium || 0)],
          ['Low', String(openFindings.low || 0)],
        ];

        for (const [label, value] of summaryItems) {
          doc.setFont('helvetica', 'bold');
          doc.text(`${label}:`, margin, y);
          doc.setFont('helvetica', 'normal');
          doc.text(value, margin + 45, y);
          y += 5.5;
        }
        y += 6;

        // Severity breakdown box
        checkPageBreak(30);
        doc.setFillColor(248, 250, 252);
        doc.roundedRect(margin, y, contentWidth, 24, 2, 2, 'F');

        const severities = [
          { label: 'Critical', count: openFindings.critical || 0, color: [220, 38, 38] },
          { label: 'High', count: openFindings.high || 0, color: [249, 115, 22] },
          { label: 'Medium', count: openFindings.medium || 0, color: [234, 179, 8] },
          { label: 'Low', count: openFindings.low || 0, color: [148, 163, 184] },
        ];

        const boxWidth = contentWidth / severities.length;
        severities.forEach((sev, i) => {
          const cx = margin + boxWidth * i + boxWidth / 2;
          doc.setFontSize(16);
          doc.setFont('helvetica', 'bold');
          doc.setTextColor(sev.color[0], sev.color[1], sev.color[2]);
          doc.text(String(sev.count), cx, y + 10, { align: 'center' });
          doc.setFontSize(8);
          doc.setFont('helvetica', 'normal');
          doc.setTextColor(100, 116, 139);
          doc.text(sev.label, cx, y + 17, { align: 'center' });
        });

        y += 32;

        // Recent scans table
        const recentScans = (dashboardSummary.recentScans || []) as Array<Record<string, unknown>>;
        if (recentScans.length > 0) {
          checkPageBreak(20);
          doc.setFontSize(14);
          doc.setFont('helvetica', 'bold');
          doc.setTextColor(15, 23, 42);
          doc.text('Recent Scans', margin, y);
          y += 8;

          // Table header
          const colWidths = [50, 30, 25, 25, 40];
          const colX = [margin];
          for (let i = 1; i < colWidths.length; i++) {
            colX.push(colX[i - 1] + colWidths[i - 1]);
          }

          doc.setFillColor(15, 23, 42);
          doc.rect(margin, y, contentWidth, 7, 'F');
          doc.setTextColor(255, 255, 255);
          doc.setFontSize(8);
          doc.setFont('helvetica', 'bold');
          doc.text('Project', colX[0] + 2, y + 5);
          doc.text('Status', colX[1] + 2, y + 5);
          doc.text('Score', colX[2] + 2, y + 5);
          doc.text('Risk', colX[3] + 2, y + 5);
          doc.text('Date', colX[4] + 2, y + 5);
          y += 7;

          doc.setFont('helvetica', 'normal');
          doc.setFontSize(7);

          recentScans.forEach((scan, idx) => {
            checkPageBreak(8);
            if (idx % 2 === 0) {
              doc.setFillColor(248, 250, 252);
              doc.rect(margin, y, contentWidth, 6.5, 'F');
            }
            doc.setTextColor(30, 41, 59);
            doc.text(String(scan.projectName || '').slice(0, 35), colX[0] + 2, y + 4.5);
            doc.text(String(scan.status || ''), colX[1] + 2, y + 4.5);
            doc.text(String(scan.score ?? 'N/A'), colX[2] + 2, y + 4.5);
            doc.text(String(scan.qualityLevel || 'N/A'), colX[3] + 2, y + 4.5);
            doc.text(scan.createdAt ? formatDate(String(scan.createdAt)) : '', colX[4] + 2, y + 4.5);
            y += 6.5;
          });
          y += 6;
        }
      }

      // --- Findings summary from API ---
      if (findingsSummary) {
        checkPageBreak(20);
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(15, 23, 42);
        doc.text('Findings Summary', margin, y);
        y += 8;

        doc.setFontSize(10);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(51, 65, 85);
        const fsItems = [
          ['Total', String(findingsSummary.total || 0)],
          ['Critical', String(findingsSummary.critical || 0)],
          ['High', String(findingsSummary.high || 0)],
          ['Medium', String(findingsSummary.medium || 0)],
          ['Low', String(findingsSummary.low || 0)],
          ['Info', String(findingsSummary.info || 0)],
        ];
        for (const [label, value] of fsItems) {
          doc.setFont('helvetica', 'bold');
          doc.text(`${label}:`, margin, y);
          doc.setFont('helvetica', 'normal');
          doc.text(value, margin + 30, y);
          y += 5.5;
        }
        y += 6;
      }

      // --- Findings Table ---
      if (findingsList.length > 0) {
        checkPageBreak(20);

        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(15, 23, 42);
        doc.text(`Findings (${findingsList.length})`, margin, y);
        y += 8;

        // Table header
        const colWidths = [22, 55, 55, 38];
        const colX = [margin, margin + colWidths[0], margin + colWidths[0] + colWidths[1], margin + colWidths[0] + colWidths[1] + colWidths[2]];

        doc.setFillColor(15, 23, 42);
        doc.rect(margin, y, contentWidth, 7, 'F');
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.text('Severity', colX[0] + 2, y + 5);
        doc.text('Title', colX[1] + 2, y + 5);
        doc.text('File', colX[2] + 2, y + 5);
        doc.text('Scanner', colX[3] + 2, y + 5);
        y += 7;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7);

        const sevColors: Record<string, [number, number, number]> = {
          critical: [220, 38, 38],
          high: [249, 115, 22],
          medium: [234, 179, 8],
          low: [148, 163, 184],
          info: [100, 116, 139],
        };

        findingsList.forEach((finding, idx) => {
          checkPageBreak(8);

          // Alternating row bg
          if (idx % 2 === 0) {
            doc.setFillColor(248, 250, 252);
            doc.rect(margin, y, contentWidth, 6.5, 'F');
          }

          const sev = String(finding.severity || 'info').toLowerCase();
          const sevColor = sevColors[sev] || sevColors.info;
          doc.setTextColor(sevColor[0], sevColor[1], sevColor[2]);
          doc.setFont('helvetica', 'bold');
          doc.text(sev.toUpperCase(), colX[0] + 2, y + 4.5);

          doc.setTextColor(30, 41, 59);
          doc.setFont('helvetica', 'normal');
          const title = String(finding.title || '').slice(0, 45);
          doc.text(title, colX[1] + 2, y + 4.5);

          doc.setTextColor(100, 116, 139);
          const filePath = String(finding.filePath || finding.file_path || finding.file || '');
          const shortPath = filePath.length > 40 ? '...' + filePath.slice(-37) : filePath;
          doc.text(shortPath, colX[2] + 2, y + 4.5);

          const scanner = String(finding.scanner || finding.toolName || finding.tool_name || '');
          doc.text(scanner, colX[3] + 2, y + 4.5);

          y += 6.5;
        });

        y += 6;
      }

      // --- Footer on each page ---
      const totalPages = doc.getNumberOfPages();
      for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i);
        doc.setDrawColor(226, 232, 240);
        doc.setLineWidth(0.3);
        doc.line(margin, pageHeight - 15, pageWidth - margin, pageHeight - 15);
        doc.setFontSize(8);
        doc.setTextColor(148, 163, 184);
        doc.setFont('helvetica', 'normal');
        doc.text('Code Hardener Security Report — Confidential', margin, pageHeight - 10);
        doc.text(`Page ${i} of ${totalPages}`, pageWidth - margin, pageHeight - 10, { align: 'right' });
      }

      const safeTitle = (report.title || 'report').replace(/[^a-zA-Z0-9-_ ]/g, '');
      doc.save(`${safeTitle}.pdf`);
    } catch (err) {
      console.error('Failed to generate PDF:', err);
      alert('Failed to generate PDF report');
    }
  };

  const handlePrint = () => {
    window.print();
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-error bg-error/10';
      case 'high':
        return 'text-orange-400 bg-orange-400/10';
      case 'medium':
        return 'text-warning bg-warning/10';
      case 'low':
        return 'text-text-tertiary bg-bg-tertiary';
      default:
        return 'text-text-secondary bg-bg-tertiary';
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <AlertCircle className="h-12 w-12 text-error mb-4" />
        <h2 className="text-xl font-semibold text-text-primary mb-2">Failed to load report</h2>
        <p className="text-text-secondary mb-4">{error}</p>
        <button
          onClick={fetchReport}
          className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors"
        >
          Try Again
        </button>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <FileText className="h-12 w-12 text-text-tertiary mb-4" />
        <h2 className="text-xl font-semibold text-text-primary mb-2">Report not found</h2>
        <p className="text-text-secondary mb-4">The report you're looking for doesn't exist.</p>
        <Link href="/reports" className="btn-primary">
          Back to Reports
        </Link>
      </div>
    );
  }

  const maxFindingsInProject = Math.max(
    ...(report.projectBreakdown || []).map(p => p.critical + p.high + p.medium + p.low),
    1
  );

  return (
    <div className="space-y-6">
      {/* Back Link */}
      <Link
        href="/reports"
        className="flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary"
      >
        <ArrowLeft size={16} />
        Back to Reports
      </Link>

      {/* Report Header */}
      <div className="card p-6">
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-lg bg-primary-500/10 flex items-center justify-center">
              <FileText size={24} className="text-primary-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-text-primary">{report.title}</h1>
              <div className="flex items-center gap-4 mt-2 text-sm text-text-secondary">
                <div className="flex items-center gap-1.5">
                  <Calendar size={14} />
                  Generated: {formatDate(report.generatedAt || report.createdAt)}
                </div>
                <span className="text-xs px-2 py-1 rounded-full bg-primary-500/10 text-primary-400 font-medium">
                  {reportTypeLabels[report.reportType] || report.reportType}
                </span>
                <div className="flex items-center gap-1.5">
                  <Building2 size={14} />
                  Scope: {report.projectName || 'All Projects'}
                </div>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleDownload}
              className="btn-secondary flex items-center gap-2"
            >
              <Download size={16} />
              Download PDF
            </button>
            <button
              onClick={handlePrint}
              className="btn-secondary flex items-center gap-2"
            >
              <Printer size={16} />
              Print
            </button>
            <button
              onClick={() => setShowShareModal(true)}
              className="btn-secondary flex items-center gap-2"
            >
              <Share2 size={16} />
              Share
            </button>
          </div>
        </div>
      </div>

      {/* Executive Summary */}
      {report.summary && (
        <div className="card p-6">
          <h2 className="text-lg font-semibold text-text-primary mb-4 flex items-center gap-2">
            <Shield size={20} className="text-primary-400" />
            Executive Summary
          </h2>

          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            {/* Score Gauge */}
            <div className="lg:col-span-1 flex flex-col items-center justify-center">
              <ScoreGauge score={report.summary.overallScore} size="lg" />
              <p className="text-sm text-text-tertiary mt-2">Overall Security Score</p>
            </div>

            {/* Key Metrics */}
            <div className="lg:col-span-3 grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-bg-tertiary rounded-lg p-4">
                <div className="text-2xl font-bold text-text-primary">
                  {report.summary.projectsScanned}
                </div>
                <div className="text-sm text-text-secondary">Projects Scanned</div>
              </div>
              <div className="bg-bg-tertiary rounded-lg p-4">
                <div className="text-2xl font-bold text-text-primary">
                  {report.summary.totalFindings}
                </div>
                <div className="text-sm text-text-secondary">Total Findings</div>
              </div>
              <div className="bg-bg-tertiary rounded-lg p-4">
                <div className="flex items-center gap-2">
                  <span className="text-2xl font-bold text-error">{report.summary.criticalCount}</span>
                  <span className="text-sm text-text-tertiary">Critical</span>
                </div>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-lg font-semibold text-orange-400">{report.summary.highCount}</span>
                  <span className="text-sm text-text-tertiary">High</span>
                </div>
              </div>
              <div className="bg-bg-tertiary rounded-lg p-4">
                <div className="flex items-center gap-2">
                  <span className="text-2xl font-bold text-warning">{report.summary.mediumCount}</span>
                  <span className="text-sm text-text-tertiary">Medium</span>
                </div>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-lg font-semibold text-text-tertiary">{report.summary.lowCount}</span>
                  <span className="text-sm text-text-tertiary">Low</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Findings by Project */}
      {report.projectBreakdown && report.projectBreakdown.length > 0 && (
        <div className="card p-6">
          <h2 className="text-lg font-semibold text-text-primary mb-4 flex items-center gap-2">
            <BarChart3 size={20} className="text-primary-400" />
            Findings by Project
          </h2>

          <div className="space-y-4">
            {report.projectBreakdown.map((project, index) => {
            const total = project.critical + project.high + project.medium + project.low;
            const widthPercent = (total / maxFindingsInProject) * 100;

            return (
              <div key={index}>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-sm font-medium text-text-primary">{project.projectName}</span>
                  <span className="text-sm text-text-tertiary">{total} findings</span>
                </div>
                <div className="h-6 bg-bg-tertiary rounded-lg overflow-hidden flex" style={{ width: `${widthPercent}%`, minWidth: '100px' }}>
                  {project.critical > 0 && (
                    <div
                      className="h-full bg-error flex items-center justify-center text-xs text-white font-medium"
                      style={{ width: `${(project.critical / total) * 100}%` }}
                      title={`${project.critical} critical`}
                    >
                      {project.critical}
                    </div>
                  )}
                  {project.high > 0 && (
                    <div
                      className="h-full bg-orange-500 flex items-center justify-center text-xs text-white font-medium"
                      style={{ width: `${(project.high / total) * 100}%` }}
                      title={`${project.high} high`}
                    >
                      {project.high}
                    </div>
                  )}
                  {project.medium > 0 && (
                    <div
                      className="h-full bg-warning flex items-center justify-center text-xs text-bg-primary font-medium"
                      style={{ width: `${(project.medium / total) * 100}%` }}
                      title={`${project.medium} medium`}
                    >
                      {project.medium}
                    </div>
                  )}
                  {project.low > 0 && (
                    <div
                      className="h-full bg-bg-hover flex items-center justify-center text-xs text-text-tertiary font-medium"
                      style={{ width: `${(project.low / total) * 100}%` }}
                      title={`${project.low} low`}
                    >
                      {project.low}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>

          {/* Legend */}
          <div className="flex items-center gap-4 mt-4 pt-4 border-t border-border-primary">
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded bg-error" />
              <span className="text-xs text-text-tertiary">Critical</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded bg-orange-500" />
              <span className="text-xs text-text-tertiary">High</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded bg-warning" />
              <span className="text-xs text-text-tertiary">Medium</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded bg-bg-hover" />
              <span className="text-xs text-text-tertiary">Low</span>
            </div>
          </div>
        </div>
      )}

      {/* Critical & High Findings */}
      {report.findings && report.findings.length > 0 && (
        <div className="card p-6">
          <h2 className="text-lg font-semibold text-text-primary mb-4 flex items-center gap-2">
            <AlertTriangle size={20} className="text-error" />
            Critical & High Findings
          </h2>

          <div className="space-y-3">
            {report.findings.map((finding, index) => (
              <div
                key={finding.id}
                className="flex items-start gap-4 p-4 bg-bg-tertiary rounded-lg"
              >
                <div className="flex items-center justify-center w-8 h-8 rounded-full bg-bg-secondary text-text-tertiary font-medium">
                  {index + 1}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={cn(
                      'text-xs px-2 py-0.5 rounded-full font-medium uppercase',
                      getSeverityColor(finding.severity)
                    )}>
                      {finding.severity}
                    </span>
                    <span className="font-medium text-text-primary">{finding.title}</span>
                  </div>
                  <div className="text-sm text-text-secondary mt-1">
                    {finding.projectName}
                  </div>
                  <div className="font-mono text-xs text-text-tertiary mt-1">
                    {finding.file}:{finding.line}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Trend Analysis */}
      {report.trendData && report.trendData.length > 0 && (
        <div className="card p-6">
          <h2 className="text-lg font-semibold text-text-primary mb-4 flex items-center gap-2">
            <TrendingUp size={20} className="text-success" />
            Trend Analysis
          </h2>

          {/* Simple trend visualization */}
          <div className="h-48 flex items-end gap-2">
            {report.trendData.map((point, index) => {
              const scoreHeight = (point.score / 1000) * 100;
              const isLast = index === report.trendData!.length - 1;

              return (
                <div key={point.date} className="flex-1 flex flex-col items-center">
                  <div className="w-full flex flex-col items-center gap-1 flex-1 justify-end">
                    <span className={cn(
                      'text-xs font-medium',
                      isLast ? 'text-primary-400' : 'text-text-tertiary'
                    )}>
                      {point.score}
                    </span>
                    <div
                      className={cn(
                        'w-full rounded-t-lg transition-all',
                        isLast ? 'bg-primary-500' : 'bg-primary-500/40'
                      )}
                      style={{ height: `${scoreHeight}%` }}
                    />
                  </div>
                  <span className="text-xs text-text-tertiary mt-2">
                    {new Date(point.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                  </span>
                </div>
              );
            })}
          </div>

          <div className="mt-4 pt-4 border-t border-border-primary">
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <div className="text-lg font-semibold text-success">+40</div>
                <div className="text-xs text-text-tertiary">Score Improvement</div>
              </div>
              <div>
                <div className="text-lg font-semibold text-success">-15</div>
                <div className="text-xs text-text-tertiary">Findings Reduced</div>
              </div>
              <div>
                <div className="text-lg font-semibold text-primary-400">24%</div>
                <div className="text-xs text-text-tertiary">Remediation Rate</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Share Modal */}
      {showShareModal && (
        <ShareModal
          reportName={report.title}
          reportId={report.id}
          onClose={() => setShowShareModal(false)}
        />
      )}
    </div>
  );
}

interface ShareModalProps {
  reportName: string;
  reportId: string;
  onClose: () => void;
}

function ShareModal({ reportName, reportId, onClose }: ShareModalProps) {
  const [copied, setCopied] = useState(false);
  const shareUrl = `https://app.codehardener.com/reports/${reportId}/public`;

  const handleCopy = async () => {
    await navigator.clipboard.writeText(shareUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-secondary rounded-lg border border-border-primary w-full max-w-md">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-border-primary">
          <h2 className="text-lg font-semibold text-text-primary">Share Report</h2>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-bg-tertiary transition-colors"
          >
            <X size={20} className="text-text-tertiary" />
          </button>
        </div>

        {/* Content */}
        <div className="p-4 space-y-4">
          <p className="text-sm text-text-secondary">
            Share a public link to &quot;{reportName}&quot;
          </p>

          <div className="flex items-center gap-2">
            <input
              type="text"
              value={shareUrl}
              readOnly
              className="input flex-1 text-sm font-mono"
            />
            <button
              onClick={handleCopy}
              className="btn-secondary flex items-center gap-2"
            >
              {copied ? (
                <>
                  <Check size={16} className="text-success" />
                  Copied
                </>
              ) : (
                <>
                  <Copy size={16} />
                  Copy
                </>
              )}
            </button>
          </div>

          <div className="p-3 bg-warning/10 border border-warning/20 rounded-lg">
            <p className="text-sm text-warning">
              Anyone with this link can view this report. The link does not expire.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end p-4 border-t border-border-primary">
          <button onClick={onClose} className="btn-primary">
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
