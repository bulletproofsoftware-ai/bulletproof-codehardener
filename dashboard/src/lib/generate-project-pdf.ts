import { jsPDF } from 'jspdf';
import { formatDate, formatDateTime } from '@/lib/utils';

// ── Types ──

interface ProjectScan {
  id: string;
  score?: number | null;
  status: string;
  scanType?: string;
  createdAt: string;
  completedAt?: string;
  duration?: number;
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

interface ProjectFinding {
  id: string;
  severity: string;
  status: string;
  scanner: string;
}

interface ProjectData {
  id: string;
  name: string;
  description?: string;
  repositoryUrl?: string;
  createdAt: string;
  lastScore?: number | null;
  scans: ProjectScan[];
  findings: ProjectFinding[];
}

// ── Colors ──

type RGB = [number, number, number];

const C = {
  darkBg: [15, 23, 42] as RGB,
  accent: [56, 189, 248] as RGB,
  white: [255, 255, 255] as RGB,
  gray: [100, 116, 139] as RGB,
  darkText: [30, 41, 59] as RGB,
  lightBg: [248, 250, 252] as RGB,
  border: [226, 232, 240] as RGB,
  success: [34, 197, 94] as RGB,
  error: [220, 38, 38] as RGB,
  warning: [234, 179, 8] as RGB,
  orange: [249, 115, 22] as RGB,
  info: [148, 163, 184] as RGB,
};

function scoreColor(score: number): RGB {
  if (score >= 900) return C.success;
  if (score >= 700) return C.accent;
  if (score >= 500) return C.warning;
  return C.error;
}

function fmtDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remaining = seconds % 60;
  return `${minutes}m ${remaining}s`;
}

// ── Main Export ──

export function generateProjectPDF(project: ProjectData) {
  try {
    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const pw = doc.internal.pageSize.getWidth();
    const ph = doc.internal.pageSize.getHeight();
    const m = 20;
    const cw = pw - m * 2;
    let y = m;

    const pgBreak = (needed: number) => {
      if (y + needed > ph - m) {
        doc.addPage();
        y = m;
      }
    };

    const sectionTitle = (title: string, fontSize = 14) => {
      pgBreak(15);
      doc.setFontSize(fontSize);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...C.darkBg);
      doc.text(title, m, y);
      y += 8;
    };

    const divider = () => {
      doc.setDrawColor(...C.border);
      doc.setLineWidth(0.5);
      doc.line(m, y, pw - m, y);
      y += 8;
    };

    // Completed scans sorted chronologically
    const completedScans = project.scans
      .filter(s => s.status === 'completed' && s.score != null)
      .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime());

    const latestScan = completedScans.length > 0
      ? completedScans[completedScans.length - 1]
      : null;

    const currentScore = latestScan?.score ?? project.lastScore ?? 0;
    const firstScanDate = completedScans.length > 0
      ? formatDate(completedScans[0].createdAt)
      : 'N/A';
    const lastScanDate = latestScan ? formatDate(latestScan.createdAt) : 'N/A';

    // ════════════════════════════════════════════
    // Cover Page
    // ════════════════════════════════════════════
    doc.setFillColor(...C.darkBg);
    doc.rect(0, 0, pw, 55, 'F');
    doc.setFillColor(...C.accent);
    doc.rect(0, 55, pw, 2, 'F');

    doc.setTextColor(...C.white);
    doc.setFontSize(22);
    doc.setFont('helvetica', 'bold');
    doc.text('Code Hardener', m, 22);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    doc.text('Project Report', m, 30);
    doc.setFontSize(9);
    doc.text(`Generated: ${formatDateTime(new Date().toISOString())}`, pw - m, 22, { align: 'right' });

    y = 70;

    // Project name
    doc.setTextColor(...C.darkBg);
    doc.setFontSize(20);
    doc.setFont('helvetica', 'bold');
    doc.text(project.name, m, y);
    y += 8;

    if (project.description) {
      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...C.gray);
      const descLines = doc.splitTextToSize(project.description, cw);
      doc.text(descLines.slice(0, 3), m, y);
      y += Math.min(descLines.length, 3) * 5 + 4;
    }

    if (project.repositoryUrl) {
      doc.setFontSize(9);
      doc.setTextColor(...C.accent);
      doc.text(project.repositoryUrl, m, y);
      y += 6;
    }

    y += 4;

    // Summary stats box
    doc.setFillColor(...C.lightBg);
    doc.roundedRect(m, y, cw, 28, 2, 2, 'F');

    const statCols = [
      { label: 'Current Score', value: String(currentScore), color: scoreColor(currentScore) },
      { label: 'Total Scans', value: String(project.scans.length), color: C.darkText },
      { label: 'First Scan', value: firstScanDate, color: C.darkText },
      { label: 'Latest Scan', value: lastScanDate, color: C.darkText },
    ];

    const statW = cw / statCols.length;
    statCols.forEach((stat, i) => {
      const cx = m + statW * i + statW / 2;
      doc.setFontSize(16);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...stat.color);
      doc.text(stat.value, cx, y + 12, { align: 'center' });
      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...C.gray);
      doc.text(stat.label, cx, y + 20, { align: 'center' });
    });

    y += 36;
    divider();

    // ════════════════════════════════════════════
    // Score Trend Table
    // ════════════════════════════════════════════
    if (completedScans.length > 0) {
      sectionTitle('Score Trend');

      // Table header
      pgBreak(10);
      const cols = [m, m + 10, m + 50, m + 72, m + 92, m + 108, m + 124, m + 140];
      doc.setFillColor(...C.darkBg);
      doc.rect(m, y, cw, 7, 'F');
      doc.setTextColor(...C.white);
      doc.setFontSize(7.5);
      doc.setFont('helvetica', 'bold');
      doc.text('#', cols[0] + 2, y + 5);
      doc.text('Date', cols[1] + 2, y + 5);
      doc.text('Score', cols[2] + 2, y + 5);
      doc.text('Delta', cols[3] + 2, y + 5);
      doc.text('Critical', cols[4] + 2, y + 5);
      doc.text('High', cols[5] + 2, y + 5);
      doc.text('Medium', cols[6] + 2, y + 5);
      doc.text('Low', cols[7] + 2, y + 5);
      y += 7;

      completedScans.forEach((scan, idx) => {
        pgBreak(7);
        if (idx % 2 === 0) {
          doc.setFillColor(...C.lightBg);
          doc.rect(m, y, cw, 6.5, 'F');
        }

        const prevScore = idx > 0 ? completedScans[idx - 1].score ?? 0 : null;
        const delta = prevScore !== null ? (scan.score ?? 0) - prevScore : null;
        const sc = scoreColor(scan.score ?? 0);

        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...C.darkText);
        doc.text(String(idx + 1), cols[0] + 2, y + 4.5);
        doc.text(formatDate(scan.createdAt), cols[1] + 2, y + 4.5);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...sc);
        doc.text(String(scan.score ?? 0), cols[2] + 2, y + 4.5);

        doc.setFont('helvetica', 'normal');
        if (delta !== null) {
          const deltaColor: RGB = delta > 0 ? C.success : delta < 0 ? C.error : C.gray;
          doc.setTextColor(...deltaColor);
          doc.text(delta > 0 ? `+${delta}` : String(delta), cols[3] + 2, y + 4.5);
        } else {
          doc.setTextColor(...C.gray);
          doc.text('-', cols[3] + 2, y + 4.5);
        }

        doc.setTextColor(...(scan.findingsCount.critical > 0 ? C.error : C.gray));
        doc.text(String(scan.findingsCount.critical), cols[4] + 2, y + 4.5);
        doc.setTextColor(...(scan.findingsCount.high > 0 ? C.orange : C.gray));
        doc.text(String(scan.findingsCount.high), cols[5] + 2, y + 4.5);
        doc.setTextColor(...(scan.findingsCount.medium > 0 ? C.warning : C.gray));
        doc.text(String(scan.findingsCount.medium), cols[6] + 2, y + 4.5);
        doc.setTextColor(...C.gray);
        doc.text(String(scan.findingsCount.low), cols[7] + 2, y + 4.5);

        y += 6.5;
      });

      y += 6;
    }

    // ════════════════════════════════════════════
    // Resolution Summary
    // ════════════════════════════════════════════
    if (project.findings.length > 0) {
      pgBreak(30);
      divider();
      sectionTitle('Resolution Summary');

      const totalFindings = project.findings.length;
      const openFindings = project.findings.filter(f => f.status === 'open').length;
      const fixedFindings = project.findings.filter(f => f.status === 'fixed').length;
      const ignoredFindings = project.findings.filter(f => f.status === 'ignored' || f.status === 'false_positive').length;
      const resolutionRate = totalFindings > 0 ? Math.round(((fixedFindings + ignoredFindings) / totalFindings) * 100) : 0;

      doc.setFillColor(...C.lightBg);
      doc.roundedRect(m, y, cw, 24, 2, 2, 'F');

      const resCols = [
        { label: 'Total Detected', value: String(totalFindings), color: C.darkText },
        { label: 'Open', value: String(openFindings), color: openFindings > 0 ? C.warning : C.success },
        { label: 'Fixed', value: String(fixedFindings), color: C.success },
        { label: 'Dismissed', value: String(ignoredFindings), color: C.gray },
        { label: 'Resolution Rate', value: `${resolutionRate}%`, color: resolutionRate >= 80 ? C.success : resolutionRate >= 50 ? C.warning : C.error },
      ];

      const resW = cw / resCols.length;
      resCols.forEach((stat, i) => {
        const cx = m + resW * i + resW / 2;
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...stat.color);
        doc.text(stat.value, cx, y + 10, { align: 'center' });
        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...C.gray);
        doc.text(stat.label, cx, y + 17, { align: 'center' });
      });

      y += 32;

      // Severity breakdown
      pgBreak(20);
      const sevGroups = ['critical', 'high', 'medium', 'low', 'info'] as const;
      const sevColors: Record<string, RGB> = {
        critical: C.error,
        high: C.orange,
        medium: C.warning,
        low: C.info,
        info: C.gray,
      };

      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...C.darkText);
      doc.text('By Severity', m, y);
      y += 6;

      for (const sev of sevGroups) {
        const count = project.findings.filter(f => f.severity === sev).length;
        if (count === 0) continue;

        pgBreak(6);
        const openCount = project.findings.filter(f => f.severity === sev && f.status === 'open').length;

        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...sevColors[sev]);
        doc.text(`${sev.toUpperCase()}:`, m + 2, y);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...C.darkText);
        doc.text(`${count} total, ${openCount} open`, m + 30, y);
        y += 5;
      }

      y += 4;
    }

    // ════════════════════════════════════════════
    // Scanner Coverage
    // ════════════════════════════════════════════
    if (project.findings.length > 0) {
      pgBreak(20);
      divider();
      sectionTitle('Scanner Coverage');

      const scannerCounts: Record<string, { total: number; open: number }> = {};
      project.findings.forEach(f => {
        if (!scannerCounts[f.scanner]) scannerCounts[f.scanner] = { total: 0, open: 0 };
        scannerCounts[f.scanner].total++;
        if (f.status === 'open') scannerCounts[f.scanner].open++;
      });

      const sortedScanners = Object.entries(scannerCounts)
        .sort(([, a], [, b]) => b.total - a.total);

      // Table header
      pgBreak(10);
      doc.setFillColor(...C.darkBg);
      doc.rect(m, y, cw, 7, 'F');
      doc.setTextColor(...C.white);
      doc.setFontSize(7.5);
      doc.setFont('helvetica', 'bold');
      doc.text('Scanner', m + 2, y + 5);
      doc.text('Total Findings', m + 60, y + 5);
      doc.text('Open', m + 100, y + 5);
      doc.text('Resolved', m + 125, y + 5);
      y += 7;

      sortedScanners.forEach(([scanner, counts], idx) => {
        pgBreak(7);
        if (idx % 2 === 0) {
          doc.setFillColor(...C.lightBg);
          doc.rect(m, y, cw, 6.5, 'F');
        }
        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...C.darkText);
        doc.text(scanner, m + 2, y + 4.5);
        doc.text(String(counts.total), m + 60, y + 4.5);
        doc.setTextColor(...(counts.open > 0 ? C.warning : C.success));
        doc.text(String(counts.open), m + 100, y + 4.5);
        doc.setTextColor(...C.success);
        doc.text(String(counts.total - counts.open), m + 125, y + 4.5);
        y += 6.5;
      });

      y += 6;
    }

    // ════════════════════════════════════════════
    // Latest Scan Summary
    // ════════════════════════════════════════════
    if (latestScan) {
      pgBreak(30);
      divider();
      sectionTitle('Latest Scan Summary');

      const details: [string, string][] = [
        ['Scan ID', latestScan.id.slice(0, 8) + '...'],
        ['Type', String(latestScan.scanType || 'standard')],
        ['Date', formatDateTime(latestScan.createdAt)],
        ['Duration', latestScan.duration ? fmtDuration(latestScan.duration) : 'N/A'],
        ['Score', String(latestScan.score ?? 0) + ' / 1000'],
      ];

      doc.setFontSize(10);
      for (const [label, value] of details) {
        pgBreak(6);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...C.gray);
        doc.text(`${label}:`, m, y);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...C.darkText);
        doc.text(value, m + 40, y);
        y += 5.5;
      }

      y += 4;

      // Finding counts for latest scan
      pgBreak(20);
      doc.setFillColor(...C.lightBg);
      doc.roundedRect(m, y, cw, 20, 2, 2, 'F');

      const fc = latestScan.findingsCount;
      const sevs = [
        { label: 'Critical', count: fc.critical, color: C.error },
        { label: 'High', count: fc.high, color: C.orange },
        { label: 'Medium', count: fc.medium, color: C.warning },
        { label: 'Low', count: fc.low, color: C.info },
        { label: 'Info', count: fc.info, color: C.gray },
      ];
      const bw = cw / sevs.length;
      sevs.forEach((s, i) => {
        const cx = m + bw * i + bw / 2;
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...s.color);
        doc.text(String(s.count), cx, y + 9, { align: 'center' });
        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...C.gray);
        doc.text(s.label, cx, y + 15, { align: 'center' });
      });

      y += 28;
    }

    // ════════════════════════════════════════════
    // Page Footers
    // ════════════════════════════════════════════
    const totalPages = doc.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i);
      doc.setDrawColor(...C.border);
      doc.setLineWidth(0.3);
      doc.line(m, ph - 15, pw - m, ph - 15);
      doc.setFontSize(8);
      doc.setTextColor(148, 163, 184);
      doc.setFont('helvetica', 'normal');
      doc.text(`Code Hardener — ${project.name} — Project Report`, m, ph - 10);
      doc.text(`Page ${i} of ${totalPages}`, pw - m, ph - 10, { align: 'right' });
    }

    doc.save(`Project-${project.name.replace(/[^a-zA-Z0-9]/g, '-')}-Report.pdf`);
  } catch (err) {
    console.error('Project PDF generation failed:', err);
    alert('Failed to generate project report');
  }
}
