import { jsPDF } from 'jspdf';
import { formatDate, formatDateTime } from '@/lib/utils';

// ── Types ──

interface SBOMPackage {
  name: string;
  version: string;
  type: string;
  language: string;
  license: string;
}

interface ScannerEvidence {
  filesAnalyzed?: number;
  rulesEvaluated?: number;
  checksPerformed?: string[];
  scanScope?: string;
  toolVersion?: string;
  detectionMethod?: string;
  configuration?: string;
  targetsAnalyzed?: string[];
  methodology?: string;
  standards?: string[];
  displayName?: string;
  category?: string;
  sbomPackages?: SBOMPackage[];
}

interface ScannerResult {
  scanner: string;
  status: 'success' | 'error' | 'skipped';
  findingsCount: number;
  duration: number;
  filesScanned: number;
  error?: string;
  evidence?: ScannerEvidence;
}

interface ScannedFile {
  path: string;
  findingsCount: number;
  scanners: string[];
}

interface ScanFinding {
  id: string;
  title: string;
  severity: string;
  scanner: string;
  filePath: string;
  line: number;
  cwe?: string;
  code: string;
  status: string;
  description: string;
  fixDescription?: string;
  fixAvailable?: boolean;
  owaspCategory?: string;
  ruleId?: string;
}

export interface AttestationData {
  id: string;
  scanId: string;
  attestationType: string;
  subjectName: string;
  subjectDigest: string;
  signature: string | null;
  signatureAlgorithm: string | null;
  certificate: string | null;
  rekorLogId: string | null;
  transparencyLogUrl: string | null;
  createdAt: string;
}

interface FileInventory {
  totalFiles: number;
  breakdown: string[];
  extensions: string[];
}

interface ScanData {
  id: string;
  projectName: string;
  branch?: string;
  status: string;
  startedAt?: string;
  completedAt?: string;
  createdAt: string;
  duration?: number;
  score?: number | null;
  qualityLevel?: string;
  scanType?: string;
  findingsCount?: { critical: number; high: number; medium: number; low: number; info: number };
  scannerResults?: ScannerResult[];
  filesScanned?: ScannedFile[];
  fileInventory?: FileInventory;
}

// ── Constants ──

const SCANNER_META: Record<string, { category: string; description: string }> = {
  // SAST
  opengrep: { category: 'SAST', description: 'Multi-language static analysis for security vulnerabilities' },
  bandit: { category: 'SAST', description: 'Python-specific security linter for common vulnerabilities' },
  gosec: { category: 'SAST', description: 'Go source code security analyzer' },
  'eslint-security': { category: 'SAST', description: 'JavaScript/TypeScript security linting rules' },
  pmd: { category: 'SAST', description: 'Multi-language static analysis for code quality and security' },
  // DAST
  nuclei: { category: 'DAST', description: 'Dynamic application security testing with vulnerability templates' },
  zap: { category: 'DAST', description: 'OWASP ZAP dynamic application security testing' },
  // SCA
  trivy: { category: 'SCA', description: 'Container image and filesystem vulnerability scanner' },
  grype: { category: 'SCA', description: 'Dependency vulnerability scanner for containers and filesystems' },
  // Secrets
  gitleaks: { category: 'Secrets', description: 'Detects hardcoded secrets and credentials in git repos' },
  // IaC
  checkov: { category: 'IaC', description: 'Infrastructure-as-code security scanner for Dockerfiles, Terraform, K8s' },
  // Load Testing
  locust: { category: 'Load Testing', description: 'Python-based load testing framework' },
  artillery: { category: 'Load Testing', description: 'Modern load testing and performance measurement' },
  k6: { category: 'Load Testing', description: 'Modern load testing tool for engineering teams' },
  // API Testing
  newman: { category: 'API Testing', description: 'Postman collection runner for API testing' },
  pact: { category: 'API Testing', description: 'Consumer-driven contract testing' },
  restler: { category: 'API Testing', description: 'Stateful REST API fuzzing tool' },
  schemathesis: { category: 'API Testing', description: 'Schema-driven API testing and validation' },
  // Browser/Visual/Accessibility
  playwright: { category: 'Browser Testing', description: 'End-to-end browser testing framework' },
  backstop: { category: 'Visual Testing', description: 'Visual regression testing for web UIs' },
  pa11y: { category: 'Accessibility', description: 'Automated accessibility testing (WCAG 2.1)' },
  // Supply Chain
  syft: { category: 'SBOM', description: 'Software bill of materials generator for supply chain visibility' },
  cosign: { category: 'Supply Chain', description: 'Container image signing and verification' },
  // Container
  dockle: { category: 'Container', description: 'Container image linter for CIS Docker benchmarks' },
  // Policy & Reporting
  opa: { category: 'Policy', description: 'Open Policy Agent policy evaluation engine' },
  conftest: { category: 'Policy', description: 'Policy testing for structured configuration data' },
  // Runtime/Chaos
  toxiproxy: { category: 'Chaos Testing', description: 'Chaos/resilience testing configuration analysis' },
  // AI Code Quality
  'llm-guard': { category: 'AI Security', description: 'Input/output guardrails for LLM applications' },
  'package-validator': { category: 'AI Code Quality', description: 'Detects hallucinated packages in dependency files' },
  stryker: { category: 'AI Code Quality', description: 'JavaScript/TypeScript mutation testing' },
  mutmut: { category: 'AI Code Quality', description: 'Python mutation testing for test quality' },
  pitest: { category: 'AI Code Quality', description: 'Java/JVM mutation testing for test quality' },
  scancode: { category: 'AI Code Quality', description: 'Snippet-level license detection for copyleft contamination' },
  aflpp: { category: 'AI Code Quality', description: 'Coverage-guided fuzz testing for C/C++ memory safety' },
  keploy: { category: 'API Testing', description: 'Record-replay API test coverage analysis' },
  deepeval: { category: 'AI Code Quality', description: 'LLM-as-Judge heuristic code analysis' },
  threatmodel: { category: 'Threat Modeling', description: 'STRIDE automated threat modeling' },
  jest: { category: 'Test Runners', description: 'JavaScript/TypeScript test execution and coverage' },
  pytest: { category: 'Test Runners', description: 'Python test execution and coverage' },
  // v2 additions
  lychee: { category: 'Code Quality', description: 'Broken link detection in documentation and HTML files' },
  'axe-core': { category: 'DAST', description: 'WCAG 2.1 accessibility compliance testing via axe-core' },
  c8: { category: 'Test Runners', description: 'Code coverage measurement and threshold enforcement' },
  'fast-check': { category: 'Test Runners', description: 'JavaScript/TypeScript property-based testing' },
  hypothesis: { category: 'Test Runners', description: 'Python property-based testing with automatic shrinking' },
  sqlmap: { category: 'DAST', description: 'SQL injection detection and exploitation testing' },
  dalfox: { category: 'DAST', description: 'Cross-site scripting (XSS) vulnerability scanning' },
  ffuf: { category: 'DAST', description: 'Web endpoint discovery and directory fuzzing' },
  socket: { category: 'SCA', description: 'Supply chain attack detection for npm/PyPI packages' },
  giskard: { category: 'AI Code Quality', description: 'LLM prompt injection and data leakage testing' },
  // Code Quality & Dead Code
  knip: { category: 'Code Quality', description: 'JS/TS dead code and unused dependency detection' },
  oxlint: { category: 'Code Quality', description: 'High-performance JavaScript/TypeScript linter' },
  jscpd: { category: 'Code Quality', description: 'Cross-language copy-paste detection' },
  ruff: { category: 'Code Quality', description: 'Ultra-fast Python linter (pyflakes, pycodestyle, flake8-bandit)' },
  phpstan: { category: 'SAST', description: 'PHP static analysis for finding bugs' },
  typos: { category: 'Code Quality', description: 'Source code spell checker' },
  vale: { category: 'Code Quality', description: 'Documentation prose linter' },
  libyear: { category: 'SCA', description: 'Dependency freshness scoring' },
  'dotenv-linter': { category: 'Code Quality', description: '.env file linter' },
  // CI/CD Security
  actionlint: { category: 'CI/CD Security', description: 'GitHub Actions workflow linter' },
  poutine: { category: 'CI/CD Security', description: 'CI/CD pipeline security scanner' },
  scorecard: { category: 'Supply Chain', description: 'OpenSSF supply chain security scoring' },
  // K8s
  kubeconform: { category: 'IaC', description: 'Kubernetes manifest validation' },
  'kube-linter': { category: 'IaC', description: 'Kubernetes security linting' },
  // Additional SCA
  'cargo-audit': { category: 'SCA', description: 'Rust dependency vulnerability scanning' },
  spectral: { category: 'API Testing', description: 'OpenAPI/AsyncAPI spec linting' },
  'license-finder': { category: 'Compliance', description: 'Dependency license compliance checker' },
  cdxgen: { category: 'SBOM', description: 'CycloneDX SBOM generator' },
};

// ── Helpers ──

type RGB = [number, number, number];

function fmtDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remaining = seconds % 60;
  return `${minutes}m ${remaining}s`;
}

// Colors
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

function sevColor(sev: string): RGB {
  const s = sev.toLowerCase();
  if (s === 'critical') return C.error;
  if (s === 'high') return C.orange;
  if (s === 'medium') return C.warning;
  if (s === 'low') return C.info;
  return C.gray;
}

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ── Main Export ──

export function generateComprehensivePDF(scan: ScanData, allFindings: ScanFinding[], attestation?: AttestationData | null) {
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

    // Helper to draw a section title
    const sectionTitle = (title: string, fontSize = 14) => {
      pgBreak(15);
      doc.setFontSize(fontSize);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...C.darkBg);
      doc.text(title, m, y);
      y += 8;
    };

    // Helper for divider
    const divider = () => {
      doc.setDrawColor(...C.border);
      doc.setLineWidth(0.5);
      doc.line(m, y, pw - m, y);
      y += 8;
    };

    // ════════════════════════════════════════════
    // ATTESTATION COVER PAGE (when available)
    // ════════════════════════════════════════════
    if (attestation) {
      // Dark header bar
      doc.setFillColor(...C.darkBg);
      doc.rect(0, 0, pw, 50, 'F');
      doc.setFillColor(...C.accent);
      doc.rect(0, 50, pw, 2, 'F');

      // Score ring gauge
      const gaugeCx = pw / 2;
      const gaugeCy = 80;
      const gaugeR = 18;
      const gaugeScore = scan.score ?? 0;
      const gaugePct = gaugeScore / 1000;
      const gaugeColor: RGB = gaugeScore >= 900 ? C.success : gaugeScore >= 700 ? C.accent : gaugeScore >= 500 ? C.warning : C.error;

      // Background ring (gray)
      doc.setDrawColor(200, 200, 200);
      doc.setLineWidth(3);
      doc.circle(gaugeCx, gaugeCy, gaugeR, 'S');

      // Colored arc — approximate with short line segments
      if (gaugePct > 0) {
        doc.setDrawColor(...gaugeColor);
        doc.setLineWidth(3);
        const startAngle = -90;
        const endAngle = startAngle + 360 * gaugePct;
        const steps = Math.max(2, Math.ceil((endAngle - startAngle) / 2));
        for (let i = 0; i < steps; i++) {
          const a1 = ((startAngle + (endAngle - startAngle) * (i / steps)) * Math.PI) / 180;
          const a2 = ((startAngle + (endAngle - startAngle) * ((i + 1) / steps)) * Math.PI) / 180;
          doc.line(
            gaugeCx + gaugeR * Math.cos(a1), gaugeCy + gaugeR * Math.sin(a1),
            gaugeCx + gaugeR * Math.cos(a2), gaugeCy + gaugeR * Math.sin(a2),
          );
        }
      }

      // Score text in center
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...gaugeColor);
      doc.text(String(gaugeScore), gaugeCx, gaugeCy + 2, { align: 'center' });
      doc.setFontSize(7);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...C.gray);
      doc.text('/ 1000', gaugeCx, gaugeCy + 7, { align: 'center' });

      // Title
      doc.setTextColor(...C.white);
      doc.setFontSize(20);
      doc.setFont('helvetica', 'bold');
      doc.text('Code Hardener', pw / 2, 22, { align: 'center' });
      doc.setFontSize(12);
      doc.setFont('helvetica', 'normal');
      doc.text('ATTESTATION CERTIFICATE', pw / 2, 36, { align: 'center' });

      // Project name & scan info
      let ay = 108;
      doc.setTextColor(...C.darkBg);
      doc.setFontSize(16);
      doc.setFont('helvetica', 'bold');
      doc.text(scan.projectName || 'Unknown Project', pw / 2, ay, { align: 'center' });
      ay += 8;
      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...C.gray);
      doc.text(`Scan ${scan.id.slice(0, 8)}  |  Branch: ${scan.branch || 'main'}  |  ${formatDate(scan.startedAt || scan.createdAt)}`, pw / 2, ay, { align: 'center' });
      ay += 16;

      // Attestation details box
      const boxX = m + 10;
      const boxW = cw - 20;
      doc.setFillColor(...C.lightBg);
      doc.roundedRect(boxX, ay, boxW, 70, 3, 3, 'F');
      doc.setDrawColor(...C.border);
      doc.roundedRect(boxX, ay, boxW, 70, 3, 3, 'S');

      const isSigned = !!attestation.signature;
      const lx = boxX + 10;
      const rx = boxX + boxW / 2 + 5;
      let dy = ay + 12;
      const rowH = 10;

      const attField = (label: string, value: string, x: number, yPos: number) => {
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...C.gray);
        doc.text(label, x, yPos);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...C.darkText);
        doc.text(value, x, yPos + 5);
      };

      attField('Attestation ID', attestation.id.slice(0, 24) + '...', lx, dy);
      attField('Type', attestation.attestationType || 'in-toto', rx, dy);
      dy += rowH + 4;

      attField('Subject', attestation.subjectName || scan.projectName || 'N/A', lx, dy);
      attField('Created', formatDateTime(attestation.createdAt), rx, dy);
      dy += rowH + 4;

      // Digest row (full width)
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...C.gray);
      doc.text('Subject Digest', lx, dy);
      doc.setFont('courier', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(...C.darkText);
      const digestStr = attestation.subjectDigest
        ? `sha256:${attestation.subjectDigest.slice(0, 56)}...`
        : 'N/A';
      doc.text(digestStr, lx, dy + 5);
      dy += rowH + 4;

      // Signature status row
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...C.gray);
      doc.text('Signature Status', lx, dy);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...(isSigned ? C.success : C.warning));
      doc.text(isSigned ? 'CRYPTOGRAPHICALLY SIGNED' : 'UNSIGNED', lx, dy + 5);
      if (isSigned && attestation.signatureAlgorithm) {
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(...C.gray);
        const algoLabel = attestation.signatureAlgorithm === 'ed25519-local'
          ? 'Ed25519 (Local Signing Key)'
          : attestation.signatureAlgorithm === 'sigstore-cosign'
          ? 'Sigstore / Cosign (OIDC)'
          : attestation.signatureAlgorithm;
        doc.text(`Algorithm: ${algoLabel}`, rx, dy + 5);
      }

      ay += 78;

      // Signature preview (if signed)
      if (isSigned) {
        ay += 4;
        doc.setFillColor(241, 245, 249);
        doc.roundedRect(boxX, ay, boxW, 22, 2, 2, 'F');
        doc.setFontSize(7);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...C.gray);
        doc.text('Signature', boxX + 8, ay + 7);
        doc.setFont('courier', 'normal');
        doc.setFontSize(6);
        doc.setTextColor(...C.darkText);
        const sigLines = [];
        const sig = attestation.signature!;
        for (let i = 0; i < Math.min(sig.length, 128); i += 64) {
          sigLines.push(sig.slice(i, i + 64));
        }
        if (sig.length > 128) sigLines.push('...');
        sigLines.forEach((line, idx) => {
          doc.text(line, boxX + 8, ay + 12 + idx * 3.5);
        });
        ay += 26;
      }

      // Rekor log entry (if Sigstore)
      if (attestation.rekorLogId) {
        ay += 4;
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...C.gray);
        doc.text('Transparency Log', boxX + 8, ay);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(...C.darkText);
        doc.text(`Rekor Log ID: ${attestation.rekorLogId}`, boxX + 8, ay + 5);
        if (attestation.transparencyLogUrl) {
          doc.setTextColor(...C.accent);
          doc.text(attestation.transparencyLogUrl, boxX + 8, ay + 10);
        }
      }

      // Footer on attestation page
      doc.setDrawColor(...C.border);
      doc.setLineWidth(0.3);
      doc.line(m, ph - 25, pw - m, ph - 25);
      doc.setFontSize(7);
      doc.setTextColor(...C.gray);
      doc.setFont('helvetica', 'normal');
      doc.text(
        'This attestation certifies the security scan was performed and results were recorded with cryptographic integrity.',
        pw / 2, ph - 18, { align: 'center', maxWidth: cw }
      );

      // Start new page for main report
      doc.addPage();
      y = m;
    }

    // ════════════════════════════════════════════
    // Section 1: Header Bar
    // ════════════════════════════════════════════
    doc.setFillColor(...C.darkBg);
    doc.rect(0, 0, pw, 40, 'F');
    doc.setFillColor(...C.accent);
    doc.rect(0, 40, pw, 1.5, 'F');
    doc.setTextColor(...C.white);
    doc.setFontSize(22);
    doc.setFont('helvetica', 'bold');
    doc.text('Code Hardener', m, 18);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text('Assurance Report', m, 26);
    doc.setFontSize(9);
    doc.text(`Generated: ${formatDateTime(new Date().toISOString())}`, pw - m, 18, { align: 'right' });
    doc.text(`Scan: ${scan.id.slice(0, 8)}...`, pw - m, 26, { align: 'right' });
    y = 52;

    // ════════════════════════════════════════════
    // Section 2: Title & Metadata
    // ════════════════════════════════════════════
    doc.setTextColor(...C.darkBg);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text(`Scan Report — ${scan.projectName || 'Unknown Project'}`, m, y);
    y += 8;
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(...C.gray);
    doc.text(
      `Branch: ${scan.branch || 'main'}  |  Status: ${scan.status}  |  ${formatDate(scan.startedAt || scan.createdAt)}`,
      m,
      y
    );
    y += 10;
    divider();

    // ════════════════════════════════════════════
    // Section 3: Score Box
    // ════════════════════════════════════════════
    pgBreak(25);
    doc.setFillColor(...C.lightBg);
    doc.roundedRect(m, y, cw, 20, 2, 2, 'F');
    const score = scan.score ?? 0;
    const sc: RGB = score >= 800 ? C.success : score >= 500 ? C.warning : C.error;
    doc.setFontSize(24);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...sc);
    doc.text(String(score), m + 10, y + 14);
    doc.setFontSize(9);
    doc.setTextColor(...C.gray);
    doc.setFont('helvetica', 'normal');
    doc.text(`/ 1000  Score  —  Quality: ${scan.qualityLevel || 'N/A'}`, m + 35, y + 14);
    y += 28;

    // ════════════════════════════════════════════
    // Section 4: Scan Details
    // ════════════════════════════════════════════
    sectionTitle('Scan Details');
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(...C.darkText);

    // Separate open vs resolved findings
    const openFindings = allFindings.filter(f => f.status === 'open');
    const resolvedFindings = allFindings.filter(f => f.status !== 'open');

    // Codebase coverage stats
    const totalFromInventory = scan.fileInventory?.totalFiles || 0;
    const totalFromScanners = scan.scannerResults
      ? Math.max(...scan.scannerResults.map(r => r.evidence?.filesAnalyzed || r.filesScanned || 0), 0)
      : 0;
    const totalFilesAnalyzed = totalFromInventory || totalFromScanners || (scan.filesScanned?.length || 0);
    const successScannerCount = scan.scannerResults?.filter(r => r.status === 'success').length || 0;

    const details: [string, string][] = [
      ['Profile', String(scan.scanType || 'standard')],
      ['Duration', scan.duration ? fmtDuration(scan.duration) : 'N/A'],
      ['Started', scan.startedAt ? formatDateTime(scan.startedAt) : 'N/A'],
      ['Completed', scan.completedAt ? formatDateTime(scan.completedAt) : 'N/A'],
      ['Files Analyzed', String(totalFilesAnalyzed)],
      ['Scanners Run', `${successScannerCount} of ${scan.scannerResults?.length || 0}`],
      ['Open Findings', String(openFindings.length)],
      ['Resolved / Suppressed', String(resolvedFindings.length)],
      ['Total Detected', String(allFindings.length)],
    ];
    for (const [label, value] of details) {
      doc.setFont('helvetica', 'bold');
      doc.text(`${label}:`, m, y);
      doc.setFont('helvetica', 'normal');
      doc.text(value, m + 40, y);
      y += 5.5;
    }

    // Language breakdown inline
    if (scan.fileInventory && scan.fileInventory.breakdown.length > 0) {
      y += 1;
      doc.setFont('helvetica', 'bold');
      doc.text('Codebase:', m, y);
      doc.setFont('helvetica', 'normal');
      const cbText = scan.fileInventory.breakdown.join('  |  ');
      const cbLines = doc.splitTextToSize(cbText, cw - 42);
      for (const cl of cbLines) {
        doc.text(cl, m + 40, y);
        y += 5;
      }
    }
    y += 4;

    // ════════════════════════════════════════════
    // Section 5: Severity Breakdown
    // ════════════════════════════════════════════
    pgBreak(30);
    doc.setFillColor(...C.lightBg);
    doc.roundedRect(m, y, cw, 24, 2, 2, 'F');
    // Count severities from OPEN findings only (resolved/suppressed don't impact score)
    const fc = {
      critical: openFindings.filter(f => f.severity === 'critical').length,
      high: openFindings.filter(f => f.severity === 'high').length,
      medium: openFindings.filter(f => f.severity === 'medium').length,
      low: openFindings.filter(f => f.severity === 'low').length,
      info: openFindings.filter(f => f.severity === 'info').length,
    };
    const sevs: { label: string; count: number; color: RGB }[] = [
      { label: 'Critical', count: fc.critical, color: C.error },
      { label: 'High', count: fc.high, color: C.orange },
      { label: 'Medium', count: fc.medium, color: C.warning },
      { label: 'Low', count: fc.low, color: C.info },
      { label: 'Info', count: fc.info, color: C.gray },
    ];
    const bw = cw / sevs.length;
    sevs.forEach((s, i) => {
      const cx = m + bw * i + bw / 2;
      doc.setFontSize(16);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(s.color[0], s.color[1], s.color[2]);
      doc.text(String(s.count), cx, y + 10, { align: 'center' });
      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...C.gray);
      doc.text(s.label, cx, y + 17, { align: 'center' });
    });
    y += 32;

    // ════════════════════════════════════════════
    // Section 6: Scanner Results Summary + Table
    // ════════════════════════════════════════════
    if (scan.scannerResults && scan.scannerResults.length > 0) {
      sectionTitle('Scanner Results');

      // Build per-scanner OPEN finding counts (resolved/suppressed = clean)
      const scannerOpenCounts: Record<string, number> = {};
      const scannerTotalCounts: Record<string, number> = {};
      allFindings.forEach(f => {
        const key = f.scanner || '';
        scannerTotalCounts[key] = (scannerTotalCounts[key] || 0) + 1;
        if (f.status === 'open') {
          scannerOpenCounts[key] = (scannerOpenCounts[key] || 0) + 1;
        }
      });
      const getOpenCount = (scanner: string) => scannerOpenCounts[scanner] || 0;
      const getTotalCount = (scanner: string) => scannerTotalCounts[scanner] || 0;

      const passCount = scan.scannerResults.filter(r => r.status === 'success' && getOpenCount(r.scanner) === 0).length;
      const failCount = scan.scannerResults.filter(r => r.status === 'success' && getOpenCount(r.scanner) > 0).length;
      const skipCount = scan.scannerResults.filter(r => r.status === 'skipped').length;
      const errCount = scan.scannerResults.filter(r => r.status === 'error').length;

      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...C.gray);
      doc.text(
        `${scan.scannerResults.length} tools executed  —  ${passCount} passed  |  ${failCount} with open findings  |  ${skipCount} not applicable  |  ${errCount} errors`,
        m,
        y
      );
      y += 8;

      // Table header
      pgBreak(10);
      const cols = [m, m + 32, m + 56, m + 78, m + 100, m + 125];
      doc.setFillColor(...C.darkBg);
      doc.rect(m, y, cw, 7, 'F');
      doc.setTextColor(...C.white);
      doc.setFontSize(7.5);
      doc.setFont('helvetica', 'bold');
      doc.text('Scanner', cols[0] + 2, y + 5);
      doc.text('Category', cols[1] + 2, y + 5);
      doc.text('Outcome', cols[2] + 2, y + 5);
      doc.text('Findings', cols[3] + 2, y + 5);
      doc.text('Duration', cols[4] + 2, y + 5);
      doc.text('Files Scanned', cols[5] + 2, y + 5);
      y += 7;

      // Table rows — outcome based on OPEN findings (resolved = pass)
      scan.scannerResults.forEach((result, idx) => {
        pgBreak(7);
        if (idx % 2 === 0) {
          doc.setFillColor(...C.lightBg);
          doc.rect(m, y, cw, 6.5, 'F');
        }
        const meta = SCANNER_META[result.scanner] || { category: 'Other', description: '' };
        const openCount = getOpenCount(result.scanner);
        const totalCount = getTotalCount(result.scanner);
        const outcome =
          result.status === 'skipped'
            ? 'N/A'
            : result.status === 'error'
            ? 'ERROR'
            : openCount === 0
            ? 'PASS'
            : 'FAIL';
        const oc: RGB =
          outcome === 'PASS' ? C.success : outcome === 'FAIL' ? C.error : outcome === 'ERROR' ? C.orange : C.gray;

        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...C.darkText);
        doc.text(result.scanner, cols[0] + 2, y + 4.5);
        doc.setTextColor(...C.gray);
        doc.text(meta.category, cols[1] + 2, y + 4.5);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...oc);
        doc.text(outcome, cols[2] + 2, y + 4.5);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...C.darkText);
        // Show "0 (412 resolved)" format when findings exist but all resolved
        const findingsLabel = openCount > 0
          ? String(openCount)
          : totalCount > 0 ? `0 (${totalCount} resolved)` : '0';
        doc.text(findingsLabel, cols[3] + 2, y + 4.5);
        doc.setTextColor(...C.gray);
        doc.text(fmtDuration(result.duration), cols[4] + 2, y + 4.5);
        doc.text(result.filesScanned > 0 ? String(result.filesScanned) : '-', cols[5] + 2, y + 4.5);
        y += 6.5;
      });
      y += 4;

      // Error details for any scanners that errored
      const errorScanners = scan.scannerResults.filter(r => r.status === 'error' && r.error);
      if (errorScanners.length > 0) {
        pgBreak(12);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...C.orange);
        doc.text('Scanner Errors', m, y);
        y += 5;
        for (const es of errorScanners) {
          pgBreak(8);
          doc.setFontSize(8);
          doc.setFont('helvetica', 'bold');
          doc.setTextColor(...C.darkText);
          doc.text(`${es.scanner}:`, m + 2, y);
          doc.setFont('helvetica', 'normal');
          doc.setTextColor(...C.error);
          const errLines = doc.splitTextToSize(es.error!, cw - 30);
          doc.text(errLines.slice(0, 2), m + 30, y);
          y += Math.min(errLines.length, 2) * 4 + 2;
        }
        y += 2;
      }

      // ════════════════════════════════════════════
      // Section 7: Scanner Evidence & Audit Trail
      // ════════════════════════════════════════════
      const evidenceScanners = scan.scannerResults.filter(r => r.evidence && r.status !== 'error');
      if (evidenceScanners.length > 0) {
        pgBreak(15);
        divider();
        sectionTitle('Scanner Evidence & Audit Trail', 12);

        for (const result of evidenceScanners) {
          const ev = result.evidence!;
          const meta = SCANNER_META[result.scanner] || { category: 'Other', description: '' };
          const scannerOpenCount = getOpenCount(result.scanner);
          const outcome =
            result.status === 'skipped' ? 'N/A' : scannerOpenCount === 0 ? 'PASS' : 'FINDINGS';

          pgBreak(18);
          // Scanner sub-header
          doc.setFillColor(...C.lightBg);
          doc.roundedRect(m, y, cw, 8, 1.5, 1.5, 'F');
          doc.setFontSize(9);
          doc.setFont('helvetica', 'bold');
          doc.setTextColor(...C.darkText);
          doc.text(`${result.scanner} (${meta.category})`, m + 3, y + 5.5);
          const oc: RGB = outcome === 'PASS' ? C.success : outcome === 'N/A' ? C.gray : C.orange;
          doc.setTextColor(...oc);
          doc.text(outcome, pw - m - 3, y + 5.5, { align: 'right' });
          y += 11;

          doc.setFontSize(8);
          doc.setFont('helvetica', 'normal');

          // Evidence key-value pairs
          const kvPairs: [string, string][] = [];
          if (ev.scanScope) kvPairs.push(['Scan Scope', ev.scanScope]);
          if (ev.detectionMethod) kvPairs.push(['Detection Method', ev.detectionMethod]);
          if (ev.configuration) kvPairs.push(['Configuration', ev.configuration]);
          if (ev.filesAnalyzed) kvPairs.push(['Files Analyzed', String(ev.filesAnalyzed)]);
          if (ev.rulesEvaluated) kvPairs.push(['Rules Checked', String(ev.rulesEvaluated)]);
          if (ev.toolVersion) kvPairs.push(['Tool Version', ev.toolVersion]);

          const lh = 4.5; // consistent line height for font size 8

          for (const [label, value] of kvPairs) {
            const wrapped = doc.splitTextToSize(value, cw - 48);
            pgBreak(wrapped.length * lh + 2);
            doc.setTextColor(...C.gray);
            doc.setFont('helvetica', 'bold');
            doc.text(`${label}:`, m + 3, y);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...C.darkText);
            for (let li = 0; li < wrapped.length; li++) {
              doc.text(wrapped[li], m + 42, y);
              y += lh;
            }
          }

          // Checks performed
          if (ev.checksPerformed && ev.checksPerformed.length > 0) {
            pgBreak(lh + 2);
            doc.setTextColor(...C.gray);
            doc.setFont('helvetica', 'bold');
            doc.text('Checks Performed:', m + 3, y);
            y += lh;
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...C.darkText);
            for (const check of ev.checksPerformed) {
              const wrapped = doc.splitTextToSize(`- ${check}`, cw - 12);
              pgBreak(wrapped.length * lh);
              for (const wl of wrapped) {
                doc.text(wl, m + 6, y);
                y += lh;
              }
            }
          }

          // Standards
          if (ev.standards && ev.standards.length > 0) {
            const stdText = ev.standards.join(', ');
            const stdWrapped = doc.splitTextToSize(stdText, cw - 48);
            pgBreak(stdWrapped.length * lh + 2);
            doc.setTextColor(...C.gray);
            doc.setFont('helvetica', 'bold');
            doc.text('Standards:', m + 3, y);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...C.darkText);
            for (let li = 0; li < stdWrapped.length; li++) {
              doc.text(stdWrapped[li], m + 42, y);
              y += lh;
            }
          }

          // Methodology
          if (ev.methodology) {
            pgBreak(lh + 2);
            doc.setTextColor(...C.gray);
            doc.setFont('helvetica', 'bold');
            doc.text('Methodology:', m + 3, y);
            y += lh;
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...C.darkText);
            const mLines = doc.splitTextToSize(ev.methodology, cw - 8);
            for (const ml of mLines) {
              pgBreak(lh);
              doc.text(ml, m + 3, y);
              y += lh;
            }
          }

          // Targets analyzed
          if (ev.targetsAnalyzed && ev.targetsAnalyzed.length > 0) {
            pgBreak(lh + 2);
            doc.setTextColor(...C.gray);
            doc.setFont('helvetica', 'bold');
            doc.text('Targets Analyzed:', m + 3, y);
            y += lh;
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...C.darkText);
            const targetText = ev.targetsAnalyzed.join(', ');
            const tLines = doc.splitTextToSize(targetText, cw - 8);
            const maxLines = Math.min(tLines.length, 4);
            for (let li = 0; li < maxLines; li++) {
              pgBreak(lh);
              doc.text(tLines[li], m + 3, y);
              y += lh;
            }
            if (tLines.length > maxLines) {
              doc.setTextColor(...C.gray);
              doc.text(`... and ${ev.targetsAnalyzed.length - maxLines} more`, m + 3, y);
              y += lh;
            }
          }

          y += 4;
        }
      }
    }

    // ════════════════════════════════════════════
    // Section 8: Detailed Findings by Scanner
    // ════════════════════════════════════════════
    // Only show open findings in the detailed section — resolved/suppressed are accounted for in the summary
    const reportFindings = openFindings;
    if (reportFindings.length > 0) {
      pgBreak(20);
      divider();
      sectionTitle(`Open Findings (${reportFindings.length})`);

      // Group findings by scanner
      const byScanner: Record<string, ScanFinding[]> = {};
      for (const f of reportFindings) {
        if (!byScanner[f.scanner]) byScanner[f.scanner] = [];
        byScanner[f.scanner].push(f);
      }

      // Sort scanners: most critical findings first
      const sortedScanners = Object.entries(byScanner).sort(([, a], [, b]) => {
        const aMin = Math.min(...a.map(f => SEV_ORDER[f.severity.toLowerCase()] ?? 5));
        const bMin = Math.min(...b.map(f => SEV_ORDER[f.severity.toLowerCase()] ?? 5));
        return aMin - bMin;
      });

      for (const [scannerName, scannerFindings] of sortedScanners) {
        const meta = SCANNER_META[scannerName] || { category: 'Other', description: 'Security scanner' };

        // Scanner section header with accent bar
        pgBreak(18);
        doc.setFillColor(...C.accent);
        doc.rect(m, y, 2, 8, 'F');
        doc.setFontSize(11);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...C.darkBg);
        doc.text(scannerName, m + 5, y + 5.5);
        y += 9;
        doc.setFontSize(8);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...C.gray);
        doc.text(
          `${meta.category}  |  ${scannerFindings.length} finding${scannerFindings.length !== 1 ? 's' : ''}  |  ${meta.description}`,
          m + 5,
          y
        );
        y += 7;

        // Findings table header
        pgBreak(8);
        const fcols = [m, m + 18, m + 93, m + 140];
        doc.setFillColor(30, 41, 59);
        doc.rect(m, y, cw, 6, 'F');
        doc.setTextColor(...C.white);
        doc.setFontSize(7);
        doc.setFont('helvetica', 'bold');
        doc.text('Severity', fcols[0] + 2, y + 4.2);
        doc.text('Title', fcols[1] + 2, y + 4.2);
        doc.text('File', fcols[2] + 2, y + 4.2);
        doc.text('CWE / Rule', fcols[3] + 2, y + 4.2);
        y += 6;

        // Sort: critical first
        const sorted = [...scannerFindings].sort(
          (a, b) => (SEV_ORDER[a.severity.toLowerCase()] ?? 5) - (SEV_ORDER[b.severity.toLowerCase()] ?? 5)
        );

        for (let idx = 0; idx < sorted.length; idx++) {
          const f = sorted[idx];

          // Summary row
          pgBreak(8);
          if (idx % 2 === 0) {
            doc.setFillColor(...C.lightBg);
            doc.rect(m, y, cw, 6, 'F');
          }

          doc.setFontSize(7);
          doc.setFont('helvetica', 'bold');
          doc.setTextColor(...sevColor(f.severity));
          doc.text(f.severity.toUpperCase(), fcols[0] + 2, y + 4.2);

          doc.setFont('helvetica', 'normal');
          doc.setTextColor(...C.darkText);
          const titleText = f.title.length > 56 ? f.title.slice(0, 53) + '...' : f.title;
          doc.text(titleText, fcols[1] + 2, y + 4.2);

          doc.setTextColor(...C.gray);
          const fp = f.filePath
            ? (f.filePath.length > 32 ? '...' + f.filePath.slice(-29) : f.filePath) +
              (f.line > 0 ? `:${f.line}` : '')
            : '';
          doc.text(fp, fcols[2] + 2, y + 4.2);

          const ruleText = f.cwe || f.ruleId || '';
          doc.text(ruleText.slice(0, 22), fcols[3] + 2, y + 4.2);
          y += 6;

          // Description
          if (f.description) {
            doc.setFontSize(7);
            doc.setTextColor(...C.darkText);
            const descLines = doc.splitTextToSize(f.description, cw - 8);
            const maxDesc = Math.min(descLines.length, 3);
            const descHeight = maxDesc * 4 + (descLines.length > 3 ? 4 : 0) + 2;
            pgBreak(descHeight);
            y += 1;
            for (let dl = 0; dl < maxDesc; dl++) {
              doc.text(descLines[dl], m + 4, y);
              y += 4;
            }
            if (descLines.length > 3) {
              doc.setTextColor(...C.gray);
              doc.text('...', m + 4, y);
              y += 4;
            }
          }

          // Code snippet
          if (f.code) {
            doc.setFontSize(6.5);
            doc.setFont('courier', 'normal');
            // Split code by newlines and wrap long lines
            const codeLines = f.code.split('\n').slice(0, 6);
            const lineH = 3.2;
            const boxPad = 3;
            const boxH = codeLines.length * lineH + boxPad * 2;
            pgBreak(boxH + 4);
            y += 2;
            doc.setFillColor(241, 245, 249);
            doc.roundedRect(m + 2, y, cw - 4, boxH, 1, 1, 'F');
            let codeY = y + boxPad + 2;
            for (const line of codeLines) {
              const trimmed = line.length > 110 ? line.slice(0, 107) + '...' : line;
              doc.setTextColor(100, 60, 60);
              doc.text(trimmed, m + 6, codeY);
              codeY += lineH;
            }
            doc.setFont('helvetica', 'normal');
            y += boxH + 3;
          }

          // Fix recommendation
          if (f.fixDescription) {
            doc.setFontSize(7);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(...C.success);
            const fixLines = doc.splitTextToSize(f.fixDescription, cw - 22);
            const maxFix = Math.min(fixLines.length, 3);
            const fixHeight = 5 + maxFix * 4 + (fixLines.length > maxFix ? 4 : 0);
            pgBreak(fixHeight);
            doc.text('Fix:', m + 4, y);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...C.darkText);
            for (let fl = 0; fl < maxFix; fl++) {
              doc.text(fixLines[fl], m + 14, y);
              y += 4;
            }
            if (fixLines.length > maxFix) {
              doc.setTextColor(...C.gray);
              doc.text('...', m + 14, y);
              y += 4;
            }
          }

          // OWASP / metadata line
          const metaTags: string[] = [];
          if (f.owaspCategory) metaTags.push(`OWASP: ${f.owaspCategory}`);
          if (f.cwe && f.ruleId) metaTags.push(`Rule: ${f.ruleId}`);
          if (f.status && f.status !== 'open') metaTags.push(`Status: ${f.status}`);
          if (metaTags.length > 0) {
            pgBreak(6);
            doc.setFontSize(6.5);
            doc.setTextColor(...C.gray);
            doc.text(metaTags.join('  |  '), m + 4, y);
            y += 5;
          }

          // Separator between findings
          if (idx < sorted.length - 1) {
            y += 1;
            doc.setDrawColor(...C.border);
            doc.setLineWidth(0.15);
            doc.line(m + 2, y, pw - m - 2, y);
            y += 2;
          }
        }

        y += 6;
      }
    } else {
      // No open findings — show clean report summary
      pgBreak(30);
      divider();
      sectionTitle('Findings Summary');
      doc.setFillColor(240, 253, 244); // light green background
      doc.roundedRect(m, y, cw, 24, 3, 3, 'F');
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...C.success);
      doc.text('ALL CLEAR — No Open Findings', pw / 2, y + 10, { align: 'center' });
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...C.gray);
      const resolvedText = resolvedFindings.length > 0
        ? `${allFindings.length} findings detected, all ${resolvedFindings.length} resolved via code fixes, accepted risk, or suppression rules.`
        : 'No security findings were detected by any scanner.';
      doc.text(resolvedText, pw / 2, y + 18, { align: 'center', maxWidth: cw - 20 });
      y += 32;
    }

    // ════════════════════════════════════════════
    // Section 9: Codebase Coverage (File Inventory)
    // ════════════════════════════════════════════
    {
      pgBreak(20);
      divider();

      // Calculate total files analyzed across all scanners (from evidence)
      const totalFromInventory = scan.fileInventory?.totalFiles || 0;
      const totalFromScanners = scan.scannerResults
        ? Math.max(...scan.scannerResults.map(r => r.evidence?.filesAnalyzed || r.filesScanned || 0), 0)
        : 0;
      const totalFilesAnalyzed = totalFromInventory || totalFromScanners || (scan.filesScanned?.length || 0);

      sectionTitle(`Codebase Coverage (${totalFilesAnalyzed} files analyzed)`);

      // Summary paragraph for auditors
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...C.darkText);
      const successScanners = scan.scannerResults?.filter(r => r.status === 'success').length || 0;
      const coverageText = `This scan analyzed ${totalFilesAnalyzed} files using ${successScanners} security tools across ` +
        `${scan.scannerResults?.map(r => SCANNER_META[r.scanner]?.category).filter((v, i, a) => v && a.indexOf(v) === i).length || 0} testing categories. ` +
        `Each scanner targets files relevant to its analysis domain (e.g., SAST scanners analyze source code, SCA scanners analyze dependency manifests).`;
      const coverageLines = doc.splitTextToSize(coverageText, cw);
      for (const cl of coverageLines) {
        pgBreak(5);
        doc.text(cl, m, y);
        y += 4.5;
      }
      y += 4;

      // File inventory breakdown by language (from _file_inventory)
      if (scan.fileInventory && scan.fileInventory.breakdown.length > 0) {
        pgBreak(12);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...C.darkText);
        doc.text('Files by Language:', m, y);
        y += 6;

        // Render breakdown as a compact two-column list
        const breakdown = scan.fileInventory.breakdown;
        const colW = cw / 2;
        doc.setFontSize(8);
        doc.setFont('helvetica', 'normal');

        for (let i = 0; i < breakdown.length; i += 2) {
          pgBreak(5.5);
          doc.setTextColor(...C.darkText);
          doc.text(`  ${breakdown[i]}`, m, y);
          if (breakdown[i + 1]) {
            doc.text(`  ${breakdown[i + 1]}`, m + colW, y);
          }
          y += 5;
        }
        y += 4;
      }

      // File extensions breakdown
      if (scan.fileInventory && scan.fileInventory.extensions.length > 0) {
        pgBreak(12);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...C.darkText);
        doc.text('Files by Extension:', m, y);
        y += 6;

        const exts = scan.fileInventory.extensions;
        const colW = cw / 3;
        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'normal');

        for (let i = 0; i < Math.min(exts.length, 24); i += 3) {
          pgBreak(5);
          doc.setTextColor(...C.gray);
          doc.text(`  ${exts[i]}`, m, y);
          if (exts[i + 1]) doc.text(`  ${exts[i + 1]}`, m + colW, y);
          if (exts[i + 2]) doc.text(`  ${exts[i + 2]}`, m + colW * 2, y);
          y += 4.5;
        }
        if (exts.length > 24) {
          doc.setTextColor(...C.gray);
          doc.text(`  ... and ${exts.length - 24} more extension types`, m, y);
          y += 4.5;
        }
        y += 4;
      }

      // Per-scanner file coverage table
      if (scan.scannerResults && scan.scannerResults.length > 0) {
        pgBreak(14);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...C.darkText);
        doc.text('Per-Scanner File Coverage:', m, y);
        y += 6;

        const scCols = [m, m + 36, m + 60, m + 90];
        doc.setFillColor(...C.darkBg);
        doc.rect(m, y, cw, 7, 'F');
        doc.setTextColor(...C.white);
        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'bold');
        doc.text('Scanner', scCols[0] + 2, y + 5);
        doc.text('Category', scCols[1] + 2, y + 5);
        doc.text('Files Analyzed', scCols[2] + 2, y + 5);
        doc.text('Scope', scCols[3] + 2, y + 5);
        y += 7;

        scan.scannerResults
          .filter(r => r.status !== 'error')
          .forEach((result, idx) => {
            pgBreak(7);
            if (idx % 2 === 0) {
              doc.setFillColor(...C.lightBg);
              doc.rect(m, y, cw, 6, 'F');
            }
            const meta = SCANNER_META[result.scanner] || { category: 'Other', description: '' };
            const filesCount = result.evidence?.filesAnalyzed || result.filesScanned || 0;

            doc.setFontSize(7);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...C.darkText);
            doc.text(result.scanner, scCols[0] + 2, y + 4.2);
            doc.setTextColor(...C.gray);
            doc.text(meta.category, scCols[1] + 2, y + 4.2);
            doc.setTextColor(...(filesCount > 0 ? C.darkText : C.gray));
            doc.text(filesCount > 0 ? String(filesCount) : 'N/A', scCols[2] + 2, y + 4.2);
            doc.setTextColor(...C.gray);
            const scope = result.evidence?.scanScope || meta.description || '';
            doc.text(scope.length > 46 ? scope.slice(0, 43) + '...' : scope, scCols[3] + 2, y + 4.2);
            y += 6;
          });
        y += 4;
      }

      // Files with findings sub-section (renamed from "Files Scanned")
      if (scan.filesScanned && scan.filesScanned.length > 0) {
        pgBreak(14);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...C.darkText);
        doc.text(`Files with Findings (${scan.filesScanned.length}):`, m, y);
        y += 6;

        const fileCols = [m, m + 100, m + 120];
        doc.setFillColor(...C.darkBg);
        doc.rect(m, y, cw, 7, 'F');
        doc.setTextColor(...C.white);
        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'bold');
        doc.text('File Path', fileCols[0] + 2, y + 5);
        doc.text('Findings', fileCols[1] + 2, y + 5);
        doc.text('Scanners', fileCols[2] + 2, y + 5);
        y += 7;

        scan.filesScanned.forEach((file, idx) => {
          pgBreak(7);
          if (idx % 2 === 0) {
            doc.setFillColor(...C.lightBg);
            doc.rect(m, y, cw, 6, 'F');
          }
          doc.setFontSize(7);
          doc.setFont('helvetica', 'normal');
          doc.setTextColor(...C.darkText);
          const fp = file.path.length > 75 ? '...' + file.path.slice(-72) : file.path;
          doc.text(fp, fileCols[0] + 2, y + 4.2);
          doc.setTextColor(...(file.findingsCount > 0 ? C.error : C.gray));
          doc.text(String(file.findingsCount), fileCols[1] + 2, y + 4.2);
          doc.setTextColor(...C.gray);
          const scannerText = file.scanners.join(', ');
          doc.text(scannerText.length > 35 ? scannerText.slice(0, 32) + '...' : scannerText, fileCols[2] + 2, y + 4.2);
          y += 6;
        });
      }
    }

    // ════════════════════════════════════════════
    // Section 10: Software Bill of Materials (SBOM)
    // ════════════════════════════════════════════
    const syftResult = scan.scannerResults?.find(r => r.scanner === 'syft');
    const sbomPackages = syftResult?.evidence?.sbomPackages;
    if (sbomPackages && sbomPackages.length > 0) {
      pgBreak(20);
      divider();
      sectionTitle(`Software Bill of Materials (${sbomPackages.length} packages)`);

      // SBOM summary by type
      const byType: Record<string, number> = {};
      const byLicense: Record<string, number> = {};
      for (const pkg of sbomPackages) {
        const t = pkg.type || 'unknown';
        byType[t] = (byType[t] || 0) + 1;
        const lic = pkg.license || 'Unknown';
        byLicense[lic] = (byLicense[lic] || 0) + 1;
      }

      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...C.gray);
      const typeSummary = Object.entries(byType).sort((a, b) => b[1] - a[1]).map(([t, c]) => `${t}: ${c}`).join('  |  ');
      doc.text(`Package types: ${typeSummary}`, m, y);
      y += 6;

      // Top licenses summary
      const topLicenses = Object.entries(byLicense).sort((a, b) => b[1] - a[1]).slice(0, 8);
      const licSummary = topLicenses.map(([l, c]) => `${l} (${c})`).join(', ');
      const licLines = doc.splitTextToSize(`Top licenses: ${licSummary}`, cw);
      for (const ll of licLines.slice(0, 2)) {
        doc.text(ll, m, y);
        y += 4.5;
      }
      y += 4;

      // SBOM Table header
      pgBreak(10);
      const sbomCols = [m, m + 50, m + 72, m + 92, m + 112];
      doc.setFillColor(...C.darkBg);
      doc.rect(m, y, cw, 7, 'F');
      doc.setTextColor(...C.white);
      doc.setFontSize(7.5);
      doc.setFont('helvetica', 'bold');
      doc.text('Package', sbomCols[0] + 2, y + 5);
      doc.text('Version', sbomCols[1] + 2, y + 5);
      doc.text('Type', sbomCols[2] + 2, y + 5);
      doc.text('Language', sbomCols[3] + 2, y + 5);
      doc.text('License', sbomCols[4] + 2, y + 5);
      y += 7;

      // Sort by type then name
      const sortedPackages = [...sbomPackages].sort((a, b) => {
        const tc = (a.type || '').localeCompare(b.type || '');
        return tc !== 0 ? tc : a.name.localeCompare(b.name);
      });

      for (let idx = 0; idx < sortedPackages.length; idx++) {
        const pkg = sortedPackages[idx];
        pgBreak(7);
        if (idx % 2 === 0) {
          doc.setFillColor(...C.lightBg);
          doc.rect(m, y, cw, 6, 'F');
        }

        doc.setFontSize(7);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...C.darkText);
        const pkgName = pkg.name.length > 36 ? pkg.name.slice(0, 33) + '...' : pkg.name;
        doc.text(pkgName, sbomCols[0] + 2, y + 4.2);

        doc.setTextColor(...C.gray);
        const ver = (pkg.version || '-').slice(0, 14);
        doc.text(ver, sbomCols[1] + 2, y + 4.2);
        doc.text((pkg.type || '-').slice(0, 12), sbomCols[2] + 2, y + 4.2);
        doc.text((pkg.language || '-').slice(0, 12), sbomCols[3] + 2, y + 4.2);

        // Color license based on risk
        const lic = pkg.license || 'Unknown';
        const isHighRisk = /AGPL|SSPL/i.test(lic);
        const isMedRisk = /GPL(?!.*LGPL)|MPL|EPL/i.test(lic) && !/LGPL/i.test(lic);
        doc.setTextColor(...(isHighRisk ? C.error : isMedRisk ? C.warning : C.gray));
        doc.text(lic.length > 22 ? lic.slice(0, 19) + '...' : lic, sbomCols[4] + 2, y + 4.2);
        y += 6;
      }
      y += 4;
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
      doc.text('Code Hardener Scan Report — Confidential', m, ph - 10);
      doc.text(`Page ${i} of ${totalPages}`, pw - m, ph - 10, { align: 'right' });
    }

    doc.save(`Scan-${scan.id.slice(0, 8)}-${scan.projectName || 'report'}.pdf`);
  } catch (err) {
    console.error('PDF generation failed:', err);
    alert('Failed to generate PDF report');
  }
}
