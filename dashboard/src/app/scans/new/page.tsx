'use client';

import { useState, useEffect, Suspense } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  ArrowLeft,
  ArrowRight,
  Loader2,
  Shield,
  Key,
  Search,
  AlertTriangle,
  FileCode,
  Cloud,
  ChevronDown,
  CheckCircle,
  Bug,
  Container,
  Globe,
  Zap,
  Activity,
  TestTube,
  Eye,
  Link2,
  FileCheck,
  Layers,
  Package,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { projectsApi, scansApi } from '@/lib/api';
import type { Project } from '@/types';

interface Branch {
  name: string;
  isDefault: boolean;
}

// Organized by category - all 70 security tools
const SCANNER_CATEGORIES = [
  {
    id: 'sast',
    name: 'Static Analysis (SAST)',
    description: 'Code-level security analysis',
    icon: Search,
    scanners: [
      { id: 'opengrep', name: 'Opengrep', description: 'Multi-language static analysis for security vulnerabilities' },
      { id: 'bandit', name: 'Bandit', description: 'Python-specific security linter' },
      { id: 'gosec', name: 'Gosec', description: 'Go security checker' },
      { id: 'eslint-security', name: 'ESLint Security', description: 'JavaScript/TypeScript security linting' },
      { id: 'pmd', name: 'PMD', description: 'Multi-language static analyzer' },
    ],
  },
  {
    id: 'dast',
    name: 'Dynamic Analysis (DAST)',
    description: 'Runtime security testing',
    icon: Globe,
    scanners: [
      { id: 'zap', name: 'OWASP ZAP', description: 'Web application security scanner' },
      { id: 'nuclei', name: 'Nuclei', description: 'Fast vulnerability scanner with templates' },
      { id: 'sqlmap', name: 'sqlmap', description: 'SQL injection testing' },
      { id: 'dalfox', name: 'Dalfox', description: 'XSS vulnerability scanning' },
      { id: 'ffuf', name: 'ffuf', description: 'Web endpoint fuzzing' },
    ],
  },
  {
    id: 'sca',
    name: 'Dependency & Container',
    description: 'Supply chain and container security',
    icon: Container,
    scanners: [
      { id: 'trivy', name: 'Trivy', description: 'Vulnerability scanning for dependencies and containers' },
      { id: 'grype', name: 'Grype', description: 'Container and filesystem vulnerability scanner' },
      { id: 'dockle', name: 'Dockle', description: 'Container image linter for CIS Docker benchmarks' },
    ],
  },
  {
    id: 'secrets',
    name: 'Secrets Detection',
    description: 'Find leaked credentials',
    icon: Key,
    scanners: [
      { id: 'gitleaks', name: 'Gitleaks', description: 'Secret detection in code and git history' },
    ],
  },
  {
    id: 'iac',
    name: 'Infrastructure as Code',
    description: 'Cloud and infrastructure security',
    icon: Cloud,
    scanners: [
      { id: 'checkov', name: 'Checkov', description: 'IaC security scanning (Terraform, K8s, CloudFormation)' },
      { id: 'kubeconform', name: 'Kubeconform', description: 'Kubernetes manifest validation' },
      { id: 'kube-linter', name: 'KubeLinter', description: 'Kubernetes security linting' },
    ],
  },
  {
    id: 'load',
    name: 'Load Testing',
    description: 'Performance and resilience testing',
    icon: Activity,
    scanners: [
      { id: 'locust', name: 'Locust', description: 'Python-based load testing' },
      { id: 'artillery', name: 'Artillery', description: 'Cloud-native load testing' },
    ],
  },
  {
    id: 'api',
    name: 'API Testing',
    description: 'API security and contract testing',
    icon: Link2,
    scanners: [
      { id: 'newman', name: 'Newman', description: 'Postman collection runner' },
      { id: 'pact', name: 'Pact', description: 'Contract testing for APIs' },
      { id: 'restler', name: 'RESTler', description: 'REST API fuzzing' },
      { id: 'schemathesis', name: 'Schemathesis', description: 'Schema-driven API testing' },
      { id: 'keploy', name: 'Keploy', description: 'Record-replay API test coverage' },
      { id: 'spectral', name: 'Spectral', description: 'OpenAPI/AsyncAPI spec linting' },
    ],
  },
  {
    id: 'browser',
    name: 'Browser & Accessibility',
    description: 'Frontend and accessibility testing',
    icon: Eye,
    scanners: [
      { id: 'playwright', name: 'Playwright', description: 'Browser automation and testing' },
      { id: 'backstop', name: 'BackstopJS', description: 'Visual regression testing' },
      { id: 'pa11y', name: 'Pa11y', description: 'Accessibility testing' },
      { id: 'lychee', name: 'Lychee', description: 'Broken link detection' },
      { id: 'axe-core', name: 'axe-core', description: 'WCAG accessibility testing' },
    ],
  },
  {
    id: 'supply-chain',
    name: 'Supply Chain',
    description: 'SBOM and attestation',
    icon: Package,
    scanners: [
      { id: 'syft', name: 'Syft', description: 'SBOM generation' },
      { id: 'cosign', name: 'Cosign', description: 'Container signing verification' },
      { id: 'package-validator', name: 'Package Validator', description: 'Hallucinated package detection' },
      { id: 'scancode', name: 'ScanCode', description: 'Snippet-level license detection' },
      { id: 'license-finder', name: 'LicenseFinder', description: 'License compliance checking' },
      { id: 'cdxgen', name: 'cdxgen', description: 'CycloneDX SBOM generation' },
      { id: 'cargo-audit', name: 'cargo-audit', description: 'Rust dependency vulnerability scanning' },
      { id: 'scorecard', name: 'OpenSSF Scorecard', description: 'Supply chain security scoring' },
      { id: 'socket', name: 'Socket', description: 'Supply chain attack detection' },
    ],
  },
  {
    id: 'test-runners',
    name: 'Test Runners',
    description: 'Execute test suites and measure coverage',
    icon: TestTube,
    scanners: [
      { id: 'jest', name: 'Jest', description: 'JavaScript/TypeScript test execution and coverage' },
      { id: 'pytest', name: 'pytest', description: 'Python test execution and coverage' },
      { id: 'c8', name: 'c8', description: 'Code coverage measurement' },
      { id: 'fast-check', name: 'fast-check', description: 'JS/TS property-based testing' },
      { id: 'hypothesis', name: 'Hypothesis', description: 'Python property-based testing' },
    ],
  },
  {
    id: 'mutation',
    name: 'Mutation Testing',
    description: 'Validate test quality via code mutations',
    icon: Bug,
    scanners: [
      { id: 'stryker', name: 'Stryker', description: 'JS/TS mutation testing' },
      { id: 'mutmut', name: 'mutmut', description: 'Python mutation testing' },
      { id: 'pitest', name: 'Pitest', description: 'Java mutation testing' },
    ],
  },
  {
    id: 'ai-code-quality',
    name: 'AI Code Quality',
    description: 'AI-specific code analysis',
    icon: Zap,
    scanners: [
      { id: 'deepeval', name: 'DeepEval', description: 'LLM-as-Judge heuristic analysis' },
      { id: 'giskard', name: 'Giskard', description: 'LLM vulnerability testing' },
      { id: 'threatmodel', name: 'STRIDE Threat Model', description: 'Automated threat modeling' },
      { id: 'knip', name: 'Knip', description: 'JS/TS dead code detection' },
      { id: 'oxlint', name: 'Oxlint', description: 'Fast JS/TS linter' },
      { id: 'jscpd', name: 'jscpd', description: 'Cross-language copy-paste detection' },
      { id: 'ruff', name: 'Ruff', description: 'Ultra-fast Python linter' },
      { id: 'phpstan', name: 'PHPStan', description: 'PHP static analysis' },
      { id: 'typos', name: 'typos', description: 'Source code spell checking' },
      { id: 'vale', name: 'Vale', description: 'Documentation prose linting' },
      { id: 'libyear', name: 'Libyear', description: 'Dependency freshness scoring' },
      { id: 'dotenv-linter', name: 'dotenv-linter', description: '.env file validation' },
    ],
  },
  {
    id: 'cicd',
    name: 'CI/CD Security',
    description: 'Pipeline and workflow security',
    icon: FileCode,
    scanners: [
      { id: 'actionlint', name: 'actionlint', description: 'GitHub Actions workflow linting' },
      { id: 'poutine', name: 'Poutine', description: 'CI/CD pipeline security scanner' },
    ],
  },
  {
    id: 'fuzz',
    name: 'Fuzz & Chaos Testing',
    description: 'Fuzzing and resilience testing',
    icon: AlertTriangle,
    scanners: [
      { id: 'aflpp', name: 'AFL++', description: 'Coverage-guided fuzzing' },
      { id: 'toxiproxy', name: 'Toxiproxy', description: 'Chaos/resilience config analysis' },
    ],
  },
  {
    id: 'policy',
    name: 'Policy & Reporting',
    description: 'Policy enforcement and reports',
    icon: FileCheck,
    scanners: [
      { id: 'opa', name: 'OPA', description: 'Policy as code with Rego' },
      { id: 'conftest', name: 'Conftest', description: 'Policy testing for configuration data' },
    ],
  },
];

// Flatten all scanners for easy lookup
const ALL_SCANNERS = SCANNER_CATEGORIES.flatMap(cat =>
  cat.scanners.map(s => ({ ...s, category: cat.id, categoryName: cat.name }))
);

// Scan profiles for quick selection (match backend PROFILE_SCANNERS)
const SCAN_PROFILES = [
  {
    id: 'quick',
    name: 'Quick Scan',
    description: 'Essential security checks (fast)',
    scanners: ['gitleaks', 'trivy'],
    icon: Zap,
  },
  {
    id: 'standard',
    name: 'Standard Scan',
    description: 'Recommended security coverage',
    scanners: ['trivy', 'gitleaks', 'opengrep', 'checkov', 'grype', 'syft', 'package-validator', 'oxlint', 'ruff', 'actionlint'],
    icon: Shield,
  },
  {
    id: 'comprehensive',
    name: 'Comprehensive Scan',
    description: 'Full security analysis with all categories',
    scanners: [
      'opengrep', 'bandit', 'gosec', 'eslint-security', 'pmd',
      'nuclei', 'zap', 'sqlmap', 'dalfox', 'ffuf',
      'trivy', 'grype', 'gitleaks', 'checkov',
      'newman', 'restler', 'schemathesis', 'keploy',
      'syft', 'cosign', 'dockle', 'opa', 'conftest',
      'package-validator', 'scancode', 'stryker', 'mutmut', 'pitest', 'deepeval', 'giskard',
      'jest', 'pytest', 'c8', 'fast-check', 'hypothesis', 'aflpp', 'threatmodel',
      'knip', 'oxlint', 'jscpd', 'ruff', 'phpstan', 'typos', 'libyear',
      'actionlint', 'poutine', 'scorecard', 'kubeconform', 'kube-linter',
      'cargo-audit', 'spectral', 'dotenv-linter', 'license-finder', 'cdxgen',
      'socket', 'lychee', 'axe-core',
    ],
    icon: Layers,
  },
  {
    id: 'security',
    name: 'Security Focus',
    description: 'Security-specific scanners',
    scanners: ['opengrep', 'bandit', 'gosec', 'eslint-security', 'nuclei', 'trivy', 'grype', 'gitleaks', 'checkov', 'syft', 'dockle', 'threatmodel', 'actionlint', 'poutine', 'scorecard', 'cargo-audit', 'sqlmap', 'dalfox', 'ffuf', 'socket'],
    icon: Shield,
  },
  {
    id: 'ai-code-quality',
    name: 'AI Code Quality',
    description: 'Purpose-built for AI-generated codebases',
    scanners: [
      'package-validator', 'deepeval', 'stryker', 'mutmut', 'pitest',
      'jest', 'pytest', 'scancode', 'schemathesis', 'keploy',
      'opengrep', 'trivy', 'gitleaks', 'eslint-security', 'bandit',
      'knip', 'oxlint', 'ruff', 'jscpd', 'typos', 'libyear',
    ],
    icon: Zap,
  },
  {
    id: 'api',
    name: 'API Testing',
    description: 'API security and contracts',
    scanners: ['newman', 'pact', 'restler', 'nuclei', 'schemathesis', 'keploy', 'spectral'],
    icon: Link2,
  },
  {
    id: 'performance',
    name: 'Performance Testing',
    description: 'Load and stress testing',
    scanners: ['locust', 'artillery'],
    icon: Activity,
  },
  {
    id: 'frontend',
    name: 'Frontend Testing',
    description: 'Browser and accessibility',
    scanners: ['playwright', 'backstop', 'pa11y', 'eslint-security'],
    icon: Eye,
  },
  {
    id: 'supply-chain',
    name: 'Supply Chain',
    description: 'SBOM, attestation, and license scanning',
    scanners: ['syft', 'cosign', 'trivy', 'grype', 'dockle', 'package-validator', 'scancode', 'socket'],
    icon: Package,
  },
  {
    id: 'pre-commit',
    name: 'Pre-commit',
    description: 'Ultrafast pre-commit hook (~30s)',
    scanners: ['gitleaks', 'trivy', 'opengrep', 'oxlint', 'ruff', 'typos'],
    icon: Zap,
  },
  {
    id: 'compliance',
    name: 'Compliance',
    description: 'SOC2/ISO27001/NIST/PCI compliance audit',
    scanners: ['trivy', 'grype', 'gitleaks', 'checkov', 'syft', 'cdxgen', 'license-finder', 'scancode', 'cosign', 'scorecard', 'opa', 'conftest', 'dockle', 'hadolint', 'actionlint', 'poutine'],
    icon: Shield,
  },
  {
    id: 'usability',
    name: 'Usability',
    description: 'Accessibility and usability testing',
    scanners: ['pa11y', 'axe-core', 'backstop', 'playwright', 'selenium-gen', 'lychee', 'vale'],
    icon: Eye,
  },
  {
    id: 'unit-test',
    name: 'Unit Test',
    description: 'Unit and mutation testing',
    scanners: ['jest', 'pytest', 'stryker', 'mutmut', 'pitest', 'c8', 'fast-check', 'hypothesis'],
    icon: TestTube,
  },
  {
    id: 'full',
    name: 'Full Suite',
    description: 'All 70 security tools',
    scanners: ALL_SCANNERS.map(s => s.id),
    icon: CheckCircle,
  },
  {
    id: 'custom',
    name: 'Custom',
    description: 'Select individual scanners',
    scanners: [],
    icon: FileCode,
  },
];

const DEFAULT_SCANNERS = ['trivy', 'gitleaks', 'opengrep', 'checkov'];

interface AdvancedOptions {
  depth: 'shallow' | 'full';
  excludePatterns: string;
  failThreshold: string;
  timeout: number;
  parallel: boolean;
  targetUrlOverride: string;
  containerImageOverride: string;
  openapiSpecOverride: string;
}

// Scanner prerequisite requirements for readiness badges
const SCANNER_PREREQUISITES: Record<string, { requires: ('targetUrl' | 'containerImage' | 'openapiSpec')[]; hint: string }> = {
  zap: { requires: ['targetUrl'], hint: 'Requires target URL' },
  nuclei: { requires: ['targetUrl'], hint: 'Requires target URL' },
  pa11y: { requires: ['targetUrl'], hint: 'Requires target URL' },
  playwright: { requires: ['targetUrl'], hint: 'Requires target URL' },
  backstop: { requires: ['targetUrl'], hint: 'Requires target URL' },
  locust: { requires: ['targetUrl'], hint: 'Requires target URL' },
  artillery: { requires: ['targetUrl'], hint: 'Requires target URL' },
  sqlmap: { requires: ['targetUrl'], hint: 'Requires target URL' },
  dalfox: { requires: ['targetUrl'], hint: 'Requires target URL' },
  ffuf: { requires: ['targetUrl'], hint: 'Requires target URL' },
  'axe-core': { requires: ['targetUrl'], hint: 'Requires target URL' },
  cosign: { requires: ['containerImage'], hint: 'Requires container image' },
  dockle: { requires: ['containerImage'], hint: 'Requires container image' },
  spectral: { requires: ['openapiSpec'], hint: 'Requires OpenAPI spec' },
  schemathesis: { requires: ['openapiSpec', 'targetUrl'], hint: 'Requires OpenAPI spec and target URL' },
  restler: { requires: ['openapiSpec', 'targetUrl'], hint: 'Requires OpenAPI spec and target URL' },
  newman: { requires: ['openapiSpec'], hint: 'Requires API spec or Postman collection' },
};

type ReadinessStatus = 'ready' | 'needs-config' | 'na';

export default function NewScanPage() {
  return (
    <Suspense fallback={<NewScanPageSkeleton />}>
      <NewScanPageContent />
    </Suspense>
  );
}

function NewScanPageSkeleton() {
  return (
    <div className="max-w-2xl mx-auto">
      <div className="mb-8">
        <div className="h-4 w-24 bg-bg-tertiary rounded animate-pulse mb-4" />
        <div className="h-8 w-48 bg-bg-tertiary rounded animate-pulse" />
        <div className="h-4 w-64 bg-bg-tertiary rounded animate-pulse mt-2" />
      </div>
      <div className="card p-6 space-y-4">
        <div className="h-6 w-32 bg-bg-tertiary rounded animate-pulse" />
        <div className="h-10 w-full bg-bg-tertiary rounded animate-pulse" />
      </div>
    </div>
  );
}

function NewScanPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const preselectedProjectId = searchParams.get('projectId');

  const [projects, setProjects] = useState<Project[]>([]);
  const [branches, setBranches] = useState<Branch[]>([]);
  const [isLoadingProjects, setIsLoadingProjects] = useState(true);
  const [isLoadingBranches, setIsLoadingBranches] = useState(false);

  const [projectId, setProjectId] = useState(preselectedProjectId || '');
  const [branch, setBranch] = useState('main');
  const [selectedProfile, setSelectedProfile] = useState('standard');
  const [scanners, setScanners] = useState<string[]>(SCAN_PROFILES.find(p => p.id === 'standard')?.scanners || DEFAULT_SCANNERS);
  const [expandedCategories, setExpandedCategories] = useState<string[]>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [advancedOptions, setAdvancedOptions] = useState<AdvancedOptions>({
    depth: 'full',
    excludePatterns: '',
    failThreshold: 'none',
    timeout: 30,
    parallel: true,
    targetUrlOverride: '',
    containerImageOverride: '',
    openapiSpecOverride: '',
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Selected project for readiness checks
  const selectedProject = projects.find(p => p.id === projectId) || null;

  // Determine scanner readiness based on project config and overrides
  const getScannerReadiness = (scannerId: string): { status: ReadinessStatus; hint: string } => {
    const prereqs = SCANNER_PREREQUISITES[scannerId];
    if (!prereqs) return { status: 'ready', hint: '' };

    const hasTargetUrl = !!(advancedOptions.targetUrlOverride || selectedProject?.targetUrl);
    const hasContainerImage = !!(advancedOptions.containerImageOverride || selectedProject?.containerImage);
    const hasOpenapiSpec = !!(advancedOptions.openapiSpecOverride || selectedProject?.openapiSpecPath);

    const missing: string[] = [];
    for (const req of prereqs.requires) {
      if (req === 'targetUrl' && !hasTargetUrl) missing.push('target URL');
      if (req === 'containerImage' && !hasContainerImage) missing.push('container image');
      if (req === 'openapiSpec' && !hasOpenapiSpec) missing.push('OpenAPI spec');
    }

    if (missing.length === 0) return { status: 'ready', hint: '' };
    return { status: 'needs-config', hint: `Needs ${missing.join(', ')}` };
  };

  // Fetch projects on mount
  useEffect(() => {
    fetchProjects();
  }, []);

  // Fetch branches when project changes
  useEffect(() => {
    if (projectId) {
      fetchBranches(projectId);
    } else {
      setBranches([]);
    }
  }, [projectId]);

  async function fetchProjects() {
    try {
      setIsLoadingProjects(true);
      const response = await projectsApi.list({ limit: 100 });
      setProjects(response.data);
    } catch (err) {
      console.error('Failed to fetch projects:', err);
    } finally {
      setIsLoadingProjects(false);
    }
  }

  async function fetchBranches(projId: string) {
    try {
      setIsLoadingBranches(true);
      // Try to get branches from project details
      const project = await projectsApi.get(projId);
      // If project has branches info, use it; otherwise default to main
      if ((project as { branches?: Branch[] }).branches) {
        setBranches((project as { branches?: Branch[] }).branches || []);
      } else {
        // Default branches if not available from API
        setBranches([{ name: 'main', isDefault: true }]);
      }
    } catch (err) {
      console.error('Failed to fetch branches:', err);
      setBranches([{ name: 'main', isDefault: true }]);
    } finally {
      setIsLoadingBranches(false);
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      const scan = await scansApi.create({
        projectId,
        branch,
        scanType: selectedProfile === 'custom' ? 'comprehensive' : selectedProfile,
        scanners,
        ...(advancedOptions.targetUrlOverride && { targetUrlOverride: advancedOptions.targetUrlOverride }),
        ...(advancedOptions.containerImageOverride && { containerImageOverride: advancedOptions.containerImageOverride }),
        ...(advancedOptions.openapiSpecOverride && { openapiSpecOverride: advancedOptions.openapiSpecOverride }),
        options: {
          depth: advancedOptions.depth,
          excludePatterns: advancedOptions.excludePatterns
            ? advancedOptions.excludePatterns.split(',').map(p => p.trim())
            : [],
          failThreshold: advancedOptions.failThreshold,
          timeout: advancedOptions.timeout,
          parallel: advancedOptions.parallel,
        },
      });
      router.push(`/scans/${scan.id}`);
    } catch (err) {
      console.error('Failed to start scan:', err);
      setError(err instanceof Error ? err.message : 'Failed to start scan. Please try again.');
      setIsSubmitting(false);
    }
  };

  const handleProfileChange = (profileId: string) => {
    setSelectedProfile(profileId);
    if (profileId !== 'custom') {
      const profile = SCAN_PROFILES.find(p => p.id === profileId);
      if (profile) {
        setScanners(profile.scanners);
      }
    }
    // Custom profile keeps current scanner selection
  };

  const toggleScanner = (scannerId: string) => {
    setSelectedProfile('custom'); // Switch to custom when manually changing
    if (scanners.includes(scannerId)) {
      setScanners(scanners.filter(s => s !== scannerId));
    } else {
      setScanners([...scanners, scannerId]);
    }
  };

  const toggleCategory = (categoryId: string) => {
    setSelectedProfile('custom');
    const category = SCANNER_CATEGORIES.find(c => c.id === categoryId);
    if (!category) return;

    const categoryScannersIds = category.scanners.map(s => s.id);
    const allSelected = categoryScannersIds.every(id => scanners.includes(id));

    if (allSelected) {
      // Deselect all in category
      setScanners(scanners.filter(s => !categoryScannersIds.includes(s)));
    } else {
      // Select all in category
      setScanners([...new Set([...scanners, ...categoryScannersIds])]);
    }
  };

  const toggleCategoryExpanded = (categoryId: string) => {
    if (expandedCategories.includes(categoryId)) {
      setExpandedCategories(expandedCategories.filter(c => c !== categoryId));
    } else {
      setExpandedCategories([...expandedCategories, categoryId]);
    }
  };

  const selectAllScanners = () => {
    setSelectedProfile('full');
    setScanners(ALL_SCANNERS.map(s => s.id));
  };

  const deselectAllScanners = () => {
    setSelectedProfile('custom');
    setScanners([]);
  };

  return (
    <div className="max-w-2xl mx-auto">
      {/* Header */}
      <div className="mb-8">
        <Link
          href="/scans"
          className="flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary mb-4"
        >
          <ArrowLeft size={16} />
          Back to Scans
        </Link>

        <h1 className="text-2xl font-bold text-text-primary">Start New Scan</h1>
        <p className="text-text-secondary mt-1">
          Configure and run a security scan on your codebase
        </p>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="mb-6 p-4 rounded-lg bg-error/10 border border-error/20">
          <div className="flex items-center gap-2 text-error">
            <AlertTriangle size={16} />
            <span className="font-medium">Failed to start scan</span>
          </div>
          <p className="text-sm text-text-secondary mt-1">{error}</p>
        </div>
      )}

      {/* Form */}
      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Section 1: Project Selection */}
        <div className="card p-6">
          <h2 className="text-lg font-semibold text-text-primary mb-4">1. Select Project</h2>

          <div className="space-y-4">
            {/* Project Select */}
            <div>
              <label className="block text-sm font-medium text-text-primary mb-2">
                Project <span className="text-error">*</span>
              </label>
              <select
                value={projectId}
                onChange={e => {
                  setProjectId(e.target.value);
                  // Branch will be fetched via useEffect and set to default
                  setBranch('main');
                }}
                className="input w-full"
                disabled={isLoadingProjects}
              >
                <option value="">Select a project...</option>
                {projects.map(project => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Branch Select */}
            {projectId && (
              <div>
                <label className="block text-sm font-medium text-text-primary mb-2">
                  Branch
                </label>
                <div className="relative">
                  <select
                    value={branch}
                    onChange={e => setBranch(e.target.value)}
                    className="input w-full"
                    disabled={isLoadingBranches}
                  >
                    {branches.map(b => (
                      <option key={b.name} value={b.name}>
                        {b.name}
                        {b.isDefault && ' (default)'}
                      </option>
                    ))}
                  </select>
                  {isLoadingBranches && (
                    <Loader2 size={16} className="absolute right-10 top-1/2 -translate-y-1/2 animate-spin text-text-tertiary" />
                  )}
                </div>
              </div>
            )}

            {/* Quick Action */}
            <div className="pt-2">
              <Link
                href="/projects/new"
                className="text-sm text-primary-400 hover:text-primary-300"
              >
                Or scan a new repository...
              </Link>
            </div>
          </div>
        </div>

        {/* Section 2: Scan Profile */}
        <div className="card p-6">
          <h2 className="text-lg font-semibold text-text-primary mb-4">2. Choose Scan Profile</h2>
          <p className="text-sm text-text-secondary mb-4">
            Select a pre-configured profile or customize scanner selection
          </p>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-4">
            {SCAN_PROFILES.slice(0, 6).map(profile => {
              const Icon = profile.icon;
              const isSelected = selectedProfile === profile.id;

              return (
                <button
                  key={profile.id}
                  type="button"
                  onClick={() => handleProfileChange(profile.id)}
                  className={cn(
                    'flex flex-col items-center gap-2 p-4 rounded-lg border transition-all text-center',
                    isSelected
                      ? 'border-primary-500 bg-primary-500/10 ring-1 ring-primary-500'
                      : 'border-border-primary hover:border-border-secondary hover:bg-bg-hover'
                  )}
                >
                  <Icon size={20} className={isSelected ? 'text-primary-400' : 'text-text-secondary'} />
                  <div>
                    <div className="text-sm font-medium text-text-primary">{profile.name}</div>
                    <div className="text-xs text-text-tertiary">{profile.scanners.length} tools</div>
                  </div>
                </button>
              );
            })}
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {SCAN_PROFILES.slice(6).map(profile => {
              const Icon = profile.icon;
              const isSelected = selectedProfile === profile.id;

              return (
                <button
                  key={profile.id}
                  type="button"
                  onClick={() => handleProfileChange(profile.id)}
                  className={cn(
                    'flex flex-col items-center gap-2 p-3 rounded-lg border transition-all text-center',
                    isSelected
                      ? 'border-primary-500 bg-primary-500/10 ring-1 ring-primary-500'
                      : 'border-border-primary hover:border-border-secondary hover:bg-bg-hover'
                  )}
                >
                  <Icon size={16} className={isSelected ? 'text-primary-400' : 'text-text-secondary'} />
                  <div className="text-xs font-medium text-text-primary">{profile.name}</div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Section 3: Scanner Details */}
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold text-text-primary">3. Scanner Selection</h2>
              <p className="text-sm text-text-secondary">
                {scanners.length} of {ALL_SCANNERS.length} scanners selected
              </p>
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={selectAllScanners}
                className="text-sm text-primary-400 hover:text-primary-300"
              >
                Select All
              </button>
              <span className="text-text-tertiary">|</span>
              <button
                type="button"
                onClick={deselectAllScanners}
                className="text-sm text-text-secondary hover:text-text-primary"
              >
                Clear
              </button>
            </div>
          </div>

          <div className="space-y-3">
            {SCANNER_CATEGORIES.map(category => {
              const CategoryIcon = category.icon;
              const categoryScannersIds = category.scanners.map(s => s.id);
              const selectedCount = categoryScannersIds.filter(id => scanners.includes(id)).length;
              const allSelected = selectedCount === category.scanners.length;
              const someSelected = selectedCount > 0 && !allSelected;
              const isExpanded = expandedCategories.includes(category.id);

              return (
                <div key={category.id} className="border border-border-primary rounded-lg overflow-hidden">
                  {/* Category Header */}
                  <div
                    className={cn(
                      'flex items-center gap-3 p-3 cursor-pointer transition-colors',
                      allSelected ? 'bg-primary-500/5' : someSelected ? 'bg-primary-500/5' : 'hover:bg-bg-hover'
                    )}
                  >
                    <input
                      type="checkbox"
                      checked={allSelected}
                      ref={input => {
                        if (input) input.indeterminate = someSelected;
                      }}
                      onChange={() => toggleCategory(category.id)}
                      className="cursor-pointer"
                    />
                    <button
                      type="button"
                      onClick={() => toggleCategoryExpanded(category.id)}
                      className="flex-1 flex items-center gap-2 text-left"
                    >
                      <CategoryIcon size={16} className="text-text-secondary" />
                      <div className="flex-1">
                        <span className="font-medium text-text-primary">{category.name}</span>
                        <span className="text-xs text-text-tertiary ml-2">
                          ({selectedCount}/{category.scanners.length})
                        </span>
                      </div>
                      <ChevronDown
                        size={16}
                        className={cn(
                          'text-text-tertiary transition-transform',
                          isExpanded && 'rotate-180'
                        )}
                      />
                    </button>
                  </div>

                  {/* Individual Scanners */}
                  {isExpanded && (
                    <div className="border-t border-border-primary bg-bg-secondary/50 p-2 space-y-1">
                      {category.scanners.map(scanner => {
                        const isSelected = scanners.includes(scanner.id);
                        const readiness = getScannerReadiness(scanner.id);
                        return (
                          <label
                            key={scanner.id}
                            className={cn(
                              'flex items-center gap-3 p-2 rounded cursor-pointer transition-colors',
                              isSelected ? 'bg-primary-500/10' : 'hover:bg-bg-hover'
                            )}
                          >
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => toggleScanner(scanner.id)}
                            />
                            <div className="flex-1 min-w-0">
                              <span className="text-sm font-medium text-text-primary">{scanner.name}</span>
                              <span className="text-xs text-text-tertiary ml-2">{scanner.description}</span>
                            </div>
                            <div className="flex items-center gap-2 flex-shrink-0">
                              {readiness.status === 'ready' && isSelected && (
                                <span className="flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded-full bg-success/10 text-success border border-success/20">
                                  <CheckCircle size={10} />
                                  Ready
                                </span>
                              )}
                              {readiness.status === 'needs-config' && isSelected && (
                                <span
                                  className="flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded-full bg-warning/10 text-warning border border-warning/20"
                                  title={readiness.hint}
                                >
                                  <AlertTriangle size={10} />
                                  Needs config
                                </span>
                              )}
                              {isSelected && readiness.status !== 'needs-config' && readiness.status !== 'ready' && (
                                <CheckCircle size={14} className="text-primary-400" />
                              )}
                            </div>
                          </label>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {scanners.length === 0 && (
            <p className="text-sm text-error mt-3">
              Please select at least one scanner
            </p>
          )}
        </div>

        {/* Section 4: Advanced Options */}
        <div className="card p-6">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="w-full flex items-center justify-between"
          >
            <h2 className="text-lg font-semibold text-text-primary">4. Advanced Options</h2>
            <ChevronDown
              size={20}
              className={cn(
                'text-text-tertiary transition-transform',
                showAdvanced && 'rotate-180'
              )}
            />
          </button>

          {showAdvanced && (
            <div className="mt-4 pt-4 border-t border-border-primary space-y-4">
              {/* Per-Scan Overrides */}
              <div>
                <h3 className="text-sm font-semibold text-text-primary mb-3">Target Overrides</h3>
                <p className="text-xs text-text-tertiary mb-3">
                  Override project-level targets for this scan only. Leave blank to use project defaults.
                </p>
                <div className="space-y-3">
                  <div>
                    <label className="block text-xs font-medium text-text-primary mb-1">
                      Target URL Override
                    </label>
                    <input
                      type="text"
                      value={advancedOptions.targetUrlOverride}
                      onChange={e => setAdvancedOptions({ ...advancedOptions, targetUrlOverride: e.target.value })}
                      placeholder={selectedProject?.targetUrl || 'https://staging.myapp.com'}
                      className="input w-full"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-text-primary mb-1">
                      Container Image Override
                    </label>
                    <input
                      type="text"
                      value={advancedOptions.containerImageOverride}
                      onChange={e => setAdvancedOptions({ ...advancedOptions, containerImageOverride: e.target.value })}
                      placeholder={selectedProject?.containerImage || 'ghcr.io/org/app:latest'}
                      className="input w-full"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-text-primary mb-1">
                      OpenAPI Spec Override
                    </label>
                    <input
                      type="text"
                      value={advancedOptions.openapiSpecOverride}
                      onChange={e => setAdvancedOptions({ ...advancedOptions, openapiSpecOverride: e.target.value })}
                      placeholder={selectedProject?.openapiSpecPath || 'openapi.yaml'}
                      className="input w-full"
                    />
                  </div>
                </div>
              </div>

              {/* Scan Depth */}
              <div>
                <label className="block text-sm font-medium text-text-primary mb-2">
                  Scan Depth
                </label>
                <select
                  value={advancedOptions.depth}
                  onChange={e => setAdvancedOptions({ ...advancedOptions, depth: e.target.value as 'shallow' | 'full' })}
                  className="input w-full"
                >
                  <option value="shallow">Shallow (latest commit only)</option>
                  <option value="full">Full (entire history)</option>
                </select>
                <p className="text-xs text-text-tertiary mt-1">
                  Full scans check git history for secrets, but take longer
                </p>
              </div>

              {/* Exclude Patterns */}
              <div>
                <label className="block text-sm font-medium text-text-primary mb-2">
                  Exclude Patterns
                </label>
                <input
                  type="text"
                  value={advancedOptions.excludePatterns}
                  onChange={e => setAdvancedOptions({ ...advancedOptions, excludePatterns: e.target.value })}
                  placeholder="node_modules, dist, *.test.js"
                  className="input w-full"
                />
                <p className="text-xs text-text-tertiary mt-1">
                  Comma-separated glob patterns to exclude from scanning
                </p>
              </div>

              {/* Fail Threshold */}
              <div>
                <label className="block text-sm font-medium text-text-primary mb-2">
                  Fail Threshold
                </label>
                <select
                  value={advancedOptions.failThreshold}
                  onChange={e => setAdvancedOptions({ ...advancedOptions, failThreshold: e.target.value })}
                  className="input w-full"
                >
                  <option value="none">{"Don't fail (report only)"}</option>
                  <option value="critical">Fail on Critical</option>
                  <option value="high">Fail on High or above</option>
                  <option value="medium">Fail on Medium or above</option>
                  <option value="low">Fail on Low or above</option>
                </select>
              </div>

              {/* Timeout */}
              <div>
                <label className="block text-sm font-medium text-text-primary mb-2">
                  Timeout (minutes)
                </label>
                <input
                  type="number"
                  value={advancedOptions.timeout}
                  onChange={e => setAdvancedOptions({ ...advancedOptions, timeout: parseInt(e.target.value) || 30 })}
                  min={5}
                  max={120}
                  className="input w-32"
                />
              </div>

              {/* Parallel Execution */}
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={advancedOptions.parallel}
                  onChange={e => setAdvancedOptions({ ...advancedOptions, parallel: e.target.checked })}
                />
                <span className="text-sm text-text-primary">Run scanners in parallel (faster)</span>
              </label>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex items-center justify-end gap-3 pt-4">
          <Link
            href="/scans"
            className="px-4 py-2 text-sm border border-border-primary rounded-lg hover:bg-bg-hover transition-colors"
          >
            Cancel
          </Link>
          <button
            type="submit"
            disabled={!projectId || scanners.length === 0 || isSubmitting}
            className="btn-primary"
          >
            {isSubmitting ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                Starting...
              </>
            ) : (
              <>
                Start Scan
                <ArrowRight size={16} />
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
