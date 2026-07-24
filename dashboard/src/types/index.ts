// Core Types for Code Hardener Dashboard

export interface User {
  id: string;
  email: string;
  name?: string;
  firstName?: string;
  lastName?: string;
  avatarUrl?: string;
  role?: 'admin' | 'member' | 'viewer';
  plan?: 'free' | 'pro' | 'team' | 'enterprise';
  createdAt: string;
  updatedAt?: string;
}

export interface Project {
  id: string;
  name: string;
  description?: string;
  repositoryUrl?: string;
  repositoryProvider?: 'github' | 'gitlab' | 'bitbucket' | null;
  defaultBranch?: string;
  lastScanId?: string;
  lastScanAt?: string;
  lastScore?: number;
  targetUrl?: string;
  containerImage?: string;
  openapiSpecPath?: string;
  authConfigured?: boolean;
  registryCredentialsId?: string;
  createdAt: string;
  updatedAt: string;
}

export interface Scan {
  id: string;
  projectId: string;
  projectName: string;
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  scanType: string;
  score?: number;
  scoreRaw?: number;
  qualityLevel?: 'excellent' | 'good' | 'moderate' | 'poor' | 'critical';
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  toolsExecuted: number;
  duration?: number;
  branch?: string;
  commit?: string;
  triggeredBy?: string;
  startedAt?: string;
  completedAt?: string;
  createdAt: string;
}

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingStatus = 'open' | 'fixed' | 'ignored' | 'false_positive' | 'deferred';
export type Exploitability = 'confirmed' | 'likely' | 'theoretical' | 'unlikely';
export type DataflowMatch = 'confirmed' | 'sanitized' | 'no_match';

export interface Finding {
  id: string;
  title: string;
  titleSimple?: string;
  description: string;
  descriptionSimple?: string;
  severity: FindingSeverity;
  status: FindingStatus;
  scanner: string;
  filePath?: string;
  lineNumber?: number;
  columnNumber?: number;
  cwe?: string;
  cweId?: string;
  cve?: string;
  codeSnippet?: string;
  fixAvailable?: boolean;
  fixDescription?: string;
  fixCode?: string;
  owaspCategory?: string;
  ruleId?: string;
  toolName?: string;
  metadata?: Record<string, unknown>;
  projectId?: string;
  projectName?: string;
  scanId?: string;
  scanTrigger?: string;
  dismissedAt?: string;
  dismissedBy?: string;
  dismissedComment?: string;
  dismissedReason?: string;
  // Enrichment fields
  exploitability?: Exploitability;
  reachable?: boolean;
  dataflowMatch?: DataflowMatch;
  llmVerified?: boolean;
  createdAt?: string;
  updatedAt?: string;
}

export interface Attestation {
  id: string;
  scanId: string;
  projectId: string;
  projectName: string;
  score: number;
  attestationType: string;
  predicateType: string;
  subjectName: string | null;
  subjectDigest: string | null;
  signatureAlgorithm: string | null;
  rekorLogId: string | null;
  rekorLogIndex: number | null;
  transparencyLogUrl: string | null;
  isSigned: boolean;
  isVerifiable: boolean;
  hasCertificate: boolean;
  signedAt: string;
  createdAt: string;
}

export interface Policy {
  id: string;
  name: string;
  description?: string;
  isActive: boolean;
  rules: PolicyRule[];
  appliedToProjects: string[];
  createdAt: string;
  updatedAt: string;
}

export interface PolicyRule {
  id: string;
  name?: string;
  type: 'severity_threshold' | 'scanner_required' | 'score_minimum' | 'custom' | 'threshold';
  condition: string;
  value: string | number;
  severity?: FindingSeverity;
  threshold?: number;
}

export interface Report {
  id: string;
  title: string;
  description?: string;
  reportType: 'security_summary' | 'compliance' | 'vulnerability' | 'executive' | 'scan_detail';
  format: 'pdf' | 'html' | 'json' | 'csv' | 'markdown' | 'sarif';
  status: 'completed' | 'pending' | 'failed';
  fileUrl?: string;
  fileSize?: number;
  projectId?: string;
  projectName?: string;
  scanId?: string;
  generatedAt?: string;
  expiresAt?: string;
  createdAt: string;
}

export interface ScoreHistoryPoint {
  score: number;
  date: string;
  project: string;
}

export interface DashboardSummary {
  qualityScore: number;
  scoreTrend: 'up' | 'down' | 'stable';
  openFindings: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info?: number;
  };
  scansThisMonth: number;
  scanLimit: number | null; // null = unlimited
  projectCount: number;
  projectLimit: number | null;
  scoreHistory: ScoreHistoryPoint[];
  recentScans: Scan[];
  recentProjects: Project[];
  criticalFindings: Finding[];
}

export interface Notification {
  id: string;
  type: 'info' | 'warning' | 'error' | 'success';
  title: string;
  message: string;
  link?: string;
  read: boolean;
  createdAt: string;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  type?: 'live' | 'test';
  lastUsedAt?: string;
  expiresAt?: string;
  createdAt: string;
}

export interface TeamMember {
  id: string;
  userId?: string;
  email: string;
  name?: string;
  firstName?: string;
  lastName?: string;
  role: 'owner' | 'admin' | 'member' | 'viewer';
  status?: 'active' | 'pending' | 'disabled';
  invitedAt?: string;
  joinedAt: string;
}

export interface Webhook {
  id: string;
  url: string;
  events: string[];
  isActive: boolean;
  secret?: string;
  lastTriggeredAt?: string;
  failureCount: number;
  createdAt: string;
}

// Pagination
export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

// Filter types
export interface FindingsFilters {
  severity?: FindingSeverity[];
  projects?: string[];
  projectId?: string;
  scanners?: string[];
  statuses?: FindingStatus[];
  exploitability?: Exploitability[];
  search?: string;
}

export interface ScansFilters {
  projectId?: string;
  status?: Scan['status'];
  dateFrom?: string;
  dateTo?: string;
}

export interface ProjectsFilters {
  search?: string;
  scoreRange?: 'excellent' | 'good' | 'medium' | 'high' | 'critical';
  lastScan?: 'today' | 'week' | 'month' | 'never';
  repository?: 'github' | 'gitlab' | 'bitbucket' | 'none';
}
