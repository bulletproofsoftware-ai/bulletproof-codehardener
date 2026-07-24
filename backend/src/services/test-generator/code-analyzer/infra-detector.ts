/**
 * CA-008: Infrastructure Detection
 * Detects infrastructure files and configurations
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { createLogger } from '../../../utils/logger.js';
import { safePath } from '../../../utils/safePath.js';
import type { InfrastructureFile } from '../types.js';

const logger = createLogger('infra-detector');

// Infrastructure file patterns
const INFRA_PATTERNS: Record<InfrastructureFile['type'], {
  filenames: string[];
  extensions?: string[];
  patterns?: RegExp[];
}> = {
  dockerfile: {
    filenames: ['Dockerfile', 'dockerfile'],
    patterns: [/Dockerfile\..+/, /\.dockerfile$/],
  },
  'docker-compose': {
    filenames: ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'],
    patterns: [/docker-compose\..+\.ya?ml$/],
  },
  kubernetes: {
    filenames: [],
    extensions: ['.yaml', '.yml'],
    patterns: [/k8s/, /kubernetes/, /deployment\.ya?ml$/, /service\.ya?ml$/, /ingress\.ya?ml$/],
  },
  terraform: {
    filenames: [],
    extensions: ['.tf', '.tfvars'],
  },
  cloudformation: {
    filenames: ['template.yaml', 'template.yml', 'template.json', 'cloudformation.yaml', 'cloudformation.yml'],
    patterns: [/cloudformation/, /cfn/],
  },
  ansible: {
    filenames: ['ansible.cfg', 'playbook.yml', 'playbook.yaml', 'site.yml', 'site.yaml'],
    patterns: [/ansible/, /playbook/],
  },
  helm: {
    filenames: ['Chart.yaml', 'Chart.yml', 'values.yaml', 'values.yml'],
    patterns: [/charts?\//],
  },
  'github-actions': {
    filenames: [],
    patterns: [/\.github\/workflows\/.+\.ya?ml$/],
  },
  'gitlab-ci': {
    filenames: ['.gitlab-ci.yml', '.gitlab-ci.yaml'],
  },
  jenkinsfile: {
    filenames: ['Jenkinsfile', 'jenkinsfile'],
    patterns: [/Jenkinsfile\..+/],
  },
};

// Security concern patterns for each infrastructure type
const SECURITY_CONCERNS: Record<InfrastructureFile['type'], Array<{
  pattern: RegExp;
  concern: string;
}>> = {
  dockerfile: [
    { pattern: /FROM\s+\S+:latest/gi, concern: 'Using :latest tag is unpredictable' },
    { pattern: /USER\s+root/gi, concern: 'Running as root user' },
    { pattern: /--no-check-certificate/gi, concern: 'SSL certificate validation disabled' },
    { pattern: /ADD\s+https?:\/\//gi, concern: 'ADD from URL can be unpredictable, use COPY' },
    { pattern: /EXPOSE\s+22\b/gi, concern: 'SSH port exposed' },
    { pattern: /ENV\s+\w*PASSWORD\w*=/gi, concern: 'Password in environment variable' },
    { pattern: /ENV\s+\w*SECRET\w*=/gi, concern: 'Secret in environment variable' },
  ],
  'docker-compose': [
    { pattern: /privileged:\s*true/gi, concern: 'Privileged mode enabled' },
    { pattern: /network_mode:\s*["']?host/gi, concern: 'Host network mode used' },
    { pattern: /cap_add:/gi, concern: 'Additional capabilities added' },
    { pattern: /security_opt:.*seccomp:unconfined/gi, concern: 'Seccomp disabled' },
    { pattern: /volumes:.*\/var\/run\/docker\.sock/gi, concern: 'Docker socket mounted' },
  ],
  kubernetes: [
    { pattern: /privileged:\s*true/gi, concern: 'Privileged container' },
    { pattern: /hostNetwork:\s*true/gi, concern: 'Host network enabled' },
    { pattern: /hostPID:\s*true/gi, concern: 'Host PID namespace' },
    { pattern: /hostIPC:\s*true/gi, concern: 'Host IPC namespace' },
    { pattern: /runAsRoot:\s*true/gi, concern: 'Running as root' },
    { pattern: /allowPrivilegeEscalation:\s*true/gi, concern: 'Privilege escalation allowed' },
    { pattern: /readOnlyRootFilesystem:\s*false/gi, concern: 'Root filesystem is writable' },
    { pattern: /securityContext:\s*\{\}/gi, concern: 'Empty security context' },
  ],
  terraform: [
    { pattern: /cidr_blocks\s*=\s*\["0\.0\.0\.0\/0"\]/gi, concern: 'Open CIDR block (0.0.0.0/0)' },
    { pattern: /publicly_accessible\s*=\s*true/gi, concern: 'Resource publicly accessible' },
    { pattern: /encrypted\s*=\s*false/gi, concern: 'Encryption disabled' },
    { pattern: /enable_key_rotation\s*=\s*false/gi, concern: 'Key rotation disabled' },
    { pattern: /skip_final_snapshot\s*=\s*true/gi, concern: 'Final snapshot skipped' },
  ],
  cloudformation: [
    { pattern: /CidrIp:\s*0\.0\.0\.0\/0/gi, concern: 'Open CIDR block' },
    { pattern: /PubliclyAccessible:\s*true/gi, concern: 'Resource publicly accessible' },
    { pattern: /Encrypted:\s*false/gi, concern: 'Encryption disabled' },
  ],
  ansible: [
    { pattern: /become:\s*yes/gi, concern: 'Privilege escalation used' },
    { pattern: /become_user:\s*root/gi, concern: 'Running as root' },
    { pattern: /no_log:\s*false/gi, concern: 'Logging sensitive data' },
    { pattern: /validate_certs:\s*no/gi, concern: 'Certificate validation disabled' },
  ],
  helm: [
    { pattern: /privileged:\s*true/gi, concern: 'Privileged container' },
    { pattern: /runAsRoot:\s*true/gi, concern: 'Running as root' },
    { pattern: /hostNetwork:\s*true/gi, concern: 'Host network enabled' },
  ],
  'github-actions': [
    { pattern: /uses:\s*\S+@master/gi, concern: 'Using @master branch (unpinned)' },
    { pattern: /uses:\s*\S+@main/gi, concern: 'Using @main branch (unpinned)' },
    { pattern: /\$\{\{\s*github\.event\.issue\.body/gi, concern: 'Using untrusted input' },
    { pattern: /\$\{\{\s*github\.event\.pull_request\.body/gi, concern: 'Using untrusted input' },
  ],
  'gitlab-ci': [
    { pattern: /--insecure/gi, concern: 'Insecure flag used' },
    { pattern: /DOCKER_TLS_CERTDIR:\s*["']?["']?/gi, concern: 'Docker TLS disabled' },
  ],
  jenkinsfile: [
    { pattern: /withCredentials/gi, concern: 'Review credential handling' },
  ],
};

// Port detection patterns
const PORT_PATTERNS = [
  /EXPOSE\s+(\d+)/gi,
  /ports?:\s*(?:-\s*)?["']?(\d+)/gi,
  /containerPort:\s*(\d+)/gi,
  /hostPort:\s*(\d+)/gi,
  /port:\s*(\d+)/gi,
];

// Service detection patterns
const SERVICE_PATTERNS = [
  /image:\s*["']?([^"'\s]+)/gi,
  /FROM\s+([^\s]+)/gi,
  /uses:\s*["']?([^"'\s@]+)/gi,
];

// Volume detection patterns
const VOLUME_PATTERNS = [
  /volumes?:\s*(?:-\s*)?["']?([^"'\s:]+)/gi,
  /VOLUME\s+\[?"?([^\]"]+)/gi,
  /mountPath:\s*["']?([^"'\s]+)/gi,
];

interface FileContent {
  path: string;
  content: string;
  relativePath: string;
}

/**
 * Scan for infrastructure files
 */
async function findInfraFiles(repoPath: string): Promise<FileContent[]> {
  const files: FileContent[] = [];

  async function scan(dirPath: string, depth: number = 0): Promise<void> {
    if (depth > 10) return;

    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = safePath(dirPath, entry.name);
        const relativePath = path.relative(repoPath, fullPath);

        if (entry.isDirectory()) {
          if (['node_modules', '.git', 'vendor', 'dist', 'build', '__pycache__', 'venv', '.venv', 'target'].includes(entry.name)) {
            continue;
          }
          await scan(fullPath, depth + 1);
        } else if (entry.isFile()) {
          // Check if this is an infrastructure file
          let isInfraFile = false;

          for (const [, config] of Object.entries(INFRA_PATTERNS)) {
            // Check filenames
            if (config.filenames.includes(entry.name)) {
              isInfraFile = true;
              break;
            }

            // Check extensions
            if (config.extensions) {
              const ext = path.extname(entry.name);
              if (config.extensions.includes(ext)) {
                isInfraFile = true;
                break;
              }
            }

            // Check patterns
            if (config.patterns) {
              for (const pattern of config.patterns) {
                if (pattern.test(relativePath)) {
                  isInfraFile = true;
                  break;
                }
              }
            }

            if (isInfraFile) break;
          }

          if (isInfraFile) {
            try {
              const content = await fs.readFile(fullPath, 'utf-8');
              files.push({ path: fullPath, content, relativePath });
            } catch {
              // Skip unreadable files
            }
          }
        }
      }
    } catch {
      // Skip inaccessible directories
    }
  }

  await scan(repoPath);
  return files;
}

/**
 * Determine infrastructure type from file
 */
function determineInfraType(file: FileContent): InfrastructureFile['type'] | null {
  const filename = path.basename(file.relativePath);

  for (const [type, config] of Object.entries(INFRA_PATTERNS)) {
    // Check filenames
    if (config.filenames.includes(filename)) {
      return type as InfrastructureFile['type'];
    }

    // Check patterns on full path
    if (config.patterns) {
      for (const pattern of config.patterns) {
        if (pattern.test(file.relativePath)) {
          return type as InfrastructureFile['type'];
        }
      }
    }
  }

  // Check by extension
  const ext = path.extname(filename);
  for (const [type, config] of Object.entries(INFRA_PATTERNS)) {
    if (config.extensions?.includes(ext)) {
      // For .tf files, it's terraform
      if (ext === '.tf' || ext === '.tfvars') {
        return 'terraform';
      }

      // For YAML/YML, need to check content for Kubernetes
      if ((ext === '.yaml' || ext === '.yml') && isKubernetesManifest(file.content)) {
        return 'kubernetes';
      }

      return type as InfrastructureFile['type'];
    }
  }

  return null;
}

/**
 * Check if YAML content is a Kubernetes manifest
 */
function isKubernetesManifest(content: string): boolean {
  const k8sIndicators = [
    /apiVersion:\s*[\w/.]+/,
    /kind:\s*(Deployment|Service|Pod|ConfigMap|Secret|Ingress|StatefulSet|DaemonSet)/,
    /metadata:\s*\n\s*name:/,
    /spec:\s*\n\s*(containers|selector|template):/,
  ];

  return k8sIndicators.some(pattern => pattern.test(content));
}

/**
 * Extract ports from content
 */
function extractPorts(content: string): number[] {
  const ports: Set<number> = new Set();

  for (const pattern of PORT_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match;
    while ((match = regex.exec(content)) !== null) {
      const port = parseInt(match[1], 10);
      if (port > 0 && port <= 65535) {
        ports.add(port);
      }
    }
  }

  return Array.from(ports).sort((a, b) => a - b);
}

/**
 * Extract services from content
 */
function extractServices(content: string): string[] {
  const services: Set<string> = new Set();

  for (const pattern of SERVICE_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match;
    while ((match = regex.exec(content)) !== null) {
      const service = match[1].split(':')[0]; // Remove tag if present
      if (service && !service.includes('$') && !service.includes('{')) {
        services.add(service);
      }
    }
  }

  return Array.from(services);
}

/**
 * Extract volumes from content
 */
function extractVolumes(content: string): string[] {
  const volumes: Set<string> = new Set();

  for (const pattern of VOLUME_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match;
    while ((match = regex.exec(content)) !== null) {
      const volume = match[1].trim();
      if (volume && !volume.includes('$') && !volume.includes('{')) {
        volumes.add(volume);
      }
    }
  }

  return Array.from(volumes);
}

/**
 * Find security concerns in content
 */
function findSecurityConcerns(content: string, type: InfrastructureFile['type']): string[] {
  const concerns: Set<string> = new Set();
  const patterns = SECURITY_CONCERNS[type] || [];

  for (const { pattern, concern } of patterns) {
    if (pattern.test(content)) {
      concerns.add(concern);
    }
  }

  return Array.from(concerns);
}

/**
 * Analyze an infrastructure file
 */
function analyzeInfraFile(file: FileContent): InfrastructureFile | null {
  const type = determineInfraType(file);
  if (!type) return null;

  return {
    type,
    path: file.relativePath,
    securityConcerns: findSecurityConcerns(file.content, type),
    services: extractServices(file.content),
    ports: extractPorts(file.content),
    volumes: extractVolumes(file.content),
  };
}

/**
 * Detect infrastructure files in a repository
 */
export async function detectInfrastructure(repoPath: string): Promise<InfrastructureFile[]> {
  logger.info({ repoPath }, 'Starting infrastructure detection');

  const startTime = Date.now();
  const results: InfrastructureFile[] = [];

  const files = await findInfraFiles(repoPath);

  for (const file of files) {
    const result = analyzeInfraFile(file);
    if (result) {
      results.push(result);
    }
  }

  // Sort by type and path
  results.sort((a, b) => {
    const typeCompare = a.type.localeCompare(b.type);
    if (typeCompare !== 0) return typeCompare;
    return a.path.localeCompare(b.path);
  });

  logger.info(
    {
      repoPath,
      infraFileCount: results.length,
      filesScanned: files.length,
      durationMs: Date.now() - startTime,
    },
    'Infrastructure detection completed'
  );

  return results;
}

/**
 * Get infrastructure files by type
 */
export function getInfraByType(
  infra: InfrastructureFile[],
  type: InfrastructureFile['type']
): InfrastructureFile[] {
  return infra.filter(i => i.type === type);
}

/**
 * Get infrastructure files with security concerns
 */
export function getInfraWithConcerns(infra: InfrastructureFile[]): InfrastructureFile[] {
  return infra.filter(i => i.securityConcerns && i.securityConcerns.length > 0);
}

/**
 * Check if repository uses Docker
 */
export function usesDocker(infra: InfrastructureFile[]): boolean {
  return infra.some(i => i.type === 'dockerfile' || i.type === 'docker-compose');
}

/**
 * Check if repository uses Kubernetes
 */
export function usesKubernetes(infra: InfrastructureFile[]): boolean {
  return infra.some(i => i.type === 'kubernetes' || i.type === 'helm');
}

/**
 * Check if repository uses CI/CD
 */
export function usesCICD(infra: InfrastructureFile[]): boolean {
  return infra.some(i =>
    i.type === 'github-actions' ||
    i.type === 'gitlab-ci' ||
    i.type === 'jenkinsfile'
  );
}
