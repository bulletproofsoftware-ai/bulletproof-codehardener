/**
 * CA-005: Data Flow Tracing
 * Traces data flow from user inputs to sinks
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { createLogger } from '../../../utils/logger.js';
import { safePath } from '../../../utils/safePath.js';
import type { DataFlow, DataFlowSource, DataFlowSink, ExtractedEndpoint } from '../types.js';
import { randomUUID } from 'crypto';

const logger = createLogger('dataflow-tracer');

// Source patterns - where user input enters the system
const SOURCE_PATTERNS: Record<DataFlowSource['type'], RegExp[]> = {
  user_input: [
    // Express/Node
    /req\.body\.([\w.]+)/gi,
    /req\.query\.([\w.]+)/gi,
    /req\.params\.([\w.]+)/gi,
    /req\.headers\[['"]([^'"]+)['"]\]/gi,
    /req\.cookies\.([\w.]+)/gi,
    // Flask/Python
    /request\.form\[['"]([^'"]+)['"]\]/gi,
    /request\.args\.([\w.]+)/gi,
    /request\.json\.([\w.]+)/gi,
    /request\.get_json\(\)/gi,
    // FastAPI
    /\basync\s+def\s+\w+\s*\([^)]*(\w+)\s*:\s*(?:str|int|dict|Body|Query|Path)/gi,
    // Django
    /request\.POST\[['"]([^'"]+)['"]\]/gi,
    /request\.GET\[['"]([^'"]+)['"]\]/gi,
    // Go
    /r\.FormValue\s*\(\s*['"]([^'"]+)['"]\s*\)/gi,
    /r\.URL\.Query\(\)\.Get\s*\(\s*['"]([^'"]+)['"]\s*\)/gi,
    /c\.Param\s*\(\s*['"]([^'"]+)['"]\s*\)/gi,
    // Java Spring
    /@RequestBody\s+(\w+)/gi,
    /@RequestParam\s*\([^)]*\)\s*(\w+)/gi,
    /@PathVariable\s*\([^)]*\)\s*(\w+)/gi,
    // Ruby/Rails
    /params\[:(\w+)\]/gi,
    /params\[['"](\w+)['"]\]/gi,
    // Generic
    /document\.getElementById\s*\(\s*['"][^'"]+['"]\s*\)\.value/gi,
    /getElementById\s*\(\s*['"][^'"]+['"]\s*\)\.value/gi,
  ],
  file: [
    /fs\.readFile\s*\(/gi,
    /fs\.readFileSync\s*\(/gi,
    /open\s*\(\s*['"][^'"]+['"]\s*,\s*['"]r/gi,
    /File\.read\s*\(/gi,
    /ioutil\.ReadFile\s*\(/gi,
    /Files\.readAllBytes\s*\(/gi,
  ],
  env: [
    /process\.env\.([\w]+)/gi,
    /os\.environ\[['"]([^'"]+)['"]\]/gi,
    /os\.Getenv\s*\(\s*['"]([^'"]+)['"]\s*\)/gi,
    /System\.getenv\s*\(\s*['"]([^'"]+)['"]\s*\)/gi,
    /ENV\[['"]([^'"]+)['"]\]/gi,
  ],
  db: [
    /\.query\s*\(/gi,
    /\.execute\s*\(/gi,
    /\.findOne\s*\(/gi,
    /\.find\s*\(/gi,
    /\.select\s*\(/gi,
    /cursor\.fetchone\s*\(/gi,
    /cursor\.fetchall\s*\(/gi,
  ],
  api: [
    /fetch\s*\(/gi,
    /axios\.\w+\s*\(/gi,
    /requests\.\w+\s*\(/gi,
    /http\.request\s*\(/gi,
    /urllib\.request/gi,
    /HttpClient/gi,
  ],
  config: [
    /config\.([\w.]+)/gi,
    /settings\.([\w.]+)/gi,
    /\.env/gi,
    /yaml\.load\s*\(/gi,
    /JSON\.parse\s*\(/gi,
  ],
};

// Sink patterns - where data goes out
const SINK_PATTERNS: Record<DataFlowSink['type'], RegExp[]> = {
  db: [
    /\.query\s*\(\s*['"`](?:INSERT|UPDATE|DELETE|SELECT)/gi,
    /\.execute\s*\(\s*['"`](?:INSERT|UPDATE|DELETE|SELECT)/gi,
    /\.raw\s*\(\s*['"`]/gi,
    /db\.\w+\.create\s*\(/gi,
    /db\.\w+\.update\s*\(/gi,
    /Model\.create\s*\(/gi,
    /cursor\.execute\s*\(\s*f?['"`]/gi,
    /db\.Exec\s*\(/gi,
    /jdbcTemplate\.\w+\s*\(/gi,
  ],
  file: [
    /fs\.writeFile\s*\(/gi,
    /fs\.writeFileSync\s*\(/gi,
    /fs\.appendFile\s*\(/gi,
    /open\s*\(\s*[^,]+,\s*['"]w/gi,
    /File\.write\s*\(/gi,
    /ioutil\.WriteFile\s*\(/gi,
    /Files\.write\s*\(/gi,
  ],
  response: [
    /res\.send\s*\(/gi,
    /res\.json\s*\(/gi,
    /res\.render\s*\(/gi,
    /res\.write\s*\(/gi,
    /return\s+jsonify\s*\(/gi,
    /return\s+render_template\s*\(/gi,
    /ResponseEntity/gi,
    /c\.JSON\s*\(/gi,
    /c\.String\s*\(/gi,
    /render\s+json:/gi,
  ],
  log: [
    /console\.log\s*\(/gi,
    /logger\.\w+\s*\(/gi,
    /logging\.\w+\s*\(/gi,
    /log\.\w+\s*\(/gi,
    /print\s*\(/gi,
    /System\.out\.println\s*\(/gi,
    /puts\s/gi,
  ],
  external_api: [
    /fetch\s*\(\s*['"][^'"]*\$\{/gi,
    /axios\.post\s*\(/gi,
    /requests\.post\s*\(/gi,
    /http\.Post\s*\(/gi,
    /HttpClient.*\.send\s*\(/gi,
  ],
  command: [
    // Detect command execution patterns
    /subprocess/gi,
    /Runtime\.getRuntime\(\)\.exec/gi,
    /system\s*\(/gi,
    /popen\s*\(/gi,
    /spawn\s*\(/gi,
  ],
  eval: [
    /eval\s*\(/gi,
    /new\s+Function\s*\(/gi,
    /setTimeout\s*\(\s*['"`]/gi,
    /setInterval\s*\(\s*['"`]/gi,
    /vm\.runInContext\s*\(/gi,
    /compile\s*\(/gi,
  ],
};

// Sanitization patterns
const SANITIZATION_PATTERNS = [
  /escape/gi,
  /sanitize/gi,
  /encode/gi,
  /htmlspecialchars/gi,
  /DOMPurify/gi,
  /xss/gi,
  /validator/gi,
  /clean/gi,
  /strip/gi,
  /parameterized/gi,
  /prepared/gi,
  /placeholder/gi,
];

// Validation patterns
const VALIDATION_PATTERNS = [
  /validate/gi,
  /isValid/gi,
  /check/gi,
  /verify/gi,
  /assert/gi,
  /schema/gi,
  /joi\./gi,
  /yup\./gi,
  /zod\./gi,
  /class-validator/gi,
  /pydantic/gi,
  /marshmallow/gi,
];

interface FileContent {
  path: string;
  content: string;
  relativePath: string;
}

/**
 * Read source files for dataflow analysis
 */
async function readSourceFiles(
  repoPath: string,
  maxFiles: number = 300
): Promise<FileContent[]> {
  const files: FileContent[] = [];
  const extensions = ['.js', '.ts', '.tsx', '.jsx', '.py', '.go', '.java', '.rb', '.php'];

  async function scan(dirPath: string): Promise<void> {
    if (files.length >= maxFiles) return;

    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        if (files.length >= maxFiles) break;

        const fullPath = safePath(dirPath, entry.name);
        const relativePath = path.relative(repoPath, fullPath);

        if (entry.isDirectory()) {
          if (['node_modules', '.git', 'vendor', 'dist', 'build', '__pycache__', 'venv', '.venv', 'target'].includes(entry.name)) {
            continue;
          }
          await scan(fullPath);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name);
          if (extensions.includes(ext)) {
            try {
              const content = await fs.readFile(fullPath, 'utf-8');
              if (content.length < 300000 && !content.includes('\0')) {
                files.push({ path: fullPath, content, relativePath });
              }
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
 * Find line number for a position
 */
function getLineNumber(content: string, position: number): number {
  return content.substring(0, position).split('\n').length;
}

/**
 * Check if content between source and sink has sanitization
 */
function hasSanitization(content: string): boolean {
  return SANITIZATION_PATTERNS.some(pattern => pattern.test(content));
}

/**
 * Check if content between source and sink has validation
 */
function hasValidation(content: string): boolean {
  return VALIDATION_PATTERNS.some(pattern => pattern.test(content));
}

/**
 * Determine risk level based on source, sink, and protections
 */
function determineRiskLevel(
  sourceType: DataFlowSource['type'],
  sinkType: DataFlowSink['type'],
  sanitized: boolean,
  validated: boolean
): DataFlow['riskLevel'] {
  // High-risk combinations
  const criticalSinks: DataFlowSink['type'][] = ['command', 'eval', 'db'];
  const highRiskSinks: DataFlowSink['type'][] = ['file', 'external_api', 'response'];

  const isUserInput = sourceType === 'user_input';

  if (isUserInput && criticalSinks.includes(sinkType)) {
    if (!sanitized && !validated) return 'critical';
    if (!sanitized || !validated) return 'high';
    return 'medium';
  }

  if (isUserInput && highRiskSinks.includes(sinkType)) {
    if (!sanitized && !validated) return 'high';
    if (!sanitized || !validated) return 'medium';
    return 'low';
  }

  if (sourceType === 'env' && sinkType === 'log') {
    return 'medium'; // Logging env vars might expose secrets
  }

  return 'low';
}

/**
 * Trace data flows in a single file
 */
function traceFlowsInFile(file: FileContent): DataFlow[] {
  const flows: DataFlow[] = [];

  // Find all sources
  const sources: Array<{ type: DataFlowSource['type']; match: RegExpMatchArray; position: number }> = [];

  for (const [sourceType, patterns] of Object.entries(SOURCE_PATTERNS)) {
    for (const pattern of patterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(file.content)) !== null) {
        sources.push({
          type: sourceType as DataFlowSource['type'],
          match,
          position: match.index,
        });
      }
    }
  }

  // Find all sinks
  const sinks: Array<{ type: DataFlowSink['type']; match: RegExpMatchArray; position: number }> = [];

  for (const [sinkType, patterns] of Object.entries(SINK_PATTERNS)) {
    for (const pattern of patterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(file.content)) !== null) {
        sinks.push({
          type: sinkType as DataFlowSink['type'],
          match,
          position: match.index,
        });
      }
    }
  }

  // For each source, find potential sinks (within same function scope approximation)
  for (const source of sources) {
    // Look for sinks within ~200 lines (approximation of function scope)
    const sourceLineCount = getLineNumber(file.content, source.position);
    const searchWindow = 200; // lines

    for (const sink of sinks) {
      const sinkLineCount = getLineNumber(file.content, sink.position);

      // Only consider sinks that come after the source within reasonable scope
      if (sinkLineCount >= sourceLineCount && sinkLineCount <= sourceLineCount + searchWindow) {
        // Get content between source and sink
        const betweenContent = file.content.substring(source.position, sink.position);

        const sanitized = hasSanitization(betweenContent);
        const validated = hasValidation(betweenContent);
        const riskLevel = determineRiskLevel(source.type, sink.type, sanitized, validated);

        // Only report flows with meaningful risk
        if (riskLevel === 'critical' || riskLevel === 'high' ||
            (riskLevel === 'medium' && source.type === 'user_input')) {

          const flow: DataFlow = {
            id: randomUUID(),
            source: {
              type: source.type,
              location: file.relativePath,
              variable: source.match[1] || source.match[0].substring(0, 50),
              line: sourceLineCount,
            },
            sink: {
              type: sink.type,
              location: file.relativePath,
              operation: sink.match[0].substring(0, 50),
              line: sinkLineCount,
            },
            path: [
              {
                file: file.relativePath,
                line: sourceLineCount,
                operation: 'source',
                variable: source.match[0].substring(0, 50),
              },
              {
                file: file.relativePath,
                line: sinkLineCount,
                operation: 'sink',
                variable: sink.match[0].substring(0, 50),
              },
            ],
            sanitized,
            validated,
            tainted: source.type === 'user_input' && !sanitized,
            riskLevel,
          };

          flows.push(flow);
        }
      }
    }
  }

  return flows;
}

/**
 * Trace data flows across a repository
 */
export async function traceDataFlows(
  repoPath: string,
  endpoints?: ExtractedEndpoint[]
): Promise<DataFlow[]> {
  logger.info({ repoPath, endpointCount: endpoints?.length }, 'Starting data flow tracing');

  const startTime = Date.now();
  const allFlows: DataFlow[] = [];

  const files = await readSourceFiles(repoPath);

  // Prioritize files that contain endpoints
  const endpointFiles = new Set(endpoints?.map(e => e.file) || []);
  const prioritizedFiles = files.sort((a, b) => {
    const aHasEndpoint = endpointFiles.has(a.relativePath) ? 0 : 1;
    const bHasEndpoint = endpointFiles.has(b.relativePath) ? 0 : 1;
    return aHasEndpoint - bHasEndpoint;
  });

  for (const file of prioritizedFiles) {
    const flows = traceFlowsInFile(file);
    allFlows.push(...flows);
  }

  // Deduplicate similar flows
  const uniqueFlows: DataFlow[] = [];
  const seen = new Set<string>();

  for (const flow of allFlows) {
    const key = `${flow.source.type}:${flow.source.location}:${flow.source.line}:${flow.sink.type}:${flow.sink.line}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueFlows.push(flow);
    }
  }

  // Sort by risk level
  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  uniqueFlows.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]);

  logger.info(
    {
      repoPath,
      flowCount: uniqueFlows.length,
      filesScanned: files.length,
      durationMs: Date.now() - startTime,
    },
    'Data flow tracing completed'
  );

  return uniqueFlows;
}

/**
 * Get flows by risk level
 */
export function getFlowsByRisk(flows: DataFlow[], riskLevel: DataFlow['riskLevel']): DataFlow[] {
  return flows.filter(f => f.riskLevel === riskLevel);
}

/**
 * Get critical and high risk flows
 */
export function getHighRiskFlows(flows: DataFlow[]): DataFlow[] {
  return flows.filter(f => f.riskLevel === 'critical' || f.riskLevel === 'high');
}

/**
 * Get tainted flows (user input without sanitization)
 */
export function getTaintedFlows(flows: DataFlow[]): DataFlow[] {
  return flows.filter(f => f.tainted);
}

/**
 * Get flows by sink type
 */
export function getFlowsBySinkType(flows: DataFlow[], sinkType: DataFlowSink['type']): DataFlow[] {
  return flows.filter(f => f.sink.type === sinkType);
}
