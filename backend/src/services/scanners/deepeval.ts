import { exec } from 'child_process';
import { promisify } from 'util';
import { readFile } from 'fs/promises';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-deepeval');
const SCAN_TARGET = '/scan-target';

// Maximum file size to analyze (512KB) — skip generated/minified files
const MAX_FILE_SIZE = 512 * 1024;
// Maximum files to analyze to keep scan time reasonable
const MAX_FILES = 500;

// ─── Source file extensions to scan ────────────────────────────────
const SOURCE_EXTENSIONS = ['js', 'ts', 'jsx', 'tsx', 'py', 'go', 'java', 'rb'];
const EXTENSION_GLOB = SOURCE_EXTENSIONS.map(e => `-name "*.${e}"`).join(' -o ');

// ─── DEEPEVAL-001: Hallucinated API Patterns ────────────────────────
// Curated list of commonly hallucinated APIs per language/runtime.
// Each entry: { pattern, language, description, correctAlternative }
interface HallucinatedAPI {
  pattern: RegExp;
  language: string;
  description: string;
  correctAlternative: string;
}

const HALLUCINATED_APIS: HallucinatedAPI[] = [
  // Node.js fs hallucinations
  { pattern: /\bfs\.readFileAsync\s*\(/g, language: 'js/ts', description: 'fs.readFileAsync() does not exist', correctAlternative: 'fs.promises.readFile()' },
  { pattern: /\bfs\.writeFileAsync\s*\(/g, language: 'js/ts', description: 'fs.writeFileAsync() does not exist', correctAlternative: 'fs.promises.writeFile()' },
  { pattern: /\bfs\.existsAsync\s*\(/g, language: 'js/ts', description: 'fs.existsAsync() does not exist', correctAlternative: 'fs.promises.access() or fs.existsSync()' },
  { pattern: /\bfs\.mkdirAsync\s*\(/g, language: 'js/ts', description: 'fs.mkdirAsync() does not exist', correctAlternative: 'fs.promises.mkdir()' },
  { pattern: /\bfs\.readdirAsync\s*\(/g, language: 'js/ts', description: 'fs.readdirAsync() does not exist', correctAlternative: 'fs.promises.readdir()' },
  { pattern: /\bfs\.statAsync\s*\(/g, language: 'js/ts', description: 'fs.statAsync() does not exist', correctAlternative: 'fs.promises.stat()' },
  { pattern: /\bfs\.unlinkAsync\s*\(/g, language: 'js/ts', description: 'fs.unlinkAsync() does not exist', correctAlternative: 'fs.promises.unlink()' },
  { pattern: /\bfs\.copyFileAsync\s*\(/g, language: 'js/ts', description: 'fs.copyFileAsync() does not exist', correctAlternative: 'fs.promises.copyFile()' },

  // Node.js path hallucinations
  { pattern: /\bpath\.exists\s*\(/g, language: 'js/ts', description: 'path.exists() does not exist in Node.js path module', correctAlternative: 'fs.existsSync() or fs.promises.access()' },

  // Array/Object hallucinations (older Node contexts)
  { pattern: /\bObject\.hasOwn\s*\(/g, language: 'js/ts', description: 'Object.hasOwn() requires Node 16.9+ / ES2022', correctAlternative: 'Object.prototype.hasOwnProperty.call() for broader compatibility' },
  { pattern: /\bArray\.prototype\.findLast\s*\(/g, language: 'js/ts', description: 'Array.prototype.findLast() requires Node 18+ / ES2023', correctAlternative: 'Reverse iteration or lodash.findLast() for broader compatibility' },
  { pattern: /\.toSorted\s*\(/g, language: 'js/ts', description: '.toSorted() requires Node 20+ / ES2023', correctAlternative: '[...arr].sort() for broader compatibility' },
  { pattern: /\.toReversed\s*\(/g, language: 'js/ts', description: '.toReversed() requires Node 20+ / ES2023', correctAlternative: '[...arr].reverse() for broader compatibility' },
  { pattern: /\.toSpliced\s*\(/g, language: 'js/ts', description: '.toSpliced() requires Node 20+ / ES2023', correctAlternative: 'Array.prototype.slice() + splice() for broader compatibility' },

  // Express hallucinations
  { pattern: /\bapp\.listen\s*\(\s*\)\.then\b/g, language: 'js/ts', description: 'Express app.listen() does not return a Promise', correctAlternative: 'Use callback: app.listen(port, () => { ... })' },
  { pattern: /\breq\.body\.validate\s*\(/g, language: 'js/ts', description: 'req.body.validate() does not exist in Express', correctAlternative: 'Use a validation library (Joi, Zod, express-validator)' },

  // React hallucinations
  { pattern: /\buseEffectAsync\s*\(/g, language: 'js/ts', description: 'useEffectAsync() does not exist in React', correctAlternative: 'Use useEffect with async IIFE inside' },
  { pattern: /\buseState\.reset\s*\(/g, language: 'js/ts', description: 'useState.reset() does not exist in React', correctAlternative: 'Call setState with initial value' },

  // Python hallucinations
  { pattern: /\bos\.path\.makedirs\s*\(/g, language: 'py', description: 'os.path.makedirs() does not exist', correctAlternative: 'os.makedirs()' },
  { pattern: /\bjson\.parse\s*\(/g, language: 'py', description: 'json.parse() does not exist in Python', correctAlternative: 'json.loads()' },
  { pattern: /\bjson\.stringify\s*\(/g, language: 'py', description: 'json.stringify() does not exist in Python', correctAlternative: 'json.dumps()' },
  { pattern: /\bstring\.contains\s*\(/g, language: 'py', description: 'string.contains() is not a Python built-in string method', correctAlternative: 'Use "in" operator: substring in string' },
  { pattern: /\blist\.length\b/g, language: 'py', description: 'list.length does not exist in Python', correctAlternative: 'len(list)' },
  { pattern: /\bdict\.keys\s*\(\)\s*\[\s*\d+\s*\]/g, language: 'py', description: 'dict.keys()[index] does not work in Python 3 (returns a view, not a list)', correctAlternative: 'list(dict.keys())[index]' },
  { pattern: /\basyncio\.sleep\s*\(/g, language: 'py', description: 'asyncio.sleep() — verify this is called with await in async context', correctAlternative: 'await asyncio.sleep() (must be awaited)' },

  // Go hallucinations
  { pattern: /\bstrings\.Contains\s*\(/g, language: 'go', description: 'Verify strings.Contains import — commonly hallucinated without proper import', correctAlternative: 'import "strings" and use strings.Contains()' },
  { pattern: /\berrors\.Wrapf\s*\(/g, language: 'go', description: 'errors.Wrapf() does not exist in stdlib errors package', correctAlternative: 'fmt.Errorf("context: %w", err) for error wrapping' },
  { pattern: /\berrors\.Cause\s*\(/g, language: 'go', description: 'errors.Cause() does not exist in stdlib errors package', correctAlternative: 'errors.Unwrap() or errors.Is() / errors.As()' },
];

// ─── DEEPEVAL-002: Inconsistent Error Handling Patterns ─────────────
interface ErrorHandlingAnalysis {
  asyncCallsWithHandling: number;
  asyncCallsWithoutHandling: number;
  mixedPatterns: boolean;
  details: string[];
}

function analyzeErrorHandling(content: string, ext: string): ErrorHandlingAnalysis {
  const result: ErrorHandlingAnalysis = {
    asyncCallsWithHandling: 0,
    asyncCallsWithoutHandling: 0,
    mixedPatterns: false,
    details: [],
  };

  if (['js', 'ts', 'jsx', 'tsx'].includes(ext)) {
    // Count await expressions
    const awaitCalls = (content.match(/\bawait\s+/g) || []).length;
    // Count try blocks
    const tryBlocks = (content.match(/\btry\s*\{/g) || []).length;
    // Count .catch() chains
    const catchChains = (content.match(/\.catch\s*\(/g) || []).length;

    const handledCalls = tryBlocks + catchChains;

    // Only flag if there are enough async calls to make inconsistency meaningful
    if (awaitCalls >= 3) {
      // Heuristic: if we have both try/catch AND .catch() in the same file, patterns are mixed
      if (tryBlocks > 0 && catchChains > 0) {
        result.mixedPatterns = true;
        result.details.push(`Mixed error handling: ${tryBlocks} try/catch blocks and ${catchChains} .catch() chains`);
      }

      // If await calls significantly outnumber try blocks, some are unhandled
      if (awaitCalls > handledCalls * 2) {
        result.asyncCallsWithoutHandling = awaitCalls - handledCalls;
        result.asyncCallsWithHandling = handledCalls;
        result.details.push(`${awaitCalls} await calls but only ${handledCalls} error handlers`);
      }
    }

    // Check for empty catch blocks
    const emptyCatches = (content.match(/catch\s*\([^)]*\)\s*\{\s*\}/g) || []).length;
    if (emptyCatches > 0) {
      result.details.push(`${emptyCatches} empty catch block(s) — errors silently swallowed`);
      result.asyncCallsWithoutHandling += emptyCatches;
    }
  }

  if (ext === 'py') {
    // Count bare except / except Exception with pass
    const bareExcepts = (content.match(/except\s*:/g) || []).length;
    const passExcepts = (content.match(/except[\s\S]*?:\s*\n\s*pass\b/g) || []).length;

    if (bareExcepts > 0) {
      result.details.push(`${bareExcepts} bare except clause(s) — catches all exceptions including SystemExit`);
      result.asyncCallsWithoutHandling += bareExcepts;
    }
    if (passExcepts > 0) {
      result.details.push(`${passExcepts} except...pass block(s) — errors silently ignored`);
      result.asyncCallsWithoutHandling += passExcepts;
    }
  }

  if (ext === 'go') {
    // Check for _ = err pattern (ignoring errors)
    const ignoredErrors = (content.match(/_\s*=\s*\w+\.?\w*\(/g) || []).length;
    // Check for result, _ := patterns
    const discardedErrors = (content.match(/,\s*_\s*:?=\s*\w+\.?\w*\(/g) || []).length;

    if (ignoredErrors > 0) {
      result.details.push(`${ignoredErrors} explicitly ignored error return value(s)`);
      result.asyncCallsWithoutHandling += ignoredErrors;
    }
    if (discardedErrors > 0) {
      result.details.push(`${discardedErrors} discarded error return value(s) via _ pattern`);
      result.asyncCallsWithoutHandling += discardedErrors;
    }
  }

  return result;
}

// ─── DEEPEVAL-003: Dead/Unreachable Code Detection ──────────────────
interface DeadCodeMatch {
  description: string;
  lineNumber: number;
  snippet: string;
}

function detectDeadCode(content: string, ext: string): DeadCodeMatch[] {
  const matches: DeadCodeMatch[] = [];
  const lines = content.split('\n');

  if (['js', 'ts', 'jsx', 'tsx', 'java'].includes(ext)) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      const nextLine = (i + 1 < lines.length) ? lines[i + 1]?.trim() : '';

      // Code after return/throw (but not in switch/case or closing braces)
      if (/^(return\b|throw\b)/.test(line) && !line.endsWith('{')) {
        if (nextLine && !nextLine.startsWith('}') && !nextLine.startsWith('case ') &&
            !nextLine.startsWith('default:') && !nextLine.startsWith('//') &&
            !nextLine.startsWith('/*') && !nextLine.startsWith('*') &&
            nextLine !== '') {
          // Verify the next line isn't a closing brace for the enclosing block
          if (!/^[}\])];?\s*$/.test(nextLine)) {
            matches.push({
              description: 'Code after return/throw statement is unreachable',
              lineNumber: i + 2, // 1-indexed, pointing at the unreachable line
              snippet: `${line}\n${nextLine}`,
            });
          }
        }
      }
    }

    // Detect unused imports (JS/TS) — import that is never referenced in the rest of the file
    const importRegex = /^import\s+(?:\{([^}]+)\}|(\w+))\s+from\s+['"][^'"]+['"];?\s*$/gm;
    let importMatch: RegExpExecArray | null;
    while ((importMatch = importRegex.exec(content)) !== null) {
      const namedImports = importMatch[1];
      const defaultImport = importMatch[2];

      if (namedImports) {
        const names = namedImports.split(',').map(n => n.trim().split(/\s+as\s+/).pop()?.trim()).filter(Boolean);
        for (const name of names) {
          if (!name) continue;
          // Count occurrences of the name outside of import statements
          const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const usageRegex = new RegExp(`\\b${escaped}\\b`, 'g');
          const allMatches = content.match(usageRegex) || [];
          // If it only appears once (the import itself), it's unused
          if (allMatches.length <= 1) {
            const importLine = content.substring(0, importMatch.index).split('\n').length;
            matches.push({
              description: `Unused import: "${name}" is imported but never referenced`,
              lineNumber: importLine,
              snippet: importMatch[0].trim(),
            });
          }
        }
      }

      if (defaultImport && !['React', 'type'].includes(defaultImport)) {
        const escaped = defaultImport.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const usageRegex = new RegExp(`\\b${escaped}\\b`, 'g');
        const allMatches = content.match(usageRegex) || [];
        if (allMatches.length <= 1) {
          const importLine = content.substring(0, importMatch.index).split('\n').length;
          matches.push({
            description: `Unused import: "${defaultImport}" is imported but never referenced`,
            lineNumber: importLine,
            snippet: importMatch[0].trim(),
          });
        }
      }
    }
  }

  if (ext === 'py') {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      const nextLine = (i + 1 < lines.length) ? lines[i + 1]?.trim() : '';

      // Code after return/raise in Python (respecting indentation)
      if (/^(return\b|raise\b)/.test(line)) {
        if (nextLine && !nextLine.startsWith('#') && nextLine !== '' &&
            !nextLine.startsWith('except') && !nextLine.startsWith('elif') &&
            !nextLine.startsWith('else') && !nextLine.startsWith('finally') &&
            !nextLine.startsWith('def ') && !nextLine.startsWith('class ')) {
          // Check indentation: next line at same or deeper indentation is unreachable
          const currentIndent = (lines[i].match(/^(\s*)/) || ['', ''])[1].length;
          const nextIndent = (lines[i + 1]?.match(/^(\s*)/) || ['', ''])[1].length;
          if (nextIndent >= currentIndent && !/^\s*$/.test(lines[i + 1])) {
            matches.push({
              description: 'Code after return/raise statement is unreachable',
              lineNumber: i + 2,
              snippet: `${line}\n${nextLine}`,
            });
          }
        }
      }
    }
  }

  return matches;
}

// ─── DEEPEVAL-004: Copy-Paste Indicators ────────────────────────────
interface CopyPasteMatch {
  description: string;
  lineNumber: number;
  snippet: string;
}

function detectCopyPasteIndicators(content: string, filePath: string): CopyPasteMatch[] {
  const matches: CopyPasteMatch[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // TODO/FIXME comments that reference other projects or generic AI artifacts
    const todoMatch = line.match(/(?:\/\/|#|\/\*|\*)\s*(TODO|FIXME|HACK|XXX)\s*:?\s*(.+)/i);
    if (todoMatch) {
      const comment = todoMatch[2].toLowerCase();
      // References to other projects, boilerplate, or AI-specific markers
      if (/(?:from\s+\w+\s+project|copied\s+from|taken\s+from|borrowed\s+from|based\s+on\s+\w+\s+example|replace\s+with\s+your|change\s+this|update\s+this\s+to|insert\s+your|your[_\s]?(?:api[_\s]?key|secret|token|password)|placeholder)/.test(comment)) {
        matches.push({
          description: `Suspicious TODO/FIXME referencing external source or placeholder: "${todoMatch[0].trim()}"`,
          lineNumber: i + 1,
          snippet: line.trim(),
        });
      }
    }

    // Generic placeholder values that AI commonly leaves in
    if (/(?:your[_-]?api[_-]?key|your[_-]?secret|sk[_-]test[_-]|pk[_-]test[_-]|REPLACE[_-]?ME|CHANGEME|example\.com|localhost:\d{4}(?:\b))/.test(line) &&
        !line.trim().startsWith('//') && !line.trim().startsWith('#') && !line.trim().startsWith('*')) {
      // Skip if it's in a test file
      if (!filePath.includes('.test.') && !filePath.includes('.spec.') && !filePath.includes('__test__')) {
        matches.push({
          description: 'Placeholder value detected — likely copy-pasted from example or AI-generated template',
          lineNumber: i + 1,
          snippet: line.trim(),
        });
      }
    }
  }

  // Detect near-duplicate function bodies (same structure, different names)
  // Look for functions with very similar body structure within the same file
  const funcRegex = /(?:function\s+(\w+)|const\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[^=])\s*=>)\s*\{/g;
  const funcBodies: Array<{ name: string; startLine: number; bodyHash: string }> = [];
  let funcMatch: RegExpExecArray | null;

  while ((funcMatch = funcRegex.exec(content)) !== null) {
    const name = funcMatch[1] || funcMatch[2];
    const startPos = funcMatch.index + funcMatch[0].length;
    const startLine = content.substring(0, funcMatch.index).split('\n').length;

    // Extract function body by brace counting
    let depth = 1;
    let pos = startPos;
    while (pos < content.length && depth > 0) {
      if (content[pos] === '{') depth++;
      if (content[pos] === '}') depth--;
      pos++;
    }

    const body = content.substring(startPos, pos - 1).trim();
    // Normalize: strip variable names, whitespace, comments for structural comparison
    const normalized = body
      .replace(/\/\/.*$/gm, '')        // Strip single-line comments
      .replace(/\/\*[\s\S]*?\*\//g, '') // Strip multi-line comments
      .replace(/\b\w+\b/g, '_')        // Replace all identifiers with _
      .replace(/\s+/g, ' ')            // Normalize whitespace
      .trim();

    if (normalized.length > 50) { // Only compare non-trivial functions
      funcBodies.push({ name, startLine, bodyHash: normalized });
    }
  }

  // Compare function bodies for near-duplicates
  for (let i = 0; i < funcBodies.length; i++) {
    for (let j = i + 1; j < funcBodies.length; j++) {
      if (funcBodies[i].bodyHash === funcBodies[j].bodyHash) {
        matches.push({
          description: `Near-duplicate functions: "${funcBodies[i].name}" (line ${funcBodies[i].startLine}) and "${funcBodies[j].name}" (line ${funcBodies[j].startLine}) have identical structure`,
          lineNumber: funcBodies[j].startLine,
          snippet: `${funcBodies[i].name}() and ${funcBodies[j].name}() have the same structure with different names`,
        });
      }
    }
  }

  return matches;
}

// ─── DEEPEVAL-005: Over-Engineered Abstractions ─────────────────────
interface OverEngineeringMatch {
  description: string;
  lineNumber: number;
  snippet: string;
}

function detectOverEngineering(content: string, ext: string): OverEngineeringMatch[] {
  const matches: OverEngineeringMatch[] = [];
  const lines = content.split('\n');

  if (['js', 'ts', 'jsx', 'tsx'].includes(ext)) {
    // Detect single-method classes
    const classRegex = /^(\s*)(?:export\s+)?class\s+(\w+)/gm;
    let classMatch: RegExpExecArray | null;

    while ((classMatch = classRegex.exec(content)) !== null) {
      const className = classMatch[2];
      const classStart = classMatch.index;
      const classStartLine = content.substring(0, classStart).split('\n').length;

      // Find the class body
      const afterClass = content.substring(classStart);
      const braceStart = afterClass.indexOf('{');
      if (braceStart === -1) continue;

      let depth = 1;
      let pos = classStart + braceStart + 1;
      while (pos < content.length && depth > 0) {
        if (content[pos] === '{') depth++;
        if (content[pos] === '}') depth--;
        pos++;
      }

      const classBody = content.substring(classStart + braceStart + 1, pos - 1);
      // Count methods (excluding constructor)
      const methods = classBody.match(/(?:async\s+)?(?:static\s+)?(?:get\s+|set\s+)?(\w+)\s*\(/g) || [];
      const nonConstructorMethods = methods.filter(m => !m.includes('constructor'));

      if (nonConstructorMethods.length === 1) {
        matches.push({
          description: `Class "${className}" has only one method — consider using a plain function instead`,
          lineNumber: classStartLine,
          snippet: `class ${className} { /* 1 method */ }`,
        });
      }
    }

    // Detect wrapper functions that just pass through to another function
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      const nextLine = (i + 1 < lines.length) ? lines[i + 1]?.trim() : '';
      const lineAfterNext = (i + 2 < lines.length) ? lines[i + 2]?.trim() : '';

      // Pattern: function foo(args) { return bar(args); }
      const funcDeclMatch = line.match(/^(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)\s*(?::\s*\w+\s*)?\{$/);
      if (funcDeclMatch) {
        const funcName = funcDeclMatch[1];
        if (nextLine && /^return\s+\w+\s*\(/.test(nextLine) && lineAfterNext === '}') {
          matches.push({
            description: `Function "${funcName}" is a pass-through wrapper that just calls another function`,
            lineNumber: i + 1,
            snippet: `${line}\n  ${nextLine}\n}`,
          });
        }
      }
    }

    // Detect interfaces with only one implementation (TypeScript)
    if (['ts', 'tsx'].includes(ext)) {
      const interfaceRegex = /\binterface\s+(\w+)\s*\{/g;
      let ifaceMatch: RegExpExecArray | null;

      while ((ifaceMatch = interfaceRegex.exec(content)) !== null) {
        const ifaceName = ifaceMatch[1];
        // Check if interface is used with "implements" — if used exactly once, it's over-engineered
        const implementsRegex = new RegExp(`\\bimplements\\s+(?:\\w+,\\s*)*${ifaceName}\\b`, 'g');
        const implementations = content.match(implementsRegex) || [];

        if (implementations.length === 1) {
          const ifaceLine = content.substring(0, ifaceMatch.index).split('\n').length;
          matches.push({
            description: `Interface "${ifaceName}" has only one implementation — premature abstraction`,
            lineNumber: ifaceLine,
            snippet: `interface ${ifaceName} { ... } // implemented once`,
          });
        }
      }
    }
  }

  if (ext === 'py') {
    // Detect classes with only __init__ and one other method
    const pyClassRegex = /^class\s+(\w+)/gm;
    let pyClassMatch: RegExpExecArray | null;

    while ((pyClassMatch = pyClassRegex.exec(content)) !== null) {
      const className = pyClassMatch[1];
      const classStartLine = content.substring(0, pyClassMatch.index).split('\n').length;
      const classIndent = (lines[classStartLine - 1]?.match(/^(\s*)/) || ['', ''])[1].length;

      // Find all method definitions in this class (same or deeper indentation)
      let methodCount = 0;
      for (let i = classStartLine; i < lines.length; i++) {
        const currentIndent = (lines[i].match(/^(\s*)/) || ['', ''])[1].length;
        // If we hit a line at same or less indentation (not empty), we've left the class
        if (i > classStartLine && currentIndent <= classIndent && lines[i].trim() !== '') break;

        if (/^\s+def\s+\w+\s*\(/.test(lines[i]) && !/def\s+__init__/.test(lines[i])) {
          methodCount++;
        }
      }

      if (methodCount === 1) {
        matches.push({
          description: `Class "${className}" has only one method (besides __init__) — consider using a plain function`,
          lineNumber: classStartLine,
          snippet: `class ${className}: # 1 non-init method`,
        });
      }
    }
  }

  if (ext === 'java') {
    // Detect single-method interfaces
    const javaIfaceRegex = /\binterface\s+(\w+)\s*(?:extends\s+\w+(?:<[^>]+>)?\s*)?\{/g;
    let javaIfaceMatch: RegExpExecArray | null;

    while ((javaIfaceMatch = javaIfaceRegex.exec(content)) !== null) {
      const ifaceName = javaIfaceMatch[1];
      const ifaceStart = javaIfaceMatch.index + javaIfaceMatch[0].length;
      const ifaceLine = content.substring(0, javaIfaceMatch.index).split('\n').length;

      // Count method declarations in the interface
      let depth = 1;
      let pos = ifaceStart;
      while (pos < content.length && depth > 0) {
        if (content[pos] === '{') depth++;
        if (content[pos] === '}') depth--;
        pos++;
      }

      const ifaceBody = content.substring(ifaceStart, pos - 1);
      const methodDecls = ifaceBody.match(/\b\w+\s+\w+\s*\(/g) || [];

      // Single-method interfaces that aren't functional interfaces (@FunctionalInterface) are suspicious
      if (methodDecls.length === 1 && !content.substring(Math.max(0, javaIfaceMatch.index - 100), javaIfaceMatch.index).includes('@FunctionalInterface')) {
        matches.push({
          description: `Interface "${ifaceName}" has only one method — may be premature abstraction unless used as a functional interface`,
          lineNumber: ifaceLine,
          snippet: `interface ${ifaceName} { /* 1 method */ }`,
        });
      }
    }
  }

  return matches;
}

// ─── Scanner Entry Point ────────────────────────────────────────────

export async function runDeepEval(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Discover source files — hardcoded path, no user input (safe exec usage matching other scanners)
    const { stdout: fileList } = await execAsync(
      `find ${SCAN_TARGET} -type f \\( ${EXTENSION_GLOB} \\) ` +
      `-not -path '*/.git/*' ` +
      `-not -path '*/node_modules/*' ` +
      `-not -path '*/.venv/*' ` +
      `-not -path '*/venv/*' ` +
      `-not -path '*/__pycache__/*' ` +
      `-not -path '*/dist/*' ` +
      `-not -path '*/build/*' ` +
      `-not -path '*/.next/*' ` +
      `-not -path '*/vendor/*' ` +
      `-not -path '*/.cache/*' ` +
      `-not -path '*/coverage/*' ` +
      `-not -name '*.min.js' ` +
      `-not -name '*.min.ts' ` +
      `-not -name '*.bundle.js' ` +
      `-not -name '*.d.ts' ` +
      `-size -${MAX_FILE_SIZE}c ` +
      `2>/dev/null | head -${MAX_FILES}`,
      { maxBuffer: 10 * 1024 * 1024, timeout: 30000 }
    );

    const sourceFiles = fileList.trim().split('\n').filter(Boolean);

    if (sourceFiles.length === 0) {
      logger.info('No source files found for DeepEval analysis');
      return {
        scanner: 'deepeval',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: `No source files found (looked for: ${SOURCE_EXTENSIONS.join(', ')})`,
      };
    }

    logger.info({ fileCount: sourceFiles.length }, 'Starting DeepEval heuristic analysis');

    let filesAnalyzed = 0;
    let hallucinatedApiHits = 0;
    let errorHandlingHits = 0;
    let deadCodeHits = 0;
    let copyPasteHits = 0;
    let overEngineeringHits = 0;

    for (const filePath of sourceFiles) {
      let content: string;
      try {
        content = await readFile(filePath, 'utf-8');
      } catch {
        logger.debug({ filePath }, 'Could not read file, skipping');
        continue;
      }

      filesAnalyzed++;
      const relativePath = filePath.replace(`${SCAN_TARGET}/`, '').replace(/^\//, '');
      const ext = filePath.split('.').pop()?.toLowerCase() || '';
      const isTestFile = /\.(test|spec)\.[jt]sx?$/.test(filePath) || /test_\w+\.py$/.test(filePath) || filePath.endsWith('_test.go');

      // ── DEEPEVAL-001: Hallucinated APIs ──
      for (const api of HALLUCINATED_APIS) {
        // Check language match
        if (api.language === 'js/ts' && !['js', 'ts', 'jsx', 'tsx'].includes(ext)) continue;
        if (api.language === 'py' && ext !== 'py') continue;
        if (api.language === 'go' && ext !== 'go') continue;

        const apiMatches = [...content.matchAll(api.pattern)];
        for (const match of apiMatches) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          hallucinatedApiHits++;
          findings.push({
            ruleId: 'DEEPEVAL-001',
            severity: 'critical',
            title: `Hallucinated API: ${api.description}`,
            description: `${api.description}. This is a common pattern in AI-generated code where the model ` +
              `invents plausible-looking API calls that do not actually exist in the target runtime or library. ` +
              `This will cause a runtime error when executed.`,
            filePath: relativePath,
            lineNumber,
            columnNumber: null,
            codeSnippet: match[0],
            cweId: 'CWE-676',
            owaspCategory: 'A04:2021-Insecure Design',
            fixAvailable: true,
            fixDescription: `Replace with: ${api.correctAlternative}`,
            metadata: {
              category: 'hallucinated-api',
              language: api.language,
              detectedPattern: match[0],
              correctAlternative: api.correctAlternative,
            },
          });
        }
      }

      // ── DEEPEVAL-002: Inconsistent Error Handling ──
      if (!isTestFile) {
        const errorAnalysis = analyzeErrorHandling(content, ext);
        if (errorAnalysis.asyncCallsWithoutHandling > 2 || errorAnalysis.mixedPatterns) {
          errorHandlingHits++;
          const severity: Severity = errorAnalysis.asyncCallsWithoutHandling > 5 ? 'high' : 'medium';
          findings.push({
            ruleId: 'DEEPEVAL-002',
            severity,
            title: `Inconsistent error handling in ${relativePath}`,
            description: `Error handling patterns are inconsistent in this file. ` +
              errorAnalysis.details.join('. ') + '. ' +
              `AI-generated code often has inconsistent error handling because different parts of the file ` +
              `may have been generated in separate prompts or sessions, each using a different error handling approach.`,
            filePath: relativePath,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: null,
            cweId: 'CWE-755',
            owaspCategory: 'A04:2021-Insecure Design',
            fixAvailable: true,
            fixDescription: 'Standardize error handling: use either try/catch or .catch() consistently. ' +
              'Ensure all async operations have error handling. Remove empty catch blocks.',
            metadata: {
              category: 'inconsistent-error-handling',
              asyncCallsWithHandling: errorAnalysis.asyncCallsWithHandling,
              asyncCallsWithoutHandling: errorAnalysis.asyncCallsWithoutHandling,
              mixedPatterns: errorAnalysis.mixedPatterns,
              details: errorAnalysis.details,
            },
          });
        }
      }

      // ── DEEPEVAL-003: Dead/Unreachable Code ──
      const deadCodeMatches = detectDeadCode(content, ext);
      for (const match of deadCodeMatches) {
        deadCodeHits++;
        findings.push({
          ruleId: 'DEEPEVAL-003',
          severity: 'medium',
          title: `${match.description} in ${relativePath}:${match.lineNumber}`,
          description: `${match.description}. Dead and unreachable code is a common artifact of AI-generated code, ` +
            `often resulting from iterative generation where the AI adds new code paths without cleaning up old ones, ` +
            `or from copy-pasting patterns that include unused imports.`,
          filePath: relativePath,
          lineNumber: match.lineNumber,
          columnNumber: null,
          codeSnippet: match.snippet,
          cweId: 'CWE-561',
          owaspCategory: null,
          fixAvailable: true,
          fixDescription: 'Remove the unreachable/unused code. If the code was intentionally disabled, add a comment explaining why.',
          metadata: {
            category: 'dead-code',
            type: match.description.includes('import') ? 'unused-import' : 'unreachable-code',
          },
        });
      }

      // ── DEEPEVAL-004: Copy-Paste Indicators ──
      const copyPasteMatches = detectCopyPasteIndicators(content, relativePath);
      for (const match of copyPasteMatches) {
        copyPasteHits++;
        findings.push({
          ruleId: 'DEEPEVAL-004',
          severity: 'medium',
          title: `Copy-paste indicator in ${relativePath}:${match.lineNumber}`,
          description: `${match.description}. ` +
            `AI-generated code frequently includes artifacts from training data or template patterns, ` +
            `such as TODOs referencing other projects, placeholder credentials, or near-duplicate function ` +
            `blocks where variable names differ slightly but the logic is identical.`,
          filePath: relativePath,
          lineNumber: match.lineNumber,
          columnNumber: null,
          codeSnippet: match.snippet,
          cweId: 'CWE-398',
          owaspCategory: null,
          fixAvailable: true,
          fixDescription: 'Review and either remove the copy-paste artifact, replace placeholder values ' +
            'with real ones, or refactor duplicate functions into a single reusable function.',
          metadata: {
            category: 'copy-paste',
          },
        });
      }

      // ── DEEPEVAL-005: Over-Engineered Abstractions ──
      if (!isTestFile) {
        const overEngineeringMatches = detectOverEngineering(content, ext);
        for (const match of overEngineeringMatches) {
          overEngineeringHits++;
          findings.push({
            ruleId: 'DEEPEVAL-005',
            severity: 'low',
            title: `Over-engineered abstraction in ${relativePath}:${match.lineNumber}`,
            description: `${match.description}. ` +
              `AI code generators tend to produce enterprise-pattern abstractions (interfaces, factory classes, ` +
              `wrapper functions) even when the codebase is simple enough for direct implementation. ` +
              `Unnecessary abstractions increase cognitive load and maintenance burden.`,
            filePath: relativePath,
            lineNumber: match.lineNumber,
            columnNumber: null,
            codeSnippet: match.snippet,
            cweId: null,
            owaspCategory: null,
            fixAvailable: true,
            fixDescription: 'Evaluate whether the abstraction layer is justified by multiple implementations. ' +
              'If not, consider using a plain function or removing the intermediate layer.',
            metadata: {
              category: 'over-engineering',
            },
          });
        }
      }
    }

    const totalHits = hallucinatedApiHits + errorHandlingHits + deadCodeHits + copyPasteHits + overEngineeringHits;

    logger.info({
      filesAnalyzed,
      totalFindings: findings.length,
      hallucinatedApiHits,
      errorHandlingHits,
      deadCodeHits,
      copyPasteHits,
      overEngineeringHits,
    }, 'DeepEval analysis completed');

    return {
      scanner: 'deepeval',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: JSON.stringify({
        filesAnalyzed,
        totalHits,
        breakdown: {
          hallucinatedApis: hallucinatedApiHits,
          inconsistentErrorHandling: errorHandlingHits,
          deadCode: deadCodeHits,
          copyPasteIndicators: copyPasteHits,
          overEngineeredAbstractions: overEngineeringHits,
        },
      }, null, 2),
      evidence: {
        checksPerformed: [
          'Hallucinated API detection (curated list per language/runtime)',
          'Inconsistent error handling pattern analysis',
          'Dead/unreachable code detection (post-return/throw, unused imports)',
          'Copy-paste indicator scanning (placeholder values, TODO references, near-duplicate functions)',
          'Over-engineered abstraction detection (single-implementation interfaces, single-method classes, pass-through wrappers)',
        ],
        scanScope: `Heuristic analysis of ${filesAnalyzed} source files across ${SOURCE_EXTENSIONS.join(', ')}`,
        filesAnalyzed,
        rulesEvaluated: 5,
        configuration: `Max file size: ${MAX_FILE_SIZE / 1024}KB, Max files: ${MAX_FILES}, Extensions: ${SOURCE_EXTENSIONS.join(', ')}`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'DeepEval analysis failed');
    return {
      scanner: 'deepeval',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
