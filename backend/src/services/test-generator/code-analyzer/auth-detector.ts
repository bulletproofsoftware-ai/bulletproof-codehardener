/**
 * CA-004: Authentication Pattern Detection
 * Detects authentication mechanisms in source code
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { createLogger } from '../../../utils/logger.js';
import { safePath } from '../../../utils/safePath.js';
import type { AuthPattern } from '../types.js';

const logger = createLogger('auth-detector');

// Authentication pattern definitions
const AUTH_PATTERNS: Record<string, {
  type: AuthPattern['type'];
  patterns: RegExp[];
  library?: string;
  securityConcerns?: string[];
}> = {
  // JWT patterns
  jwt_jsonwebtoken: {
    type: 'jwt',
    patterns: [
      /require\s*\(\s*['"]jsonwebtoken['"]\s*\)/gi,
      /from\s+['"]jsonwebtoken['"]/gi,
      /jwt\.sign\s*\(/gi,
      /jwt\.verify\s*\(/gi,
      /jwt\.decode\s*\(/gi,
    ],
    library: 'jsonwebtoken',
    securityConcerns: ['Ensure proper algorithm validation', 'Use strong secrets'],
  },
  jwt_jose: {
    type: 'jwt',
    patterns: [
      /from\s+['"]jose['"]/gi,
      /require\s*\(\s*['"]jose['"]\s*\)/gi,
      /new\s+SignJWT\s*\(/gi,
      /jwtVerify\s*\(/gi,
    ],
    library: 'jose',
  },
  jwt_python: {
    type: 'jwt',
    patterns: [
      /import\s+jwt/gi,
      /from\s+jwt\s+import/gi,
      /jwt\.encode\s*\(/gi,
      /jwt\.decode\s*\(/gi,
      /PyJWT/gi,
    ],
    library: 'PyJWT',
  },

  // Session patterns
  session_express: {
    type: 'session',
    patterns: [
      /require\s*\(\s*['"]express-session['"]\s*\)/gi,
      /from\s+['"]express-session['"]/gi,
      /app\.use\s*\(\s*session\s*\(/gi,
      /req\.session/gi,
    ],
    library: 'express-session',
    securityConcerns: ['Use secure cookie settings', 'Implement session regeneration'],
  },
  session_flask: {
    type: 'session',
    patterns: [
      /from\s+flask\s+import.*session/gi,
      /session\s*\[\s*['"][^'"]+['"]\s*\]/gi,
      /Flask-Session/gi,
    ],
    library: 'Flask-Session',
  },
  session_django: {
    type: 'session',
    patterns: [
      /request\.session/gi,
      /SessionMiddleware/gi,
      /SESSION_ENGINE/gi,
    ],
    library: 'Django Sessions',
  },

  // OAuth patterns
  oauth_passport: {
    type: 'oauth',
    patterns: [
      /require\s*\(\s*['"]passport['"]\s*\)/gi,
      /from\s+['"]passport['"]/gi,
      /passport\.authenticate\s*\(/gi,
      /passport\.use\s*\(/gi,
      /passport-google-oauth/gi,
      /passport-github/gi,
      /passport-facebook/gi,
    ],
    library: 'Passport.js',
  },
  oauth_generic: {
    type: 'oauth',
    patterns: [
      /OAuth2Client/gi,
      /oauth2\.0/gi,
      /oauth_token/gi,
      /access_token/gi,
      /refresh_token/gi,
      /authorization_code/gi,
      /client_credentials/gi,
    ],
    securityConcerns: ['Validate redirect URIs', 'Use PKCE for public clients'],
  },

  // API Key patterns
  api_key: {
    type: 'api_key',
    patterns: [
      /api[_-]?key/gi,
      /apikey/gi,
      /x-api-key/gi,
      /Authorization.*api[_-]?key/gi,
      /req\.headers\[['"]x-api-key['"]\]/gi,
      /\.header\s*\(\s*['"]x-api-key['"]/gi,
    ],
    securityConcerns: ['Rotate keys regularly', 'Use secure key storage'],
  },

  // Basic Auth patterns
  basic_auth: {
    type: 'basic',
    patterns: [
      /basic-auth/gi,
      /express-basic-auth/gi,
      /Authorization.*Basic/gi,
      /basicAuth/gi,
      /HTTPBasicAuth/gi,
      /BasicAuthentication/gi,
    ],
    securityConcerns: ['Only use over HTTPS', 'Consider stronger auth methods'],
  },

  // Bearer Token patterns
  bearer: {
    type: 'bearer',
    patterns: [
      /Authorization.*Bearer/gi,
      /bearer\s+token/gi,
      /req\.headers\.authorization/gi,
      /\.split\s*\(\s*['"]Bearer\s*['"]\s*\)/gi,
    ],
  },

  // Firebase Auth
  firebase_auth: {
    type: 'custom',
    patterns: [
      /firebase\/auth/gi,
      /firebase-admin/gi,
      /verifyIdToken/gi,
      /createCustomToken/gi,
      /signInWith/gi,
    ],
    library: 'Firebase Auth',
  },

  // Auth0
  auth0: {
    type: 'oauth',
    patterns: [
      /auth0/gi,
      /express-jwt-authz/gi,
      /express-oauth2-jwt-bearer/gi,
      /@auth0\/nextjs-auth0/gi,
    ],
    library: 'Auth0',
  },

  // Clerk
  clerk: {
    type: 'custom',
    patterns: [
      /@clerk\/nextjs/gi,
      /@clerk\/clerk-sdk-node/gi,
      /ClerkProvider/gi,
      /useAuth\s*\(\s*\)/gi,
    ],
    library: 'Clerk',
  },

  // Supabase Auth
  supabase_auth: {
    type: 'custom',
    patterns: [
      /supabase\.auth/gi,
      /@supabase\/supabase-js/gi,
      /createClient\s*\(/gi,
      /signInWithPassword/gi,
    ],
    library: 'Supabase Auth',
  },

  // Go patterns
  go_jwt: {
    type: 'jwt',
    patterns: [
      /github\.com\/golang-jwt\/jwt/gi,
      /github\.com\/dgrijalva\/jwt-go/gi,
      /jwt\.Parse/gi,
      /jwt\.NewWithClaims/gi,
    ],
    library: 'golang-jwt',
  },

  // Spring Security
  spring_security: {
    type: 'custom',
    patterns: [
      /@EnableWebSecurity/gi,
      /@PreAuthorize/gi,
      /@Secured/gi,
      /SecurityContextHolder/gi,
      /UserDetailsService/gi,
      /AuthenticationManager/gi,
    ],
    library: 'Spring Security',
  },

  // Ruby/Rails
  devise: {
    type: 'custom',
    patterns: [
      /devise/gi,
      /current_user/gi,
      /authenticate_user!/gi,
      /before_action\s*:authenticate/gi,
    ],
    library: 'Devise',
  },
};

// Security concern patterns to detect
const SECURITY_CONCERNS: Array<{
  pattern: RegExp;
  concern: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}> = [
  {
    pattern: /algorithm\s*[=:]\s*['"]none['"]/gi,
    concern: 'JWT "none" algorithm vulnerability',
    severity: 'critical',
  },
  {
    pattern: /verify\s*[=:]\s*false/gi,
    concern: 'JWT verification disabled',
    severity: 'critical',
  },
  {
    pattern: /expiresIn\s*[=:]\s*['"]?\d{4,}[dhy]?['"]?/gi,
    concern: 'Very long token expiration time',
    severity: 'medium',
  },
  {
    pattern: /secure\s*[=:]\s*false/gi,
    concern: 'Insecure cookie configuration',
    severity: 'high',
  },
  {
    pattern: /httpOnly\s*[=:]\s*false/gi,
    concern: 'httpOnly cookie flag disabled',
    severity: 'high',
  },
  {
    pattern: /sameSite\s*[=:]\s*['"]none['"]/gi,
    concern: 'SameSite cookie set to none',
    severity: 'medium',
  },
  {
    pattern: /password\s*[=:]\s*['"][^'"]{1,8}['"]/gi,
    concern: 'Potentially weak hardcoded password',
    severity: 'high',
  },
  {
    pattern: /secret\s*[=:]\s*['"][^'"]{1,16}['"]/gi,
    concern: 'Potentially weak secret key',
    severity: 'high',
  },
];

interface FileContent {
  path: string;
  content: string;
  relativePath: string;
}

/**
 * Read source files for auth detection
 */
async function readSourceFiles(
  repoPath: string,
  extensions: string[],
  maxFiles: number = 500
): Promise<FileContent[]> {
  const files: FileContent[] = [];

  async function scan(dirPath: string): Promise<void> {
    if (files.length >= maxFiles) return;

    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        if (files.length >= maxFiles) break;

        const fullPath = safePath(dirPath, entry.name);
        const relativePath = path.relative(repoPath, fullPath);

        // Skip common non-source directories
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
              // Skip very large files or binary files
              if (content.length < 500000 && !content.includes('\0')) {
                files.push({ path: fullPath, content, relativePath });
              }
            } catch {
              // Skip files we can't read
            }
          }
        }
      }
    } catch {
      // Skip directories we can't access
    }
  }

  await scan(repoPath);
  return files;
}

/**
 * Find line number for a match position
 */
function getLineNumber(content: string, position: number): number {
  return content.substring(0, position).split('\n').length;
}

/**
 * Detect authentication patterns in a file
 */
function detectAuthInFile(file: FileContent): AuthPattern[] {
  const patterns: AuthPattern[] = [];
  const seenPatterns = new Set<string>();

  for (const [name, config] of Object.entries(AUTH_PATTERNS)) {
    for (const pattern of config.patterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;

      while ((match = regex.exec(file.content)) !== null) {
        const key = `${config.type}:${file.relativePath}:${match.index}`;
        if (seenPatterns.has(key)) continue;
        seenPatterns.add(key);

        const line = getLineNumber(file.content, match.index);

        // Check for associated security concerns
        const concerns: string[] = config.securityConcerns ? [...config.securityConcerns] : [];

        // Look for additional security concerns near this match
        const contextStart = Math.max(0, match.index - 500);
        const contextEnd = Math.min(file.content.length, match.index + 500);
        const context = file.content.substring(contextStart, contextEnd);

        for (const concernCheck of SECURITY_CONCERNS) {
          if (concernCheck.pattern.test(context)) {
            concerns.push(concernCheck.concern);
          }
        }

        patterns.push({
          type: config.type,
          file: file.relativePath,
          line,
          mechanism: name,
          library: config.library,
          securityConcerns: concerns.length > 0 ? [...new Set(concerns)] : undefined,
          indicators: [match[0].substring(0, 100)],
        });

        // Only report first match per pattern type per file
        break;
      }
    }
  }

  return patterns;
}

/**
 * Detect authentication patterns in a repository
 */
export async function detectAuthPatterns(repoPath: string): Promise<AuthPattern[]> {
  logger.info({ repoPath }, 'Starting auth pattern detection');

  const startTime = Date.now();
  const patterns: AuthPattern[] = [];

  // Common source file extensions
  const extensions = [
    '.js', '.ts', '.tsx', '.jsx', '.mjs', '.cjs',
    '.py', '.go', '.java', '.kt', '.rb', '.php',
    '.rs', '.cs', '.swift',
  ];

  const files = await readSourceFiles(repoPath, extensions);

  for (const file of files) {
    const filePatterns = detectAuthInFile(file);
    patterns.push(...filePatterns);
  }

  // Deduplicate by type and file
  const uniquePatterns: AuthPattern[] = [];
  const seen = new Set<string>();

  for (const pattern of patterns) {
    const key = `${pattern.type}:${pattern.mechanism}:${pattern.file}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniquePatterns.push(pattern);
    }
  }

  // Sort by file and line
  uniquePatterns.sort((a, b) => {
    const fileCompare = a.file.localeCompare(b.file);
    if (fileCompare !== 0) return fileCompare;
    return a.line - b.line;
  });

  logger.info(
    {
      repoPath,
      patternCount: uniquePatterns.length,
      filesScanned: files.length,
      durationMs: Date.now() - startTime,
    },
    'Auth pattern detection completed'
  );

  return uniquePatterns;
}

/**
 * Get patterns by authentication type
 */
export function getPatternsByType(
  patterns: AuthPattern[],
  type: AuthPattern['type']
): AuthPattern[] {
  return patterns.filter(p => p.type === type);
}

/**
 * Get patterns with security concerns
 */
export function getPatternsWithConcerns(patterns: AuthPattern[]): AuthPattern[] {
  return patterns.filter(p => p.securityConcerns && p.securityConcerns.length > 0);
}

/**
 * Check if repository uses specific auth type
 */
export function usesAuthType(patterns: AuthPattern[], type: AuthPattern['type']): boolean {
  return patterns.some(p => p.type === type);
}

/**
 * Get primary authentication method
 */
export function getPrimaryAuthMethod(patterns: AuthPattern[]): AuthPattern | undefined {
  if (patterns.length === 0) return undefined;

  // Count occurrences of each type
  const typeCounts = new Map<AuthPattern['type'], number>();
  for (const pattern of patterns) {
    typeCounts.set(pattern.type, (typeCounts.get(pattern.type) || 0) + 1);
  }

  // Find most common type
  let maxCount = 0;
  let primaryType: AuthPattern['type'] = 'none';
  for (const [type, count] of typeCounts.entries()) {
    if (count > maxCount) {
      maxCount = count;
      primaryType = type;
    }
  }

  // Return first pattern of that type
  return patterns.find(p => p.type === primaryType);
}
