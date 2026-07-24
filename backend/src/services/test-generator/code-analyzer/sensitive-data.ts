/**
 * CA-006: Sensitive Data Detection
 * Identifies PII, credentials, and other sensitive data in source code
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { createLogger } from '../../../utils/logger.js';
import { safePath } from '../../../utils/safePath.js';
import type { SensitiveDataPoint } from '../types.js';

const logger = createLogger('sensitive-data');

// Sensitive data patterns
const SENSITIVE_PATTERNS: Record<SensitiveDataPoint['type'], Array<{
  pattern: RegExp;
  field: string;
  classification: string;
  riskLevel: SensitiveDataPoint['riskLevel'];
}>> = {
  pii: [
    // Names
    { pattern: /(?:first|last|full)[_-]?name/gi, field: 'name', classification: 'Personal Identifier', riskLevel: 'medium' },
    { pattern: /\buser[_-]?name\b/gi, field: 'username', classification: 'Personal Identifier', riskLevel: 'medium' },

    // Contact
    { pattern: /\bemail\b/gi, field: 'email', classification: 'Contact Information', riskLevel: 'medium' },
    { pattern: /phone[_-]?(?:number)?/gi, field: 'phone', classification: 'Contact Information', riskLevel: 'medium' },
    { pattern: /\baddress\b/gi, field: 'address', classification: 'Contact Information', riskLevel: 'medium' },
    { pattern: /zip[_-]?code/gi, field: 'zipCode', classification: 'Contact Information', riskLevel: 'low' },
    { pattern: /postal[_-]?code/gi, field: 'postalCode', classification: 'Contact Information', riskLevel: 'low' },

    // Government IDs
    { pattern: /\bssn\b|social[_-]?security/gi, field: 'ssn', classification: 'Government ID', riskLevel: 'critical' },
    { pattern: /passport[_-]?(?:number|no)?/gi, field: 'passport', classification: 'Government ID', riskLevel: 'critical' },
    { pattern: /driver[_-]?license/gi, field: 'driverLicense', classification: 'Government ID', riskLevel: 'critical' },
    { pattern: /national[_-]?id/gi, field: 'nationalId', classification: 'Government ID', riskLevel: 'critical' },
    { pattern: /tax[_-]?id/gi, field: 'taxId', classification: 'Government ID', riskLevel: 'critical' },

    // Biometric
    { pattern: /biometric/gi, field: 'biometric', classification: 'Biometric Data', riskLevel: 'critical' },
    { pattern: /fingerprint/gi, field: 'fingerprint', classification: 'Biometric Data', riskLevel: 'critical' },
    { pattern: /face[_-]?(?:id|data|scan)/gi, field: 'faceData', classification: 'Biometric Data', riskLevel: 'critical' },

    // Demographics
    { pattern: /\bdate[_-]?of[_-]?birth\b|\bdob\b/gi, field: 'dateOfBirth', classification: 'Demographic', riskLevel: 'medium' },
    { pattern: /\bbirth[_-]?date\b/gi, field: 'birthDate', classification: 'Demographic', riskLevel: 'medium' },
    { pattern: /\bage\b/gi, field: 'age', classification: 'Demographic', riskLevel: 'low' },
    { pattern: /\bgender\b|\bsex\b/gi, field: 'gender', classification: 'Demographic', riskLevel: 'low' },
    { pattern: /\bethnicity\b|\brace\b/gi, field: 'ethnicity', classification: 'Demographic', riskLevel: 'medium' },
  ],
  credential: [
    // Passwords
    { pattern: /\bpassword\b/gi, field: 'password', classification: 'Authentication', riskLevel: 'critical' },
    { pattern: /\bpasswd\b/gi, field: 'passwd', classification: 'Authentication', riskLevel: 'critical' },
    { pattern: /\bsecret\b/gi, field: 'secret', classification: 'Authentication', riskLevel: 'high' },

    // Tokens
    { pattern: /api[_-]?key/gi, field: 'apiKey', classification: 'API Credential', riskLevel: 'critical' },
    { pattern: /api[_-]?secret/gi, field: 'apiSecret', classification: 'API Credential', riskLevel: 'critical' },
    { pattern: /access[_-]?token/gi, field: 'accessToken', classification: 'Authentication', riskLevel: 'critical' },
    { pattern: /refresh[_-]?token/gi, field: 'refreshToken', classification: 'Authentication', riskLevel: 'critical' },
    { pattern: /bearer[_-]?token/gi, field: 'bearerToken', classification: 'Authentication', riskLevel: 'critical' },
    { pattern: /auth[_-]?token/gi, field: 'authToken', classification: 'Authentication', riskLevel: 'critical' },

    // Keys
    { pattern: /private[_-]?key/gi, field: 'privateKey', classification: 'Cryptographic', riskLevel: 'critical' },
    { pattern: /secret[_-]?key/gi, field: 'secretKey', classification: 'Cryptographic', riskLevel: 'critical' },
    { pattern: /encryption[_-]?key/gi, field: 'encryptionKey', classification: 'Cryptographic', riskLevel: 'critical' },

    // OAuth
    { pattern: /client[_-]?id/gi, field: 'clientId', classification: 'OAuth', riskLevel: 'medium' },
    { pattern: /client[_-]?secret/gi, field: 'clientSecret', classification: 'OAuth', riskLevel: 'critical' },

    // Database
    { pattern: /db[_-]?password/gi, field: 'dbPassword', classification: 'Database', riskLevel: 'critical' },
    { pattern: /database[_-]?password/gi, field: 'databasePassword', classification: 'Database', riskLevel: 'critical' },
    { pattern: /connection[_-]?string/gi, field: 'connectionString', classification: 'Database', riskLevel: 'critical' },
  ],
  financial: [
    // Cards
    { pattern: /credit[_-]?card/gi, field: 'creditCard', classification: 'Payment Card', riskLevel: 'critical' },
    { pattern: /card[_-]?number/gi, field: 'cardNumber', classification: 'Payment Card', riskLevel: 'critical' },
    { pattern: /\bcvv\b|\bcvc\b/gi, field: 'cvv', classification: 'Payment Card', riskLevel: 'critical' },
    { pattern: /expir(?:y|ation)[_-]?date/gi, field: 'expiryDate', classification: 'Payment Card', riskLevel: 'high' },

    // Bank
    { pattern: /bank[_-]?account/gi, field: 'bankAccount', classification: 'Banking', riskLevel: 'critical' },
    { pattern: /account[_-]?number/gi, field: 'accountNumber', classification: 'Banking', riskLevel: 'critical' },
    { pattern: /routing[_-]?number/gi, field: 'routingNumber', classification: 'Banking', riskLevel: 'critical' },
    { pattern: /\biban\b/gi, field: 'iban', classification: 'Banking', riskLevel: 'critical' },
    { pattern: /\bswift\b/gi, field: 'swift', classification: 'Banking', riskLevel: 'high' },

    // Financial
    { pattern: /\bsalary\b/gi, field: 'salary', classification: 'Financial', riskLevel: 'high' },
    { pattern: /\bincome\b/gi, field: 'income', classification: 'Financial', riskLevel: 'medium' },
    { pattern: /tax[_-]?return/gi, field: 'taxReturn', classification: 'Financial', riskLevel: 'critical' },
  ],
  health: [
    // Medical
    { pattern: /medical[_-]?record/gi, field: 'medicalRecord', classification: 'Medical', riskLevel: 'critical' },
    { pattern: /health[_-]?record/gi, field: 'healthRecord', classification: 'Medical', riskLevel: 'critical' },
    { pattern: /\bdiagnosis\b/gi, field: 'diagnosis', classification: 'Medical', riskLevel: 'critical' },
    { pattern: /prescription/gi, field: 'prescription', classification: 'Medical', riskLevel: 'high' },
    { pattern: /medication/gi, field: 'medication', classification: 'Medical', riskLevel: 'high' },

    // Insurance
    { pattern: /insurance[_-]?(?:id|number|policy)/gi, field: 'insuranceId', classification: 'Insurance', riskLevel: 'high' },
    { pattern: /patient[_-]?id/gi, field: 'patientId', classification: 'Medical', riskLevel: 'high' },

    // Conditions
    { pattern: /\ballergy\b|\ballergies\b/gi, field: 'allergy', classification: 'Medical', riskLevel: 'high' },
    { pattern: /blood[_-]?type/gi, field: 'bloodType', classification: 'Medical', riskLevel: 'medium' },
    { pattern: /genetic[_-]?data/gi, field: 'geneticData', classification: 'Medical', riskLevel: 'critical' },
  ],
  location: [
    // GPS
    { pattern: /\blatitude\b|\blat\b/gi, field: 'latitude', classification: 'Geolocation', riskLevel: 'medium' },
    { pattern: /\blongitude\b|\blng\b|\blon\b/gi, field: 'longitude', classification: 'Geolocation', riskLevel: 'medium' },
    { pattern: /geo[_-]?location/gi, field: 'geolocation', classification: 'Geolocation', riskLevel: 'medium' },
    { pattern: /\bcoordinates\b/gi, field: 'coordinates', classification: 'Geolocation', riskLevel: 'medium' },

    // IP
    { pattern: /\bip[_-]?address\b/gi, field: 'ipAddress', classification: 'Network', riskLevel: 'low' },
    { pattern: /\bclient[_-]?ip\b/gi, field: 'clientIp', classification: 'Network', riskLevel: 'low' },

    // Location
    { pattern: /home[_-]?address/gi, field: 'homeAddress', classification: 'Physical Location', riskLevel: 'high' },
    { pattern: /work[_-]?address/gi, field: 'workAddress', classification: 'Physical Location', riskLevel: 'medium' },
  ],
  custom: [],
};

// Encryption/masking patterns that indicate data protection
const PROTECTION_PATTERNS = [
  /encrypt/gi,
  /hash/gi,
  /bcrypt/gi,
  /argon2/gi,
  /scrypt/gi,
  /pbkdf2/gi,
  /cipher/gi,
  /mask/gi,
  /redact/gi,
  /obscure/gi,
  /\*{4,}/g,  // Masked data like ****
];

interface FileContent {
  path: string;
  content: string;
  relativePath: string;
}

/**
 * Read source files for sensitive data detection
 */
async function readSourceFiles(
  repoPath: string,
  maxFiles: number = 500
): Promise<FileContent[]> {
  const files: FileContent[] = [];
  const extensions = [
    '.js', '.ts', '.tsx', '.jsx', '.mjs', '.cjs',
    '.py', '.go', '.java', '.kt', '.rb', '.php',
    '.json', '.yaml', '.yml', '.env', '.config',
    '.sql', '.graphql', '.gql',
  ];

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
          // Also check for common sensitive file names
          const isEnvFile = entry.name.startsWith('.env') || entry.name.includes('.env.');
          const isConfigFile = entry.name.includes('config') || entry.name.includes('secrets');

          if (extensions.includes(ext) || isEnvFile || isConfigFile) {
            try {
              const content = await fs.readFile(fullPath, 'utf-8');
              if (content.length < 500000 && !content.includes('\0')) {
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
 * Check if data appears to be encrypted or masked
 */
function isProtected(content: string, position: number): { encrypted: boolean; masked: boolean } {
  // Check context around the match (200 chars before and after)
  const start = Math.max(0, position - 200);
  const end = Math.min(content.length, position + 200);
  const context = content.substring(start, end);

  const encrypted = PROTECTION_PATTERNS.some(p => p.test(context));
  const masked = /\*{4,}|x{4,}/gi.test(context);

  return { encrypted, masked };
}

/**
 * Get context around a match
 */
function getContext(content: string, position: number): string {
  const lineStart = content.lastIndexOf('\n', position) + 1;
  const lineEnd = content.indexOf('\n', position);
  return content.substring(lineStart, lineEnd === -1 ? content.length : lineEnd).trim();
}

/**
 * Detect sensitive data in a file
 */
function detectSensitiveInFile(file: FileContent): SensitiveDataPoint[] {
  const points: SensitiveDataPoint[] = [];
  const seen = new Set<string>();

  for (const [type, patterns] of Object.entries(SENSITIVE_PATTERNS)) {
    for (const { pattern, field, classification, riskLevel } of patterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;

      while ((match = regex.exec(file.content)) !== null) {
        const key = `${type}:${field}:${file.relativePath}:${match.index}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const line = getLineNumber(file.content, match.index);
        const { encrypted, masked } = isProtected(file.content, match.index);
        const context = getContext(file.content, match.index);

        points.push({
          type: type as SensitiveDataPoint['type'],
          field,
          file: file.relativePath,
          line,
          encrypted,
          masked,
          classification,
          context: context.length > 100 ? context.substring(0, 100) + '...' : context,
          riskLevel: encrypted || masked ? 'low' : riskLevel,
        });
      }
    }
  }

  return points;
}

/**
 * Find sensitive data in a repository
 */
export async function findSensitiveData(repoPath: string): Promise<SensitiveDataPoint[]> {
  logger.info({ repoPath }, 'Starting sensitive data detection');

  const startTime = Date.now();
  const allPoints: SensitiveDataPoint[] = [];

  const files = await readSourceFiles(repoPath);

  for (const file of files) {
    const points = detectSensitiveInFile(file);
    allPoints.push(...points);
  }

  // Deduplicate
  const uniquePoints: SensitiveDataPoint[] = [];
  const seen = new Set<string>();

  for (const point of allPoints) {
    const key = `${point.type}:${point.field}:${point.file}:${point.line}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniquePoints.push(point);
    }
  }

  // Sort by risk level
  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  uniquePoints.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]);

  logger.info(
    {
      repoPath,
      pointCount: uniquePoints.length,
      filesScanned: files.length,
      durationMs: Date.now() - startTime,
    },
    'Sensitive data detection completed'
  );

  return uniquePoints;
}

/**
 * Get sensitive data by type
 */
export function getSensitiveByType(
  points: SensitiveDataPoint[],
  type: SensitiveDataPoint['type']
): SensitiveDataPoint[] {
  return points.filter(p => p.type === type);
}

/**
 * Get unprotected sensitive data
 */
export function getUnprotectedData(points: SensitiveDataPoint[]): SensitiveDataPoint[] {
  return points.filter(p => !p.encrypted && !p.masked);
}

/**
 * Get high-risk sensitive data
 */
export function getHighRiskData(points: SensitiveDataPoint[]): SensitiveDataPoint[] {
  return points.filter(p => p.riskLevel === 'critical' || p.riskLevel === 'high');
}

/**
 * Get credentials
 */
export function getCredentials(points: SensitiveDataPoint[]): SensitiveDataPoint[] {
  return points.filter(p => p.type === 'credential');
}

/**
 * Get PII data
 */
export function getPII(points: SensitiveDataPoint[]): SensitiveDataPoint[] {
  return points.filter(p => p.type === 'pii');
}
