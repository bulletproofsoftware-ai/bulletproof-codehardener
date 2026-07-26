/**
 * SSRF Prevention Validator (security-h003, SEC-008)
 *
 * Validates repository URLs to prevent Server-Side Request Forgery attacks.
 * - Blocks private IPv4/IPv6 ranges
 * - Allowlist: github.com, gitlab.com, bitbucket.org
 * - DNS resolution validation before clone
 * - Validates URL schemes (https only for production)
 */

import dns from 'dns/promises';
import { URL } from 'url';
import { createLogger } from '../../../utils/logger.js';
import type { SSRFValidationResult } from '../../../types/github.types.js';

const logger = createLogger('ssrf-validator');

// Allowed hosts for repository URLs
const ALLOWED_HOSTS = new Set([
  'github.com',
  'www.github.com',
  'gitlab.com',
  'www.gitlab.com',
  'bitbucket.org',
  'www.bitbucket.org',
]);

// Private IPv4 ranges (RFC 1918, RFC 5737, RFC 6598)
const PRIVATE_IPV4_RANGES = [
  { start: '10.0.0.0', end: '10.255.255.255' },      // 10.0.0.0/8
  { start: '172.16.0.0', end: '172.31.255.255' },    // 172.16.0.0/12
  { start: '192.168.0.0', end: '192.168.255.255' },  // 192.168.0.0/16
  { start: '127.0.0.0', end: '127.255.255.255' },    // 127.0.0.0/8 (loopback)
  { start: '169.254.0.0', end: '169.254.255.255' },  // 169.254.0.0/16 (link-local)
  { start: '100.64.0.0', end: '100.127.255.255' },   // 100.64.0.0/10 (CGN)
  { start: '0.0.0.0', end: '0.255.255.255' },        // 0.0.0.0/8
  { start: '192.0.0.0', end: '192.0.0.255' },        // 192.0.0.0/24
  { start: '192.0.2.0', end: '192.0.2.255' },        // 192.0.2.0/24 (TEST-NET-1)
  { start: '198.51.100.0', end: '198.51.100.255' },  // 198.51.100.0/24 (TEST-NET-2)
  { start: '203.0.113.0', end: '203.0.113.255' },    // 203.0.113.0/24 (TEST-NET-3)
  { start: '224.0.0.0', end: '239.255.255.255' },    // 224.0.0.0/4 (multicast)
  { start: '240.0.0.0', end: '255.255.255.255' },    // 240.0.0.0/4 (reserved)
];

// Private IPv6 prefixes
const PRIVATE_IPV6_PREFIXES = [
  '::1',              // Loopback
  'fe80::',           // Link-local
  'fc00::',           // Unique local (fc00::/7)
  'fd00::',           // Unique local (fc00::/7)
  'ff00::',           // Multicast
  '::ffff:0:0',       // IPv4-mapped
  '::ffff:127.',      // IPv4-mapped loopback
  '::ffff:10.',       // IPv4-mapped private
  '::ffff:172.16.',   // IPv4-mapped private
  '::ffff:192.168.',  // IPv4-mapped private
];

export class SSRFValidator {
  private readonly allowedHosts: Set<string>;
  private readonly allowInsecureSchemes: boolean;

  constructor(options: { allowInsecureSchemes?: boolean; additionalAllowedHosts?: string[] } = {}) {
    this.allowInsecureSchemes = options.allowInsecureSchemes || false;
    this.allowedHosts = new Set([
      ...ALLOWED_HOSTS,
      ...(options.additionalAllowedHosts || []),
    ]);
  }

  /**
   * Validate a repository URL for SSRF vulnerabilities
   */
  async validateUrl(urlString: string): Promise<SSRFValidationResult> {
    try {
      // Parse URL
      const url = new URL(urlString);

      // Validate scheme
      const schemeResult = this.validateScheme(url.protocol);
      if (!schemeResult.valid) {
        this.logSsrfAttempt(urlString, 'invalid_scheme', schemeResult.error!);
        return schemeResult;
      }

      // Validate host against allowlist
      const hostResult = this.validateHost(url.hostname);
      if (!hostResult.valid) {
        this.logSsrfAttempt(urlString, 'host_not_allowed', hostResult.error!);
        return hostResult;
      }

      // DNS resolution validation
      const dnsResult = await this.validateDnsResolution(url.hostname);
      if (!dnsResult.valid) {
        this.logSsrfAttempt(urlString, 'private_ip_detected', dnsResult.error!);
        return dnsResult;
      }

      // Validate port (only standard ports allowed)
      const portResult = this.validatePort(url.port, url.protocol);
      if (!portResult.valid) {
        this.logSsrfAttempt(urlString, 'non_standard_port', portResult.error!);
        return portResult;
      }

      // Check for URL manipulation attempts
      const manipulationResult = this.checkUrlManipulation(urlString, url);
      if (!manipulationResult.valid) {
        this.logSsrfAttempt(urlString, 'url_manipulation', manipulationResult.error!);
        return manipulationResult;
      }

      return { valid: true };
    } catch (error) {
      if (error instanceof TypeError) {
        this.logSsrfAttempt(urlString, 'invalid_url', 'Invalid URL format');
        return { valid: false, error: 'Invalid URL format' };
      }
      const message = `URL validation failed: ${(error as Error).message}`;
      this.logSsrfAttempt(urlString, 'validation_error', message);
      return { valid: false, error: message };
    }
  }

  /**
   * Validate URL scheme (https only in production)
   */
  private validateScheme(protocol: string): SSRFValidationResult {
    const normalizedProtocol = protocol.toLowerCase();

    if (normalizedProtocol === 'https:') {
      return { valid: true };
    }

    if (normalizedProtocol === 'http:' && this.allowInsecureSchemes) {
      return { valid: true };
    }

    if (normalizedProtocol === 'git:' || normalizedProtocol === 'ssh:') {
      return { valid: false, error: 'Git and SSH protocols are not supported. Use HTTPS URLs.' };
    }

    return { valid: false, error: `Invalid URL scheme: ${protocol}. Only HTTPS is allowed.` };
  }

  /**
   * Validate host against allowlist
   */
  private validateHost(hostname: string): SSRFValidationResult {
    const normalizedHost = hostname.toLowerCase();

    // Check if it's an IP address (not allowed, must use hostname)
    if (this.isIpAddress(normalizedHost)) {
      return { valid: false, error: 'IP addresses are not allowed. Use the hostname (e.g., github.com).' };
    }

    // Check against allowlist
    if (!this.allowedHosts.has(normalizedHost)) {
      return {
        valid: false,
        error: `Host '${normalizedHost}' is not in the allowed list. Allowed hosts: ${Array.from(this.allowedHosts).join(', ')}`,
      };
    }

    return { valid: true };
  }

  /**
   * Validate DNS resolution to ensure host doesn't resolve to private IP
   */
  private async validateDnsResolution(hostname: string): Promise<SSRFValidationResult> {
    try {
      // Resolve both IPv4 and IPv6
      const [ipv4Addresses, ipv6Addresses] = await Promise.all([
        dns.resolve4(hostname).catch(() => []),
        dns.resolve6(hostname).catch(() => []),
      ]);

      const allAddresses = [...ipv4Addresses, ...ipv6Addresses];

      if (allAddresses.length === 0) {
        return { valid: false, error: `DNS resolution failed for ${hostname}` };
      }

      // Check each resolved IP for private ranges
      for (const ip of ipv4Addresses) {
        if (this.isPrivateIPv4(ip)) {
          return {
            valid: false,
            error: `Host ${hostname} resolves to private IP ${ip}. This may indicate DNS rebinding attack.`,
          };
        }
      }

      for (const ip of ipv6Addresses) {
        if (this.isPrivateIPv6(ip)) {
          return {
            valid: false,
            error: `Host ${hostname} resolves to private IPv6 ${ip}. This may indicate DNS rebinding attack.`,
          };
        }
      }

      return { valid: true };
    } catch (error) {
      return { valid: false, error: `DNS resolution failed: ${(error as Error).message}` };
    }
  }

  /**
   * Validate port (only standard ports)
   */
  private validatePort(port: string, protocol: string): SSRFValidationResult {
    if (!port) {
      return { valid: true }; // Default port is fine
    }

    const portNum = parseInt(port, 10);

    if (protocol === 'https:' && portNum !== 443) {
      return { valid: false, error: 'Non-standard HTTPS port is not allowed. Use port 443.' };
    }

    if (protocol === 'http:' && portNum !== 80) {
      return { valid: false, error: 'Non-standard HTTP port is not allowed. Use port 80.' };
    }

    return { valid: true };
  }

  /**
   * Check for URL manipulation attempts
   */
  private checkUrlManipulation(original: string, parsed: URL): SSRFValidationResult {
    // Check for credentials in URL
    if (parsed.username || parsed.password) {
      return { valid: false, error: 'URLs with embedded credentials are not allowed.' };
    }

    // Check for backslash (can be used for URL confusion)
    if (original.includes('\\')) {
      return { valid: false, error: 'Backslashes in URLs are not allowed.' };
    }

    // Check for multiple @ signs (can be used for URL confusion)
    const atCount = (original.match(/@/g) || []).length;
    if (atCount > 1) {
      return { valid: false, error: 'Multiple @ characters in URL are not allowed.' };
    }

    // Check for encoded characters that might bypass validation
    const encodedPatterns = [
      '%00', '%0a', '%0d',  // Null, LF, CR
      '%2f%2f', '%5c',      // Encoded slashes
      '%40',                // Encoded @
    ];

    const lowerOriginal = original.toLowerCase();
    for (const pattern of encodedPatterns) {
      if (lowerOriginal.includes(pattern)) {
        return { valid: false, error: 'URL contains potentially malicious encoded characters.' };
      }
    }

    return { valid: true };
  }

  /**
   * Log an SSRF attempt detection (SEC-016-D)
   * Uses warn level for potential attacks, providing data for alerting systems.
   */
  private logSsrfAttempt(url: string, attemptType: string, reason: string): void {
    logger.warn({
      url: url.length > 200 ? url.substring(0, 200) + '...' : url,
      attemptType,
      reason,
      securityEvent: 'ssrf_attempt_blocked',
    }, `SSRF attempt blocked: ${attemptType}`);
  }

  /**
   * Check if string is an IP address
   */
  private isIpAddress(str: string): boolean {
    // IPv4 check
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(str)) {
      return true;
    }

    // IPv6 check (simplified)
    if (str.includes(':') && !str.includes('.')) {
      return true;
    }

    // IPv4-mapped IPv6
    if (str.startsWith('::ffff:')) {
      return true;
    }

    return false;
  }

  /**
   * Check if IPv4 address is in private range
   */
  private isPrivateIPv4(ip: string): boolean {
    const ipNum = this.ipv4ToNumber(ip);

    for (const range of PRIVATE_IPV4_RANGES) {
      const startNum = this.ipv4ToNumber(range.start);
      const endNum = this.ipv4ToNumber(range.end);

      if (ipNum >= startNum && ipNum <= endNum) {
        return true;
      }
    }

    return false;
  }

  /**
   * Convert IPv4 address to number for range comparison
   */
  private ipv4ToNumber(ip: string): number {
    const parts = ip.split('.').map(Number);
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
  }

  /**
   * Check if IPv6 address is in private range
   */
  private isPrivateIPv6(ip: string): boolean {
    const normalizedIp = ip.toLowerCase();

    for (const prefix of PRIVATE_IPV6_PREFIXES) {
      if (normalizedIp.startsWith(prefix.toLowerCase())) {
        return true;
      }
    }

    // Additional check for IPv4-mapped addresses
    if (normalizedIp.startsWith('::ffff:')) {
      const ipv4Part = normalizedIp.slice(7);
      if (this.isPrivateIPv4(ipv4Part)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Validate a GitHub repository URL specifically
   */
  async validateGitHubUrl(urlString: string): Promise<SSRFValidationResult> {
    const baseResult = await this.validateUrl(urlString);
    if (!baseResult.valid) {
      return baseResult;
    }

    try {
      const url = new URL(urlString);

      // Must be github.com. A bare endsWith('github.com') also accepts
      // look-alike hosts such as "evilgithub.com", so match the apex host
      // exactly and require a dot before the suffix for subdomains.
      const host = url.hostname.toLowerCase();
      if (host !== 'github.com' && !host.endsWith('.github.com')) {
        return { valid: false, error: 'URL must be a GitHub repository URL.' };
      }

      // Path should match owner/repo pattern
      const pathParts = url.pathname.split('/').filter(Boolean);
      if (pathParts.length < 2) {
        return { valid: false, error: 'Invalid GitHub repository URL format. Expected: https://github.com/owner/repo' };
      }

      // Validate owner and repo names
      const ownerRepoRegex = /^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/;
      const [owner, repo] = pathParts;

      if (!ownerRepoRegex.test(owner)) {
        return { valid: false, error: `Invalid repository owner name: ${owner}` };
      }

      // Remove .git suffix if present for validation
      const repoName = repo.replace(/\.git$/, '');
      if (!ownerRepoRegex.test(repoName)) {
        return { valid: false, error: `Invalid repository name: ${repoName}` };
      }

      return { valid: true };
    } catch {
      return { valid: false, error: 'Invalid GitHub repository URL format.' };
    }
  }

  /**
   * Extract owner and repo from GitHub URL
   */
  extractGitHubRepo(urlString: string): { owner: string; repo: string } | null {
    try {
      const url = new URL(urlString);
      const pathParts = url.pathname.split('/').filter(Boolean);

      if (pathParts.length < 2) {
        return null;
      }

      return {
        owner: pathParts[0],
        repo: pathParts[1].replace(/\.git$/, ''),
      };
    } catch {
      return null;
    }
  }
}

// Singleton instance
let ssrfValidatorInstance: SSRFValidator | null = null;

/**
 * Get the singleton SSRFValidator instance
 */
export function getSSRFValidator(): SSRFValidator {
  if (!ssrfValidatorInstance) {
    const isDev = process.env.NODE_ENV === 'development';
    ssrfValidatorInstance = new SSRFValidator({
      allowInsecureSchemes: isDev,
    });
  }
  return ssrfValidatorInstance;
}

/**
 * Reset the singleton instance (for testing)
 */
export function resetSSRFValidator(): void {
  ssrfValidatorInstance = null;
}
