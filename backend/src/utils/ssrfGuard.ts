import { lookup } from 'node:dns/promises';
import net from 'node:net';

/**
 * SSRF protection for outbound requests to user-supplied URLs.
 *
 * Webhook targets are registered by users and then fetched by the backend, so
 * without a check a user can point one at an internal service — container
 * networking, a database admin port, or cloud metadata on 169.254.169.254 —
 * and use this server as a proxy into the private network.
 */

const BLOCKED_V4 = [
  { net: '127.0.0.0', bits: 8 },    // loopback
  { net: '10.0.0.0', bits: 8 },     // RFC1918
  { net: '172.16.0.0', bits: 12 },  // RFC1918
  { net: '192.168.0.0', bits: 16 }, // RFC1918
  { net: '169.254.0.0', bits: 16 }, // link-local / cloud metadata
  { net: '0.0.0.0', bits: 8 },      // "this" network
  { net: '100.64.0.0', bits: 10 },  // carrier-grade NAT
];

function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;
}

function isBlockedV4(ip: string): boolean {
  const addr = ipv4ToInt(ip);
  return BLOCKED_V4.some(({ net: base, bits }) => {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (addr & mask) === (ipv4ToInt(base) & mask);
  });
}

function isBlockedV6(ip: string): boolean {
  const v = ip.toLowerCase();
  if (v === '::1' || v === '::') return true;          // loopback / unspecified
  if (v.startsWith('fe80')) return true;                // link-local
  if (v.startsWith('fc') || v.startsWith('fd')) return true; // unique local
  // IPv4-mapped (::ffff:a.b.c.d) — judge on the embedded v4 address.
  const mapped = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isBlockedV4(mapped[1]);
  return false;
}

export class SsrfBlockedError extends Error {}

/**
 * Throws SsrfBlockedError unless `rawUrl` is an http(s) URL that resolves
 * only to public addresses.
 */
export async function assertPublicUrl(rawUrl: string): Promise<URL> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new SsrfBlockedError(`invalid URL: ${rawUrl}`);
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SsrfBlockedError(`blocked scheme: ${url.protocol}`);
  }

  const host = url.hostname.replace(/^\[|\]$/g, '');

  // A literal IP needs no DNS round trip.
  if (net.isIP(host)) {
    const blocked = net.isIPv4(host) ? isBlockedV4(host) : isBlockedV6(host);
    if (blocked) throw new SsrfBlockedError(`blocked address: ${host}`);
    return url;
  }

  let records: Array<{ address: string; family: number }>;
  try {
    records = await lookup(host, { all: true });
  } catch {
    throw new SsrfBlockedError(`DNS resolution failed for ${host}`);
  }

  // Every answer must be public: one internal record is enough to abuse.
  for (const { address, family } of records) {
    const blocked = family === 4 ? isBlockedV4(address) : isBlockedV6(address);
    if (blocked) {
      throw new SsrfBlockedError(`${host} resolves to internal address ${address}`);
    }
  }
  return url;
}
