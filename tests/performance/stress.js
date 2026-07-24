import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Rate } from 'k6/metrics';

/**
 * Code Hardener - Stress Test
 *
 * Tests the system beyond normal load to find breaking points.
 * Gradually increases load until the system shows stress.
 *
 * Usage: k6 run stress.js
 */

// Custom metrics
const errorRate = new Rate('error_rate');
const timeouts = new Counter('timeouts');

export const options = {
  stages: [
    { duration: '2m', target: 50 },    // Warm up
    { duration: '5m', target: 100 },   // Normal load
    { duration: '5m', target: 200 },   // High load
    { duration: '5m', target: 300 },   // Very high load
    { duration: '5m', target: 400 },   // Extreme load
    { duration: '3m', target: 0 },     // Recovery
  ],
  thresholds: {
    http_req_duration: ['p(95)<2000'],  // More lenient during stress
    http_req_failed: ['rate<0.1'],      // Allow up to 10% failure
    error_rate: ['rate<0.15'],          // Track our custom error rate
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:4000';
const MARKETING_URL = 'http://localhost:3000';

// Endpoints to stress test
const ENDPOINTS = [
  { url: `${BASE_URL}/health`, method: 'GET', name: 'health' },
  { url: `${BASE_URL}/api/version`, method: 'GET', name: 'version' },
  { url: `${BASE_URL}/api/projects`, method: 'GET', name: 'projects', auth: true },
  { url: `${BASE_URL}/api/scans`, method: 'GET', name: 'scans', auth: true },
  { url: `${BASE_URL}/api/findings`, method: 'GET', name: 'findings', auth: true },
  { url: `${MARKETING_URL}/`, method: 'GET', name: 'marketing-home' },
  { url: `${MARKETING_URL}/features`, method: 'GET', name: 'marketing-features' },
  { url: `${MARKETING_URL}/pricing`, method: 'GET', name: 'marketing-pricing' },
];

const TEST_USER = {
  email: 'test@codehardener.local',
  password: 'TestPassword123!',
};

export function setup() {
  const loginRes = http.post(`${BASE_URL}/api/auth/login`, JSON.stringify(TEST_USER), {
    headers: { 'Content-Type': 'application/json' },
  });

  let token = '';
  try {
    token = JSON.parse(loginRes.body).token;
  } catch {
    console.warn('Could not get auth token for stress test');
  }

  return { token };
}

export default function (data) {
  const authHeaders = data.token
    ? { Authorization: `Bearer ${data.token}` }
    : {};

  // Randomly select an endpoint
  const endpoint = ENDPOINTS[Math.floor(Math.random() * ENDPOINTS.length)];

  const params = {
    timeout: '10s',
    headers: endpoint.auth ? authHeaders : {},
  };

  group(endpoint.name, function () {
    let res;

    try {
      if (endpoint.method === 'GET') {
        res = http.get(endpoint.url, params);
      } else if (endpoint.method === 'POST') {
        res = http.post(endpoint.url, JSON.stringify(endpoint.body || {}), {
          ...params,
          headers: { ...params.headers, 'Content-Type': 'application/json' },
        });
      }

      const success = check(res, {
        [`${endpoint.name} status OK`]: (r) => r.status >= 200 && r.status < 500,
        [`${endpoint.name} not timeout`]: (r) => r.timings.duration < 10000,
      });

      errorRate.add(!success);

      if (res.timings.duration >= 10000) {
        timeouts.add(1);
      }
    } catch (e) {
      errorRate.add(true);
      timeouts.add(1);
      console.error(`Error on ${endpoint.name}: ${e.message}`);
    }
  });

  // Minimal sleep during stress test
  sleep(Math.random() * 0.5);
}

export function handleSummary(data) {
  const lines = [
    '',
    '=== Stress Test Summary ===',
    '',
    `Peak VUs: ${data.metrics.vus_max?.values?.max || 'N/A'}`,
    `Total Requests: ${data.metrics.http_reqs?.values?.count || 0}`,
    `Failed Requests: ${((data.metrics.http_req_failed?.values?.rate || 0) * 100).toFixed(2)}%`,
    `Timeouts: ${data.metrics.timeouts?.values?.count || 0}`,
    '',
    'Response Times:',
    `  avg: ${data.metrics.http_req_duration?.values?.avg?.toFixed(2) || 'N/A'}ms`,
    `  p95: ${data.metrics.http_req_duration?.values?.['p(95)']?.toFixed(2) || 'N/A'}ms`,
    `  p99: ${data.metrics.http_req_duration?.values?.['p(99)']?.toFixed(2) || 'N/A'}ms`,
    `  max: ${data.metrics.http_req_duration?.values?.max?.toFixed(2) || 'N/A'}ms`,
    '',
  ];

  // Identify breaking point
  const failRate = data.metrics.http_req_failed?.values?.rate || 0;
  const p95 = data.metrics.http_req_duration?.values?.['p(95)'] || 0;

  if (failRate > 0.1 || p95 > 2000) {
    lines.push('WARNING: System showed signs of stress');
    lines.push(`  Error rate: ${(failRate * 100).toFixed(2)}%`);
    lines.push(`  p95 latency: ${p95.toFixed(2)}ms`);
  } else {
    lines.push('System handled stress well');
  }

  console.log(lines.join('\n'));

  return {
    '/reports/stress-summary.json': JSON.stringify(data, null, 2),
  };
}
