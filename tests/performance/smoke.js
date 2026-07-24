import http from 'k6/http';
import { check, sleep } from 'k6';

/**
 * Code Hardener - Smoke Test
 *
 * Quick sanity check to verify the system is working.
 * Low VUs, short duration.
 *
 * Usage: k6 run smoke.js
 */

export const options = {
  vus: 2,
  duration: '30s',
  thresholds: {
    http_req_duration: ['p(95)<500'],
    http_req_failed: ['rate<0.01'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:4000';

export default function () {
  // Health check
  const healthRes = http.get(`${BASE_URL}/health`);
  check(healthRes, {
    'health check returns 200': (r) => r.status === 200,
    'health check returns healthy': (r) => {
      try {
        return JSON.parse(r.body).status === 'healthy';
      } catch {
        return false;
      }
    },
  });

  sleep(1);

  // API version
  const versionRes = http.get(`${BASE_URL}/api/version`);
  check(versionRes, {
    'version returns 200': (r) => r.status === 200,
    'version has version field': (r) => {
      try {
        return JSON.parse(r.body).version !== undefined;
      } catch {
        return false;
      }
    },
  });

  sleep(1);

  // Marketing site home
  const marketingRes = http.get('http://localhost:3000');
  check(marketingRes, {
    'marketing home returns 200': (r) => r.status === 200,
    'marketing has content': (r) => r.body && r.body.length > 100,
  });

  sleep(1);
}

export function handleSummary(data) {
  return {
    'stdout': textSummary(data, { indent: '  ', enableColors: true }),
    '/reports/smoke-summary.json': JSON.stringify(data),
  };
}

function textSummary(data, _opts) {
  const lines = ['', '=== Smoke Test Summary ===', ''];

  const metrics = data.metrics;

  if (metrics.http_req_duration) {
    lines.push(`HTTP Request Duration:`);
    lines.push(`  avg: ${metrics.http_req_duration.values.avg.toFixed(2)}ms`);
    lines.push(`  p95: ${metrics.http_req_duration.values['p(95)'].toFixed(2)}ms`);
  }

  if (metrics.http_reqs) {
    lines.push(`HTTP Requests: ${metrics.http_reqs.values.count}`);
  }

  if (metrics.http_req_failed) {
    lines.push(`Failed Requests: ${(metrics.http_req_failed.values.rate * 100).toFixed(2)}%`);
  }

  lines.push('');

  const thresholds = data.thresholds || {};
  const allPassed = Object.values(thresholds).every(t => t.ok);

  if (allPassed) {
    lines.push('Status: PASSED');
  } else {
    lines.push('Status: FAILED');
    Object.entries(thresholds).forEach(([name, result]) => {
      if (!result.ok) {
        lines.push(`  - ${name}: FAILED`);
      }
    });
  }

  return lines.join('\n');
}
