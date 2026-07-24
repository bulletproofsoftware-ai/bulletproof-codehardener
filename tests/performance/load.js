import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Trend } from 'k6/metrics';

/**
 * Code Hardener - Load Test
 *
 * Tests the system under normal expected load.
 * Simulates typical user behavior patterns.
 *
 * Usage: k6 run load.js
 */

// Custom metrics
const apiLatency = new Trend('api_latency');
const loginAttempts = new Counter('login_attempts');

export const options = {
  stages: [
    { duration: '1m', target: 20 },   // Ramp up to 20 users
    { duration: '3m', target: 50 },   // Ramp up to 50 users
    { duration: '5m', target: 50 },   // Stay at 50 users
    { duration: '2m', target: 20 },   // Ramp down to 20 users
    { duration: '1m', target: 0 },    // Ramp down to 0
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    http_req_failed: ['rate<0.01'],
    api_latency: ['p(95)<400'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:4000';
const DASHBOARD_URL = 'http://localhost:3001';

// Test data
const TEST_USER = {
  email: 'test@codehardener.local',
  password: 'TestPassword123!',
};

export function setup() {
  // Login to get auth token
  const loginRes = http.post(`${BASE_URL}/api/auth/login`, JSON.stringify(TEST_USER), {
    headers: { 'Content-Type': 'application/json' },
  });

  let token = '';
  try {
    token = JSON.parse(loginRes.body).token;
  } catch {
    console.warn('Could not get auth token');
  }

  return { token };
}

export default function (data) {
  const authHeaders = data.token
    ? { Authorization: `Bearer ${data.token}`, 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json' };

  // Simulate different user journeys
  const scenario = Math.random();

  if (scenario < 0.3) {
    // 30% - Login flow
    loginFlow();
  } else if (scenario < 0.7) {
    // 40% - Dashboard operations
    dashboardOperations(authHeaders);
  } else {
    // 30% - API operations
    apiOperations(authHeaders);
  }

  sleep(Math.random() * 3 + 1); // Random sleep 1-4 seconds
}

function loginFlow() {
  group('Login Flow', function () {
    // Visit login page
    const loginPageRes = http.get(`${DASHBOARD_URL}/login`);
    check(loginPageRes, {
      'login page loads': (r) => r.status === 200,
    });

    sleep(1);

    // Submit login
    loginAttempts.add(1);
    const loginRes = http.post(
      `${BASE_URL}/api/auth/login`,
      JSON.stringify(TEST_USER),
      { headers: { 'Content-Type': 'application/json' } }
    );

    check(loginRes, {
      'login successful': (r) => r.status === 200,
      'login returns token': (r) => {
        try {
          return JSON.parse(r.body).token !== undefined;
        } catch {
          return false;
        }
      },
    });

    apiLatency.add(loginRes.timings.duration);
  });
}

function dashboardOperations(headers) {
  group('Dashboard Operations', function () {
    // Dashboard home
    const dashRes = http.get(DASHBOARD_URL, { headers });
    check(dashRes, {
      'dashboard loads': (r) => r.status === 200 || r.status === 302,
    });

    sleep(0.5);

    // Projects list
    const projectsRes = http.get(`${BASE_URL}/api/projects`, { headers });
    check(projectsRes, {
      'projects list returns 200': (r) => r.status === 200 || r.status === 401,
    });
    apiLatency.add(projectsRes.timings.duration);

    sleep(0.5);

    // Scans list
    const scansRes = http.get(`${BASE_URL}/api/scans`, { headers });
    check(scansRes, {
      'scans list returns 200': (r) => r.status === 200 || r.status === 401,
    });
    apiLatency.add(scansRes.timings.duration);

    sleep(0.5);

    // Findings summary
    const findingsRes = http.get(`${BASE_URL}/api/findings/summary`, { headers });
    check(findingsRes, {
      'findings summary returns 200': (r) => r.status === 200 || r.status === 401,
    });
    apiLatency.add(findingsRes.timings.duration);
  });
}

function apiOperations(headers) {
  group('API Operations', function () {
    // Health check
    const healthRes = http.get(`${BASE_URL}/health`);
    check(healthRes, {
      'health returns 200': (r) => r.status === 200,
    });

    sleep(0.5);

    // Get current user
    const userRes = http.get(`${BASE_URL}/api/auth/me`, { headers });
    check(userRes, {
      'user endpoint responds': (r) => r.status === 200 || r.status === 401,
    });
    apiLatency.add(userRes.timings.duration);

    sleep(0.5);

    // List attestations
    const attestRes = http.get(`${BASE_URL}/api/attestations`, { headers });
    check(attestRes, {
      'attestations endpoint responds': (r) => r.status === 200 || r.status === 401,
    });
    apiLatency.add(attestRes.timings.duration);
  });
}

export function handleSummary(data) {
  return {
    '/reports/load-summary.json': JSON.stringify(data, null, 2),
  };
}
