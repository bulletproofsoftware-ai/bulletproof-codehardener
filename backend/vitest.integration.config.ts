import { defineConfig } from 'vitest/config';

/**
 * PostgreSQL-backed integration suite.
 *
 * Deliberately a SEPARATE config from `vitest.config.ts` so the fast unit run
 * (`npm test`) never pays for a container start. The two suites cannot collide:
 * the unit config includes only `src/**\/*.test.ts` / `*.spec.ts`, and every
 * file here is `tests/integration/**\/*.itest.ts`.
 *
 * Run with: npm run test:db  (from backend/)
 */
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/integration/**/*.itest.ts'],
    exclude: ['node_modules', 'dist'],
    globalSetup: ['./tests/integration/global-setup.ts'],
    // One container, one database each — files share it, so they must not race.
    fileParallelism: false,
    // Container start + init.sql + 24 migrations, twice.
    hookTimeout: 300_000,
    testTimeout: 60_000,
    teardownTimeout: 60_000,
  },
});
