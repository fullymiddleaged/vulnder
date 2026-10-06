import path from 'node:path';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
      {
        // Worker code, run inside workerd with a local D1.
        plugins: [
          cloudflareTest(async () => ({
            wrangler: { configPath: './wrangler.jsonc' },
            // Tests stub env.AI and never reach Cloudflare, so CI (and forks) need no login or token.
            remoteBindings: false,
            miniflare: {
              bindings: { TEST_MIGRATIONS: await readD1Migrations(path.join(import.meta.dirname, 'migrations')) },
            },
          })),
        ],
        test: {
          name: 'workers',
          include: ['test/**/*.test.ts'],
          setupFiles: ['./test/apply-migrations.ts'],
        },
      },
      {
        // Node-only code: the Wrangler-backed store and the backfill script.
        test: {
          name: 'node',
          include: ['scripts/**/*.test.ts'],
          environment: 'node',
        },
      },
    ],
  },
});
