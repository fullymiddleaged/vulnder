import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

/**
 * The production D1 database ID stays out of git: wrangler.jsonc keeps a
 * placeholder, and commands that reach Cloudflare use a generated copy,
 * wrangler.production.jsonc (git-ignored), with the real ID from
 * D1_DATABASE_ID. Set that in the shell, in a git-ignored .env, or as a
 * Workers Builds / GitHub Actions variable.
 *
 * A fork that commits its own ID needs none of this: with no placeholder in
 * wrangler.jsonc, the committed config is used as it is.
 */

export const PLACEHOLDER_D1_ID = '00000000-0000-0000-0000-000000000000';
export const PRODUCTION_CONFIG = 'wrangler.production.jsonc';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PLACEHOLDER_FIELD = new RegExp(`("database_id"\\s*:\\s*")${PLACEHOLDER_D1_ID}(")`, 'g');

export function hasPlaceholderId(config: string): boolean {
  return new RegExp(PLACEHOLDER_FIELD.source).test(config);
}

/** The config with every placeholder database_id replaced by `id`. */
export function stampD1Id(config: string, id: string): string {
  const trimmed = id.trim();
  if (!UUID.test(trimmed) || trimmed === PLACEHOLDER_D1_ID) {
    throw new Error(`D1_DATABASE_ID must be the database's UUID (see \`npx wrangler d1 list\`), got "${trimmed}"`);
  }
  if (!hasPlaceholderId(config)) throw new Error(`wrangler.jsonc has no placeholder database_id to replace`);
  return config.replace(PLACEHOLDER_FIELD, `$1${trimmed}$2`);
}

/**
 * Writes wrangler.production.jsonc for commands that reach Cloudflare and
 * returns its path: wrangler.jsonc with the real ID, or an unchanged copy when
 * wrangler.jsonc already holds one. It sits next to wrangler.jsonc, so the
 * relative paths inside resolve the same.
 */
export function productionConfig(cwd = process.cwd(), env: NodeJS.ProcessEnv = process.env): string {
  const config = readFileSync(path.join(cwd, 'wrangler.jsonc'), 'utf8');
  const target = path.join(cwd, PRODUCTION_CONFIG);
  if (!hasPlaceholderId(config)) {
    writeFileSync(target, config);
    return target;
  }

  let id = env.D1_DATABASE_ID;
  const dotenv = path.join(cwd, '.env');
  if (!id && env === process.env && existsSync(dotenv)) {
    process.loadEnvFile(dotenv);
    id = process.env.D1_DATABASE_ID;
  }
  if (!id) {
    throw new Error('set D1_DATABASE_ID to the production database ID (in your shell, a git-ignored .env, or the build settings)');
  }
  writeFileSync(target, stampD1Id(config, id));
  return target;
}
