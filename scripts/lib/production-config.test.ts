import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { hasPlaceholderId, PLACEHOLDER_D1_ID, PRODUCTION_CONFIG, productionConfig, stampD1Id } from './production-config';

const ID = '3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b';
const CONFIG = `{
  "d1_databases": [{ "binding": "DB", "database_id": "${PLACEHOLDER_D1_ID}" }],
  // A comment mentioning ${PLACEHOLDER_D1_ID} stays as it is.
  "env": { "paid": { "d1_databases": [{ "binding": "DB", "database_id":"${PLACEHOLDER_D1_ID}" }] } }
}
`;

function project(config: string): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'vulnder-config-'));
  writeFileSync(path.join(dir, 'wrangler.jsonc'), config);
  return dir;
}

describe('stampD1Id', () => {
  it('replaces every placeholder database_id and nothing else', () => {
    const out = stampD1Id(CONFIG, ` ${ID}\n`);
    expect(out.match(new RegExp(ID, 'g'))).toHaveLength(2);
    expect(out).toContain(`"database_id": "${ID}"`);
    expect(out).toContain(`"database_id":"${ID}"`);
    expect(out).toContain(`// A comment mentioning ${PLACEHOLDER_D1_ID} stays as it is.`);
    expect(hasPlaceholderId(out)).toBe(false);
  });

  it('refuses anything that is not a real database UUID', () => {
    for (const bad of ['', 'vulnder', PLACEHOLDER_D1_ID, `${ID}"; "x": "`, '3f2b8c1e-5d4a-4e6f-9a7b']) {
      expect(() => stampD1Id(CONFIG, bad), bad).toThrow(/D1_DATABASE_ID must be/);
    }
  });

  it('refuses a config with no placeholder to replace', () => {
    expect(() => stampD1Id(stampD1Id(CONFIG, ID), ID)).toThrow(/no placeholder/);
  });
});

describe('productionConfig', () => {
  it('writes a git-ignored copy with the real ID beside wrangler.jsonc', () => {
    const dir = project(CONFIG);
    const file = productionConfig(dir, { D1_DATABASE_ID: ID });
    expect(file).toBe(path.join(dir, PRODUCTION_CONFIG));
    expect(readFileSync(file, 'utf8')).toBe(stampD1Id(CONFIG, ID));
    // The committed config is untouched.
    expect(readFileSync(path.join(dir, 'wrangler.jsonc'), 'utf8')).toBe(CONFIG);
  });

  it('copies wrangler.jsonc unchanged when it already holds a real ID', () => {
    const committed = stampD1Id(CONFIG, ID);
    const dir = project(committed);
    expect(readFileSync(productionConfig(dir, {}), 'utf8')).toBe(committed);
  });

  it('fails clearly when the ID is needed but not set', () => {
    expect(() => productionConfig(project(CONFIG), {})).toThrow(/set D1_DATABASE_ID/);
  });
});
