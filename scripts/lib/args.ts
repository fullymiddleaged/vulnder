import { parseArgs } from 'node:util';
import type { SourceName } from '../../src/ingest/types';

const ALL_SOURCES: SourceName[] = ['cve', 'ghsa', 'kev', 'epss'];

export function parseSources(value: string | undefined): SourceName[] | undefined {
  if (!value) return undefined;
  const names = value.split(',').map((s) => s.trim()).filter(Boolean);
  for (const n of names) {
    if (!ALL_SOURCES.includes(n as SourceName)) throw new Error(`unknown source "${n}" (expected ${ALL_SOURCES.join(', ')})`);
  }
  return names as SourceName[];
}

/** --local (default) or --remote. */
export function parseTarget(values: { local?: boolean; remote?: boolean }): 'local' | 'remote' {
  if (values.local && values.remote) throw new Error('choose either --local or --remote');
  return values.remote ? 'remote' : 'local';
}

export { parseArgs };
