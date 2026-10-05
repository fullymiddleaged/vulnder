import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { open, opendir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile);

export const CVELIST_REPO = 'https://github.com/CVEProject/cvelistV5.git';

/** Clones cvelistV5 shallowly, or fast-forwards an existing clone. */
export async function ensureClone(dir: string, update: boolean, log: (m: string) => void): Promise<void> {
  if (!existsSync(path.join(dir, '.git'))) {
    log(`cloning ${CVELIST_REPO} into ${dir} (shallow; this takes a while)`);
    await run('git', ['clone', '--depth', '1', '--single-branch', CVELIST_REPO, dir], { maxBuffer: 1 << 26 });
  } else if (update) {
    log(`updating ${dir}`);
    await run('git', ['-C', dir, 'fetch', '--depth', '1', 'origin', 'main'], { maxBuffer: 1 << 26 });
    await run('git', ['-C', dir, 'reset', '--hard', 'FETCH_HEAD'], { maxBuffer: 1 << 26 });
  }
}

/** Every CVE record file under cves/, in no particular order. */
export async function* cveFiles(dir: string): AsyncGenerator<string> {
  const root = path.join(dir, 'cves');
  for await (const year of await opendir(root)) {
    if (!year.isDirectory()) continue;
    for await (const bucket of await opendir(path.join(root, year.name))) {
      if (!bucket.isDirectory()) continue;
      for await (const file of await opendir(path.join(root, year.name, bucket.name))) {
        if (file.isFile() && /^CVE-\d{4}-\d+\.json$/.test(file.name)) yield path.join(root, year.name, bucket.name, file.name);
      }
    }
  }
}

export interface CveMeta {
  cveId: string;
  state: string;
  datePublished: string | null;
  dateUpdated: string | null;
}

/**
 * Reads cveMetadata from the start of a record without parsing the whole file.
 * cvelistV5 writes cveMetadata before containers; if the fields are not in the
 * first chunk, the whole file is parsed instead.
 */
export function metaFromHead(head: string): CveMeta | null {
  const block = /"cveMetadata"\s*:\s*\{([^{}]*)\}/.exec(head)?.[1];
  if (!block) return null;
  const field = (name: string) => new RegExp(`"${name}"\\s*:\\s*"([^"]*)"`).exec(block)?.[1] ?? null;
  const cveId = field('cveId');
  const state = field('state');
  if (!cveId || !state) return null;
  return { cveId, state, datePublished: field('datePublished'), dateUpdated: field('dateUpdated') };
}

export async function readMeta(file: string): Promise<CveMeta | null> {
  const fh = await open(file, 'r');
  try {
    const buf = Buffer.alloc(4096);
    const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
    const meta = metaFromHead(buf.subarray(0, bytesRead).toString('utf8'));
    if (meta) return meta;
  } finally {
    await fh.close();
  }
  try {
    const json = JSON.parse(await readFile(file, 'utf8')) as { cveMetadata?: Record<string, unknown> };
    const m = json.cveMetadata ?? {};
    if (typeof m.cveId !== 'string' || typeof m.state !== 'string') return null;
    return {
      cveId: m.cveId,
      state: m.state,
      datePublished: typeof m.datePublished === 'string' ? m.datePublished : null,
      dateUpdated: typeof m.dateUpdated === 'string' ? m.dateUpdated : null,
    };
  } catch {
    return null;
  }
}
