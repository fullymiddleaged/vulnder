import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { cveFiles, metaFromHead, readMeta } from './cvelist-clone';

const record = {
  dataType: 'CVE_RECORD',
  dataVersion: '5.2',
  cveMetadata: {
    cveId: 'CVE-2026-104910',
    state: 'PUBLISHED',
    datePublished: '2026-10-02T16:01:32.781Z',
    dateUpdated: '2026-10-03T15:52:56.095Z',
  },
  containers: { cna: { title: 'x' } },
};

describe('metaFromHead', () => {
  it('reads cveMetadata without parsing the whole record', () => {
    expect(metaFromHead(JSON.stringify(record, null, 2).slice(0, 400))).toEqual(record.cveMetadata);
  });

  it('returns null when the block is not in the head', () => {
    expect(metaFromHead('{"containers": {')).toBeNull();
  });

  it('handles rejected records without datePublished', () => {
    const rejected = { cveMetadata: { cveId: 'CVE-2026-104886', state: 'REJECTED', dateUpdated: '2026-10-02T21:10:15.271Z' } };
    expect(metaFromHead(JSON.stringify(rejected))).toEqual({ ...rejected.cveMetadata, datePublished: null });
  });
});

describe('clone walking', () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'cvelist-'));
    await mkdir(path.join(dir, 'cves', '2026', '104xxx'), { recursive: true });
    await writeFile(path.join(dir, 'cves', '2026', '104xxx', 'CVE-2026-104910.json'), JSON.stringify(record));
    // cveMetadata after a large containers block: falls back to a full parse.
    const late = { containers: { cna: { pad: 'x'.repeat(10_000) } }, cveMetadata: { ...record.cveMetadata, cveId: 'CVE-2026-104911' } };
    await writeFile(path.join(dir, 'cves', '2026', '104xxx', 'CVE-2026-104911.json'), JSON.stringify(late));
    await writeFile(path.join(dir, 'cves', '2026', '104xxx', 'README.md'), 'not a record');
    await writeFile(path.join(dir, 'cves', 'delta.json'), '{}');
  });
  afterAll(() => rm(dir, { recursive: true, force: true }));

  it('finds record files only', async () => {
    const files: string[] = [];
    for await (const f of cveFiles(dir)) files.push(path.basename(f));
    expect(files.sort()).toEqual(['CVE-2026-104910.json', 'CVE-2026-104911.json']);
  });

  it('reads metadata from the head or the whole file', async () => {
    const base = path.join(dir, 'cves', '2026', '104xxx');
    expect((await readMeta(path.join(base, 'CVE-2026-104910.json')))?.cveId).toBe('CVE-2026-104910');
    expect((await readMeta(path.join(base, 'CVE-2026-104911.json')))?.cveId).toBe('CVE-2026-104911');
  });
});
