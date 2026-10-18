import { describe, expect, it } from 'vitest';
import { MAX_MANIFEST_BYTES, MAX_MANIFEST_ENTRIES, MAX_MANIFEST_LINES, MAX_TEXT_CHARS } from '../src/resolve/limits';
import type { Candidate } from '../src/resolve/types';
import { MAX_SCAN_BYTES } from '../src/resolve/cve-list';
import { capEntries, fileProblem, joinNotes, scanFileProblem, textProblem } from '../web/upload';

describe('scanFileProblem', () => {
  it('takes text exports from scanners, up to its own size limit', () => {
    for (const name of ['scan.csv', 'Q2 report.CSV', 'office.nessus', 'qualys.xml', 'trivy.json', 'ids.txt', 'export.tsv']) {
      expect(scanFileProblem(name, 1000), name).toBeNull();
    }
    expect(scanFileProblem('big.nessus', MAX_SCAN_BYTES)).toBeNull();
    expect(scanFileProblem('big.nessus', MAX_SCAN_BYTES + 1)).toMatch(/larger than 50 MB/);
    expect(scanFileProblem('scan.csv', 0)).toMatch(/empty/);
    for (const name of ['report.pdf', 'scan.xlsx', 'scan.zip', 'Dockerfile']) expect(scanFileProblem(name, 1000), name).toMatch(/isn't a report/);
  });
});

describe('fileProblem', () => {
  it('takes the names parsers know, and sniffable extensions', () => {
    for (const name of ['package.json', 'package-lock.json', 'requirements-dev.txt', 'go.mod', 'Dockerfile', 'Dockerfile.prod', 'app.cdx.json', 'sbom.spdx.json', 'bom.json', 'deps.toml', 'C:\\work\\Gemfile.lock', '.mcp.json', 'mcp.json', 'claude_desktop_config.json']) {
      expect(fileProblem(name, 1000), name).toBeNull();
    }
  });

  it('refuses other types, empty files and files over the size limit', () => {
    expect(fileProblem('photo.png', 1000)).toMatch(/^photo\.png isn't a manifest Vulnder reads/);
    expect(fileProblem('setup.exe', 1000)).not.toBeNull();
    expect(fileProblem('notes', 1000)).not.toBeNull();
    expect(fileProblem('package.json', 0)).toBe('package.json is empty.');
    expect(fileProblem('package.json', MAX_MANIFEST_BYTES)).toBeNull();
    expect(fileProblem('package.json', MAX_MANIFEST_BYTES + 1)).toBe('package.json is larger than 10 MB.');
  });
});

describe('textProblem', () => {
  it('is never held to the description limit', () => {
    expect(textProblem('package.json', 'x'.repeat(MAX_TEXT_CHARS * 100))).toBeNull();
  });

  it('refuses binary files', () => {
    expect(textProblem('bom.json', '{"a":\0}')).toBe("bom.json isn't a text file.");
  });

  it('allows exactly the line limit and refuses one more', () => {
    expect(textProblem('requirements.txt', 'a\n'.repeat(MAX_MANIFEST_LINES - 1))).toBeNull();
    expect(textProblem('requirements.txt', 'a\n'.repeat(MAX_MANIFEST_LINES))).toBe('requirements.txt has more than 300,000 lines.');
  });
});

describe('capEntries', () => {
  const pkg = (name: string, direct: boolean): Candidate => ({ kind: 'package', ecosystem: 'npm', name, version: '1.0.0', direct });

  it('sends everything up to the limit, with no note', () => {
    const all = Array.from({ length: MAX_MANIFEST_ENTRIES }, (_, i) => pkg(`p${i}`, i % 2 === 0));
    expect(capEntries(all)).toEqual({ sent: all, note: '' });
  });

  it('keeps direct dependencies first when there are too many', () => {
    const all = [pkg('t1', false), pkg('d1', true), pkg('t2', false), pkg('d2', true), pkg('t3', false)];
    const { sent, note } = capEntries(all, 3);
    expect(sent.map((c) => c.name)).toEqual(['d1', 'd2', 't1']);
    expect(note).toBe('Checked 3 of 5 entries: every direct dependency and the first indirect ones.');
    expect(capEntries([pkg('d1', true), pkg('d2', true), pkg('t1', false)], 1).note).toBe('Checked 1 of 3 entries: the first 1 direct dependencies.');
  });
});

describe('joinNotes', () => {
  it('joins the notes there are, in order, and is empty without any', () => {
    expect(joinNotes("1 MCP server wasn't checked.", 'Checked 3 of 5 entries.')).toBe("1 MCP server wasn't checked. Checked 3 of 5 entries.");
    expect(joinNotes(undefined, '')).toBe('');
    expect(joinNotes(undefined, 'Checked 3 of 5 entries.')).toBe('Checked 3 of 5 entries.');
  });
});
