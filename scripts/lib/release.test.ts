import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { latestVersion, releaseNotes, sameTemplate, versionFromTag } from './release';

describe('versionFromTag', () => {
  it('takes vX.Y.Z matching package.json', () => {
    expect(versionFromTag('v0.2.0', '0.2.0')).toBe('0.2.0');
  });

  it('refuses a tag that differs from package.json, or isn\'t vX.Y.Z', () => {
    expect(() => versionFromTag('v0.2.1', '0.2.0')).toThrow(/doesn't match/);
    for (const tag of ['0.2.0', 'v0.2', 'v0.2.0-rc.1', 'release-0.2.0']) expect(() => versionFromTag(tag, '0.2.0'), tag).toThrow(/isn't vX.Y.Z/);
  });
});

describe('releaseNotes', () => {
  const changelog = [
    '# Changelog',
    '',
    '## [Unreleased]',
    '',
    '- Not yet.',
    '',
    '## [0.2.0] - 2026-11-09',
    '',
    '### Added',
    '',
    '- A button.',
    '',
    '## [0.1.0] - 2026-10-01',
    '',
    '- First.',
    '',
  ].join('\r\n');

  it("returns the version's section, up to the next one", () => {
    expect(releaseNotes(changelog, '0.2.0')).toBe('### Added\n\n- A button.');
    expect(releaseNotes(changelog, '0.1.0')).toBe('- First.');
  });

  it("refuses a version with no section, or an empty one, and doesn't match a prefix", () => {
    expect(() => releaseNotes(changelog, '0.3.0')).toThrow(/no "## \[0.3.0\]"/);
    expect(() => releaseNotes(changelog, '0.2')).toThrow(/no "## \[0.2\]"/);
    expect(() => releaseNotes('## [0.4.0]\n\n## [0.3.0]\n- x', '0.4.0')).toThrow(/empty/);
  });
});

describe('latestVersion', () => {
  it('skips Unreleased and takes the first numbered section', () => {
    expect(latestVersion('# Changelog\n\n## [Unreleased]\n\n## [0.2.0] - 2026-11-09\n\n## [0.1.0]\n')).toBe('0.2.0');
    expect(latestVersion('# Changelog\n\n## [Unreleased]\n')).toBeUndefined();
  });

  it("is package.json's version, with release notes, in this repository", () => {
    const changelog = readFileSync('CHANGELOG.md', 'utf8');
    const { version } = JSON.parse(readFileSync('package.json', 'utf8')) as { version: string };
    expect(latestVersion(changelog)).toBe(version);
    expect(releaseNotes(changelog, version)).not.toBe('');
  });
});

describe('sameTemplate', () => {
  const template = (generator: string, resources: unknown[]) =>
    JSON.stringify({ metadata: { _generator: { name: 'bicep', version: generator, templateHash: generator } }, resources }, null, 2);

  it('ignores the Bicep version and template hash', () => {
    expect(sameTemplate(template('0.48.1', [{ type: 'a' }]), template('0.49.0', [{ type: 'a' }]))).toBe(true);
  });

  it('notices any other difference', () => {
    expect(sameTemplate(template('0.48.1', [{ type: 'a' }]), template('0.48.1', [{ type: 'b' }]))).toBe(false);
  });
});
