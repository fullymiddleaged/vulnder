/**
 * Checks for the release workflow (.github/workflows/release.yml): the tag
 * matches package.json, the changelog has the version's notes, and the
 * committed ARM template is what main.bicep builds to.
 */

const TAG_RE = /^v(\d+\.\d+\.\d+)$/;

/** The version a tag names, if it matches package.json; throws otherwise. */
export function versionFromTag(tag: string, packageVersion: string): string {
  const version = TAG_RE.exec(tag)?.[1];
  if (!version) throw new Error(`tag "${tag}" isn't vX.Y.Z`);
  if (version !== packageVersion) throw new Error(`tag ${tag} doesn't match package.json version ${packageVersion}`);
  return version;
}

/** The body of the changelog's `## [version]` section; throws if it's missing or empty. */
export function releaseNotes(changelog: string, version: string): string {
  const lines = changelog.split(/\r?\n/);
  const start = lines.findIndex((l) => l.startsWith(`## [${version}]`));
  if (start < 0) throw new Error(`CHANGELOG.md has no "## [${version}]" section`);
  const end = lines.findIndex((l, i) => i > start && /^## /.test(l));
  const notes = lines.slice(start + 1, end < 0 ? undefined : end).join('\n').trim();
  if (!notes) throw new Error(`CHANGELOG.md's "## [${version}]" section is empty`);
  return notes;
}

/**
 * Whether two built ARM templates are the same, ignoring the generator stamp
 * (Bicep's version and the template hash), so a contributor on another Bicep
 * release still matches when the output is otherwise identical.
 */
export function sameTemplate(committed: string, built: string): boolean {
  return JSON.stringify(withoutGenerator(committed)) === JSON.stringify(withoutGenerator(built));
}

function withoutGenerator(text: string): unknown {
  const template = JSON.parse(text) as { metadata?: { _generator?: unknown } };
  if (template.metadata) delete template.metadata._generator;
  return template;
}
