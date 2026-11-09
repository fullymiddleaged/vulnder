/**
 * Prints a release's notes from CHANGELOG.md, after checking the tag matches
 * package.json. Used by .github/workflows/release.yml.
 *
 *   npx tsx scripts/release-notes.ts v0.2.0
 */
import { readFileSync } from 'node:fs';
import { releaseNotes, versionFromTag } from './lib/release';

const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as { version: string };
const version = versionFromTag(process.argv[2] ?? '', pkg.version);
console.log(releaseNotes(readFileSync('CHANGELOG.md', 'utf8'), version));
