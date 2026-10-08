import { MAX_MANIFEST_BYTES, MAX_MANIFEST_ENTRIES, MAX_MANIFEST_LINES } from '../src/resolve/limits';
import { isManifestFilename } from '../src/resolve/manifests';
import type { Candidate } from '../src/resolve/types';

/**
 * Checks on an uploaded manifest, before and after it is read. Uploads never
 * meet the description's length limit: the file is parsed here and only its
 * package names and versions are sent.
 */

/** Extensions worth sniffing when the name isn't one a parser knows (bom.json, deps.txt). */
const SNIFFABLE = /\.(json|txt|in|toml|xml|lock|mod)$/i;

export const MANIFEST_FORMATS =
  'package.json, package-lock.json, requirements.txt, pyproject.toml, go.mod, Cargo.toml, pom.xml, Gemfile.lock, composer.json, Dockerfiles, CycloneDX or SPDX JSON';

/** Why a file can't be read, from its name and size alone; null when it can. */
export function fileProblem(name: string, size: number): string | null {
  if (!isManifestFilename(name) && !SNIFFABLE.test(name)) return `${name} isn't a manifest Vulnder reads. Try ${MANIFEST_FORMATS}.`;
  if (size === 0) return `${name} is empty.`;
  if (size > MAX_MANIFEST_BYTES) return `${name} is larger than ${MAX_MANIFEST_BYTES / 1_000_000} MB.`;
  return null;
}

/** Why a file's text can't be used: binary, or too many lines. Null when it can. */
export function textProblem(name: string, text: string): string | null {
  if (text.includes('\0')) return `${name} isn't a text file.`;
  let lines = 1;
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) {
    if (++lines > MAX_MANIFEST_LINES) return `${name} has more than ${MAX_MANIFEST_LINES.toLocaleString('en')} lines.`;
  }
  return null;
}

/**
 * At most `max` entries, direct dependencies first, then indirect ones, each
 * in file order, and a note saying what was left out (empty when nothing was).
 */
export function capEntries(entries: Candidate[], max = MAX_MANIFEST_ENTRIES): { sent: Candidate[]; note: string } {
  if (entries.length <= max) return { sent: entries, note: '' };
  const direct = entries.filter((c) => c.direct);
  const sent = [...direct, ...entries.filter((c) => !c.direct)].slice(0, max);
  const which = direct.length >= max ? `the first ${max.toLocaleString('en')} direct dependencies` : 'every direct dependency and the first indirect ones';
  return { sent, note: `Checked ${max.toLocaleString('en')} of ${entries.length.toLocaleString('en')} entries: ${which}.` };
}
