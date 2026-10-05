import type { Ecosystem } from '../../lib/normalize';

/**
 * Package URLs (https://github.com/package-url/purl-spec), as found in
 * CycloneDX and SPDX SBOMs. OS packages (deb, rpm, apk) and container images
 * are outside version 1 and return null.
 */

const TYPES: Record<string, Ecosystem> = {
  npm: 'npm',
  pypi: 'PyPI',
  cargo: 'crates.io',
  golang: 'Go',
  maven: 'Maven',
  nuget: 'NuGet',
  composer: 'Packagist',
  gem: 'RubyGems',
  hex: 'Hex',
  pub: 'Pub',
  swift: 'SwiftURL',
  githubactions: 'GitHub Actions',
};

export function parsePurl(purl: string): { ecosystem: Ecosystem; name: string; version: string | null } | null {
  const m = /^pkg:([a-zA-Z][a-zA-Z0-9.+-]*)\/([^?#]+?)(?:@([^?#]+))?(?:[?#].*)?$/.exec(purl.trim());
  if (!m) return null;
  const ecosystem = TYPES[m[1]!.toLowerCase()];
  if (!ecosystem) return null;
  const segments = m[2]!.split('/').map((s) => decodeURIComponent(s));
  const version = m[3] ? decodeURIComponent(m[3]) : null;
  let name: string;
  switch (ecosystem) {
    case 'Maven':
      // pkg:maven/group/artifact
      if (segments.length < 2) return null;
      name = `${segments.slice(0, -1).join('.')}:${segments[segments.length - 1]}`;
      break;
    case 'npm':
    case 'Go':
    case 'Packagist':
    case 'SwiftURL':
    case 'GitHub Actions':
      name = segments.join('/');
      break;
    default:
      name = segments[segments.length - 1]!;
  }
  return name ? { ecosystem, name, version } : null;
}
