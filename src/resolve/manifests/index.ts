import { parse as parseToml } from 'smol-toml';
import type { Ecosystem } from '../../lib/normalize';
import type { Candidate, ManifestParser } from '../types';
import { parsePurl } from './purl';
import { exactCargo, exactSemver, parsePep508 } from './versions';

/**
 * Deterministic manifest parsers. They run in the browser (a lockfile never
 * leaves the user's machine) and are tested server-side. To add a format,
 * write a ManifestParser and add it to PARSERS; see CONTRIBUTING.md.
 */

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);

function parseJsonObject(text: string): Json | null {
  try {
    const v = JSON.parse(text) as unknown;
    return isObj(v) ? v : null;
  } catch {
    return null;
  }
}

function pkg(ecosystem: Ecosystem, name: string, version: string | null, direct = true): Candidate {
  return { kind: 'package', ecosystem, name: name.trim(), version, direct };
}

// ---- npm ----

const packageLock: ManifestParser = {
  id: 'package-lock.json',
  matchesFilename: (f) => f === 'package-lock.json' || f === 'npm-shrinkwrap.json',
  sniff: (t) => {
    const j = parseJsonObject(t);
    return !!j && typeof j.lockfileVersion === 'number';
  },
  parse(text) {
    const j = parseJsonObject(text);
    if (!j) throw new Error('not JSON');
    const out: Candidate[] = [];
    if (isObj(j.packages)) {
      const root = isObj(j.packages['']) ? j.packages[''] : {};
      const direct = new Set([...Object.keys(isObj(root.dependencies) ? root.dependencies : {}), ...Object.keys(isObj(root.devDependencies) ? root.devDependencies : {})]);
      for (const [path, info] of Object.entries(j.packages)) {
        if (!path || !isObj(info) || info.link) continue;
        const name = typeof info.name === 'string' ? info.name : path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
        if (!name) continue;
        const topLevel = path === `node_modules/${name}`;
        out.push(pkg('npm', name, exactSemver(info.version), topLevel && direct.has(name)));
      }
    } else if (isObj(j.dependencies)) {
      // lockfileVersion 1
      const walk = (deps: Json, depth: number) => {
        for (const [name, info] of Object.entries(deps)) {
          if (!isObj(info)) continue;
          out.push(pkg('npm', name, exactSemver(info.version), depth === 0 && !info.dev));
          if (isObj(info.dependencies)) walk(info.dependencies, depth + 1);
        }
      };
      walk(j.dependencies, 0);
    }
    return out;
  },
};

const packageJson: ManifestParser = {
  id: 'package.json',
  matchesFilename: (f) => f === 'package.json',
  sniff: (t) => {
    const j = parseJsonObject(t);
    return !!j && !('lockfileVersion' in j) && !('require' in j) && (isObj(j.dependencies) || isObj(j.devDependencies));
  },
  parse(text) {
    const j = parseJsonObject(text);
    if (!j) throw new Error('not JSON');
    const out: Candidate[] = [];
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      const deps = j[field];
      if (!isObj(deps)) continue;
      for (const [name, spec] of Object.entries(deps)) out.push(pkg('npm', name, exactSemver(spec)));
    }
    return out;
  },
};

// ---- Python ----

const requirementsTxt: ManifestParser = {
  id: 'requirements.txt',
  matchesFilename: (f) => /^requirements([-_.][\w.-]*)?\.(txt|in)$/i.test(f),
  sniff: (t) => {
    const lines = t.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
    if (lines.length === 0) return false;
    // Every line must look like a requirement, and at least one must carry a version specifier,
    // so a pasted word list ("redis\nnginx") is not mistaken for a requirements file.
    // The extras group takes its own trailing whitespace: two \s* either side of an
    // optional group could split one run of spaces every way, which is quadratic.
    const req = /^(?:-[a-zA-Z-]+.*|[A-Za-z0-9][A-Za-z0-9._-]*\s*(?:\[[^\]]*\]\s*)?(?:(?:[=<>!~]=?|===).*)?(?:;.*)?)$/;
    return lines.every((l) => req.test(l)) && lines.some((l) => /[=<>~]=|>|</.test(l));
  },
  parse(text) {
    const out: Candidate[] = [];
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('#') || line.startsWith('-')) continue;
      const r = parsePep508(line);
      if (r) out.push(pkg('PyPI', r.name, r.version));
    }
    return out;
  },
};

const pyprojectToml: ManifestParser = {
  id: 'pyproject.toml',
  matchesFilename: (f) => f === 'pyproject.toml',
  // [ \t]* rather than \s* after ^ in multiline sniffs: \s* runs on through blank
  // lines from every line start, which is quadratic in a run of newlines.
  sniff: (t) => /^[ \t]*\[(project|tool\.poetry)(\.[\w.-]+)?\]/m.test(t),
  parse(text) {
    const doc = parseToml(text) as Json;
    const out: Candidate[] = [];
    const project = isObj(doc.project) ? doc.project : {};
    for (const req of Array.isArray(project.dependencies) ? project.dependencies : []) {
      if (typeof req !== 'string') continue;
      const r = parsePep508(req);
      if (r) out.push(pkg('PyPI', r.name, r.version));
    }
    const optional = isObj(project['optional-dependencies']) ? project['optional-dependencies'] : {};
    for (const group of Object.values(optional)) {
      for (const req of Array.isArray(group) ? group : []) {
        const r = typeof req === 'string' ? parsePep508(req) : null;
        if (r) out.push(pkg('PyPI', r.name, r.version));
      }
    }
    const tool = isObj(doc.tool) ? doc.tool : {};
    const poetry = isObj(tool.poetry) ? tool.poetry : {};
    const groups = isObj(poetry.group) ? Object.values(poetry.group).map((g) => (isObj(g) ? g.dependencies : null)) : [];
    for (const deps of [poetry.dependencies, poetry['dev-dependencies'], ...groups]) {
      if (!isObj(deps)) continue;
      for (const [name, spec] of Object.entries(deps)) {
        if (name.toLowerCase() === 'python') continue;
        const v = typeof spec === 'string' ? spec : isObj(spec) ? spec.version : null;
        out.push(pkg('PyPI', name, typeof v === 'string' && /^==?\s*[\w.]+$/.test(v.trim()) ? v.trim().replace(/^==?\s*/, '') : null));
      }
    }
    return out;
  },
};

// ---- Go ----

const goMod: ManifestParser = {
  id: 'go.mod',
  matchesFilename: (f) => f === 'go.mod',
  sniff: (t) => /^[ \t]*module[ \t]+\S+/m.test(t) && /^[ \t]*(go[ \t]+\d|require\b)/m.test(t),
  parse(text) {
    const out: Candidate[] = [];
    let inBlock = false;
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.replace(/\/\/.*$/, (c) => (/indirect/.test(c) ? ' //indirect' : '')).trim();
      if (/^require\s*\($/.test(line)) {
        inBlock = true;
        continue;
      }
      if (inBlock && line === ')') {
        inBlock = false;
        continue;
      }
      const m = (inBlock ? /^(\S+)\s+(v\S+)(\s+\/\/indirect)?$/ : /^require\s+(\S+)\s+(v\S+)(\s+\/\/indirect)?$/).exec(line);
      if (m) out.push(pkg('Go', m[1]!, m[2]!, !m[3]));
    }
    return out;
  },
};

// ---- Rust ----

const cargoToml: ManifestParser = {
  id: 'Cargo.toml',
  matchesFilename: (f) => f === 'Cargo.toml',
  sniff: (t) => /^[ \t]*\[package\]/m.test(t) && /^[ \t]*\[(dev-|build-)?dependencies\]/m.test(t),
  parse(text) {
    const doc = parseToml(text) as Json;
    const out: Candidate[] = [];
    const tables: unknown[] = [doc.dependencies, doc['dev-dependencies'], doc['build-dependencies']];
    if (isObj(doc.workspace)) tables.push(doc.workspace.dependencies);
    for (const deps of tables) {
      if (!isObj(deps)) continue;
      for (const [key, spec] of Object.entries(deps)) {
        const name = isObj(spec) && typeof spec.package === 'string' ? spec.package : key;
        const v = typeof spec === 'string' ? spec : isObj(spec) ? spec.version : null;
        out.push(pkg('crates.io', name, exactCargo(v)));
      }
    }
    return out;
  },
};

// ---- Maven ----

const pomXml: ManifestParser = {
  id: 'pom.xml',
  matchesFilename: (f) => f === 'pom.xml',
  sniff: (t) => /<project[\s>]/.test(t) && /<dependency>/.test(t),
  // Blocks are found with indexOf, not lazy regexes: /<x>[\s\S]*?<\/x>/ rescans
  // to the end from every unclosed <x>, which 200,000 characters of them make
  // seconds of CPU on the server. Element text is [^<]* then trimmed, for the same reason.
  parse(text) {
    const xml = stripXmlComments(text);
    const tag = (block: string, name: string) => new RegExp(`<${name}>([^<]*)</${name}>`).exec(block)?.[1]!.trim() ?? null;
    const props = new Map<string, string>();
    const propsBlock = xmlBlocks(xml, 'properties')[0] ?? '';
    for (const m of propsBlock.matchAll(/<([\w.-]+)>([^<]*)<\/\1>/g)) props.set(m[1]!, m[2]!.trim());
    const projectVersion = tag(withoutDependencies(withoutFirst(xml, 'parent')), 'version');
    if (projectVersion) props.set('project.version', projectVersion);
    const resolve = (v: string | null) => (v ? v.replace(/\$\{([^}]+)\}/g, (_, k: string) => props.get(k) ?? `\${${k}}`) : null);

    const out: Candidate[] = [];
    for (const block of xmlBlocks(xml, 'dependency')) {
      const g = resolve(tag(block, 'groupId'));
      const a = resolve(tag(block, 'artifactId'));
      if (!g || !a || g.includes('${') || a.includes('${')) continue;
      const v = resolve(tag(block, 'version'));
      // Maven ranges ([1.0,2.0)) and unresolved properties are not exact versions.
      const exact = v && !/[[\](),$]/.test(v) ? v : null;
      out.push(pkg('Maven', `${g}:${a}`, exact));
    }
    return out;
  },
};

/** The text without <!-- … --> comments; an unclosed one is left as it is. */
function stripXmlComments(xml: string): string {
  let out = '';
  let at = 0;
  for (;;) {
    const start = xml.indexOf('<!--', at);
    const end = start < 0 ? -1 : xml.indexOf('-->', start + 4);
    if (end < 0) return out + xml.slice(at);
    out += xml.slice(at, start);
    at = end + 3;
  }
}

/** The contents of each <name>…</name>, shortest first match, like /<name>([\s\S]*?)<\/name>/g. */
function xmlBlocks(xml: string, name: string): string[] {
  const open = `<${name}>`;
  const close = `</${name}>`;
  const out: string[] = [];
  let at = 0;
  for (;;) {
    const start = xml.indexOf(open, at);
    const end = start < 0 ? -1 : xml.indexOf(close, start + open.length);
    // No close after this opener means none after any later one either.
    if (end < 0) return out;
    out.push(xml.slice(start + open.length, end));
    at = end + close.length;
  }
}

/** The text without its first <name>…</name> block. */
function withoutFirst(xml: string, name: string): string {
  const start = xml.indexOf(`<${name}>`);
  const end = start < 0 ? -1 : xml.indexOf(`</${name}>`, start);
  return end < 0 ? xml : xml.slice(0, start) + xml.slice(end + name.length + 3);
}

/** The text without everything from the first <dependencies> to the last </dependencies>. */
function withoutDependencies(xml: string): string {
  const start = xml.indexOf('<dependencies>');
  const end = xml.lastIndexOf('</dependencies>');
  return start < 0 || end < start ? xml : xml.slice(0, start) + xml.slice(end + '</dependencies>'.length);
}

// ---- Ruby ----

const gemfileLock: ManifestParser = {
  id: 'Gemfile.lock',
  matchesFilename: (f) => f === 'Gemfile.lock',
  sniff: (t) => /^GEM\s*$/m.test(t) && /^\s{2}specs:\s*$/m.test(t),
  parse(text) {
    const out: Candidate[] = [];
    const direct = new Set<string>();
    let section = '';
    let inSpecs = false;
    for (const line of text.split(/\r?\n/)) {
      if (/^\S/.test(line)) {
        section = line.trim();
        inSpecs = false;
        continue;
      }
      if (section === 'DEPENDENCIES') {
        const m = /^\s{2}([^\s!(]+)/.exec(line);
        if (m) direct.add(m[1]!);
        continue;
      }
      if (/^\s{2}specs:\s*$/.test(line)) {
        inSpecs = section === 'GEM';
        continue;
      }
      // Exactly four spaces: a gem; six would be one of its dependencies.
      const m = inSpecs ? /^ {4}([^\s(]+) \(([^)]+)\)\s*$/.exec(line) : null;
      if (m) out.push(pkg('RubyGems', m[1]!, m[2]!.split('-')[0]!.trim()));
    }
    return out.map((c) => ({ ...c, direct: direct.size === 0 || direct.has((c as { name: string }).name) }));
  },
};

// ---- PHP ----

const composerJson: ManifestParser = {
  id: 'composer.json',
  matchesFilename: (f) => f === 'composer.json',
  sniff: (t) => {
    const j = parseJsonObject(t);
    return !!j && (isObj(j.require) || isObj(j['require-dev']));
  },
  parse(text) {
    const j = parseJsonObject(text);
    if (!j) throw new Error('not JSON');
    const out: Candidate[] = [];
    for (const field of ['require', 'require-dev']) {
      const deps = j[field];
      if (!isObj(deps)) continue;
      for (const [name, spec] of Object.entries(deps)) {
        // Platform requirements (php, ext-json, composer-plugin-api) have no vendor prefix.
        if (!name.includes('/')) continue;
        out.push(pkg('Packagist', name, exactSemver(spec)));
      }
    }
    return out;
  },
};

// ---- Dockerfile ----

const dockerfile: ManifestParser = {
  id: 'Dockerfile',
  matchesFilename: (f) => /^(Dockerfile|Containerfile)(\..+)?$/.test(f) || /\.dockerfile$/i.test(f),
  // The first instruction other than ARG must be FROM.
  sniff: (t) => {
    const first = t.split(/\r?\n/).find((l) => l.trim() && !l.trim().startsWith('#') && !/^\s*ARG\s/i.test(l));
    return !!first && /^\s*FROM\s+\S+/i.test(first);
  },
  parse(text) {
    const out: Candidate[] = [];
    const stages = new Set<string>();
    for (const line of text.split(/\r?\n/)) {
      const m = /^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?/i.exec(line);
      if (!m) continue;
      const ref = m[1]!;
      if (m[2]) stages.add(m[2].toLowerCase());
      if (ref === 'scratch' || stages.has(ref.toLowerCase()) || ref.includes('$')) continue;
      // [registry/][namespace/]name[:tag][@digest]
      const noDigest = ref.split('@')[0]!;
      const colon = noDigest.lastIndexOf(':');
      const hasTag = colon > noDigest.lastIndexOf('/');
      const path = hasTag ? noDigest.slice(0, colon) : noDigest;
      const tag = hasTag ? noDigest.slice(colon + 1) : null;
      const parts = path.split('/');
      const name = parts[parts.length - 1]!;
      const vendor = parts.length > 1 && !parts[parts.length - 2]!.includes('.') ? parts[parts.length - 2]! : null;
      const version = tag && /^\d/.test(tag) ? (/^[\d.]+/.exec(tag)?.[0] ?? null)?.replace(/\.$/, '') ?? null : null;
      out.push({ kind: 'product', name, vendor: vendor === 'library' ? null : vendor, version, direct: true });
    }
    return out;
  },
};

// ---- SBOMs ----

const cyclonedx: ManifestParser = {
  id: 'CycloneDX',
  matchesFilename: (f) => /\.(cdx|bom)\.json$/i.test(f),
  sniff: (t) => parseJsonObject(t)?.bomFormat === 'CycloneDX',
  parse(text) {
    const j = parseJsonObject(text);
    if (!j || j.bomFormat !== 'CycloneDX') throw new Error('not CycloneDX');
    const out: Candidate[] = [];
    const walk = (components: unknown) => {
      for (const c of Array.isArray(components) ? components : []) {
        if (!isObj(c)) continue;
        const p = typeof c.purl === 'string' ? parsePurl(c.purl) : null;
        if (p) out.push(pkg(p.ecosystem, p.name, p.version));
        walk(c.components);
      }
    };
    walk(j.components);
    return out;
  },
};

const spdx: ManifestParser = {
  id: 'SPDX',
  matchesFilename: (f) => /\.spdx\.json$/i.test(f),
  sniff: (t) => typeof parseJsonObject(t)?.spdxVersion === 'string',
  parse(text) {
    const j = parseJsonObject(text);
    if (!j || typeof j.spdxVersion !== 'string') throw new Error('not SPDX');
    const out: Candidate[] = [];
    for (const p of Array.isArray(j.packages) ? j.packages : []) {
      if (!isObj(p) || !Array.isArray(p.externalRefs)) continue;
      for (const ref of p.externalRefs) {
        if (!isObj(ref) || ref.referenceType !== 'purl' || typeof ref.referenceLocator !== 'string') continue;
        const parsed = parsePurl(ref.referenceLocator);
        if (parsed) out.push(pkg(parsed.ecosystem, parsed.name, parsed.version));
      }
    }
    return out;
  },
};

/** Order matters for sniffing: more specific formats first. */
export const PARSERS: ManifestParser[] = [
  packageLock,
  cyclonedx,
  spdx,
  composerJson,
  packageJson,
  goMod,
  gemfileLock,
  pomXml,
  pyprojectToml,
  cargoToml,
  dockerfile,
  requirementsTxt,
];

export interface ManifestResult {
  format: string;
  candidates: Candidate[];
}

/**
 * Parses text as a known manifest, by file name when one is given, otherwise
 * by content. Returns null for anything else (free text goes to the model).
 */
/** Whether a file name is one a parser claims (package.json, go.mod, Dockerfile.prod, app.cdx.json, …). */
export function isManifestFilename(filename: string): boolean {
  const base = filename.split(/[\\/]/).pop() ?? '';
  return PARSERS.some((p) => p.matchesFilename(base));
}

export function parseManifest(text: string, filename?: string): ManifestResult | null {
  const base = filename?.split(/[\\/]/).pop();
  const byName = base ? PARSERS.find((p) => p.matchesFilename(base)) : undefined;
  const candidates = byName ? [byName] : PARSERS.filter((p) => p.sniff(text));
  for (const parser of candidates) {
    try {
      return { format: parser.id, candidates: dedupe(parser.parse(text)) };
    } catch {
      // try the next one
    }
  }
  return null;
}

function dedupe(items: Candidate[]): Candidate[] {
  const byKey = new Map<string, Candidate>();
  for (const c of items) {
    const key = c.kind === 'package' ? `p:${c.ecosystem}:${c.name}:${c.version}` : `r:${c.vendor}:${c.name}:${c.version}`;
    const prev = byKey.get(key);
    byKey.set(key, prev ? { ...c, direct: prev.direct || c.direct } : c);
  }
  return [...byKey.values()];
}
