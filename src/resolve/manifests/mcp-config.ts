import type { Candidate, ManifestParser, ParsedManifest } from '../types';
import { imageCandidate } from './image';
import { exactSemver, parsePep508 } from './versions';

/**
 * MCP client config files: the servers an AI agent starts or connects to.
 * Claude Desktop, Claude Code (.mcp.json) and Cursor list them under
 * `mcpServers`; VS Code (.vscode/mcp.json) under `servers`. A server started
 * with a package runner (npx, uvx, docker run, …) becomes that package or
 * image. Local scripts and remote URLs can't be checked, so they're counted
 * in a note instead.
 *
 * Only `command`, `args` and `url` are read. Config files hold API keys in
 * `env` and `headers`; those are never read, and neither is any argument
 * after the package, so no key can reach a candidate. Like every manifest,
 * this runs in the browser.
 */

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);

/** More servers than any real config holds; the rest are ignored. */
const MAX_SERVERS = 500;
/** Arguments looked at per server, enough to get past a runner's options to the package. */
const MAX_ARGS = 40;

const NPM_NAME = /^(?:@[a-z0-9][\w.~-]*\/)?[a-z0-9][\w.~-]*$/i;

function servers(text: string): Json[] | null {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isObj(doc)) return null;
  const block = isObj(doc.mcpServers) ? doc.mcpServers : isObj(doc.servers) ? doc.servers : null;
  if (!block) return null;
  const list = Object.values(block).filter(isObj).slice(0, MAX_SERVERS);
  return list.some((s) => typeof s.command === 'string' || typeof s.url === 'string') ? list : null;
}

/** The program a command runs, without its path or a Windows extension: `C:\\…\\npx.cmd` is `npx`. */
function program(command: string): string {
  return (command.split(/[\\/]/).pop() ?? '').replace(/\.(cmd|exe|bat|ps1)$/i, '').toLowerCase();
}

/** `name@version` as an npm package; null for a path, URL or anything else. */
function npmPackage(spec: string): Candidate | null {
  const at = spec.lastIndexOf('@');
  const name = at > 0 ? spec.slice(0, at) : spec;
  if (!NPM_NAME.test(name) || name.length > 214) return null;
  return { kind: 'package', ecosystem: 'npm', name, version: at > 0 ? exactSemver(spec.slice(at + 1)) : null, direct: true };
}

/** `name==1.2.3`, `name@1.2.3` or `name` as a PyPI package. */
function pypiPackage(spec: string): Candidate | null {
  const m = /^([A-Za-z0-9][\w.-]*)@([\w.+!-]+)$/.exec(spec);
  const r = m ? { name: m[1]!, version: /^\d/.test(m[2]!) ? m[2]! : null } : parsePep508(spec);
  if (!r || /[/\\:]/.test(spec)) return null;
  return { kind: 'package', ecosystem: 'PyPI', name: r.name, version: r.version, direct: true };
}

/** Runner options that take a value, by runner: the value isn't the package. */
const NPX_VALUE = new Set(['-c', '--call', '--cache', '--registry', '--userconfig', '-w', '--workspace']);
const UVX_VALUE = new Set([
  '--with',
  '--with-editable',
  '--with-requirements',
  '--python',
  '-p',
  '--index',
  '--index-url',
  '--extra-index-url',
  '--default-index',
  '--find-links',
  '-f',
  '--refresh-package',
  '--reinstall-package',
  '--upgrade-package',
  '--env-file',
  '--directory',
  '--project',
  '--cache-dir',
  '--config-file',
  '--constraints',
  '--overrides',
]);
const DOCKER_VALUE = new Set([
  '-e', '--env', '--env-file', '-v', '--volume', '--mount', '--name', '-p', '--publish', '--network', '--net', '-w', '--workdir',
  '--entrypoint', '-u', '--user', '--add-host', '-l', '--label', '--platform', '--pull', '-m', '--memory', '--cpus', '--restart',
  '-h', '--hostname', '--dns', '--device', '--cap-add', '--cap-drop', '--security-opt', '--tmpfs', '--ulimit', '--log-driver',
  '--log-opt', '--runtime', '--gpus', '--ipc', '--pid', '--shm-size', '--expose', '--group-add', '--label-file', '--stop-signal',
]);

/**
 * The first argument that isn't an option, skipping the values of options in
 * `takesValue`, and the value of the first option in `packageOption` when one
 * names the package outright (npx --package=x, uvx --from x).
 */
function positional(args: string[], takesValue: Set<string>, packageOption: Set<string> = new Set()): string | null {
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === '--') return args[i + 1] ?? null;
    if (!a.startsWith('-')) return a;
    const [flag, inline] = a.includes('=') ? [a.slice(0, a.indexOf('=')), a.slice(a.indexOf('=') + 1)] : [a, null];
    if (packageOption.has(flag)) return inline ?? args[i + 1] ?? null;
    if (inline === null && takesValue.has(flag)) i++;
  }
  return null;
}

type Server = { candidate: Candidate } | { unchecked: 'local' | 'remote' };

function server(s: Json): Server {
  if (typeof s.command !== 'string') return { unchecked: typeof s.url === 'string' ? 'remote' : 'local' };
  const raw = Array.isArray(s.args) ? s.args.filter((a): a is string => typeof a === 'string') : [];
  // A command given as one string ("npx -y pkg") with no args: split it.
  const tokens = raw.length === 0 ? s.command.trim().split(/\s+/) : [s.command.trim(), ...raw];
  let run = program(tokens[0] ?? '');
  let args = tokens.slice(1, MAX_ARGS + 1);
  // Two-word runners: npm exec / npm x, pnpm dlx, yarn dlx, bun x, uv tool run, pipx run.
  if ((run === 'npm' && (args[0] === 'exec' || args[0] === 'x')) || ((run === 'pnpm' || run === 'yarn') && args[0] === 'dlx') || (run === 'bun' && args[0] === 'x')) {
    run = 'npx';
    args = args.slice(1);
  } else if (run === 'uv' && args[0] === 'tool' && args[1] === 'run') {
    run = 'uvx';
    args = args.slice(2);
  } else if (run === 'pipx' && args[0] === 'run') {
    args = args.slice(1);
  } else if ((run === 'docker' || run === 'podman') && args[0] === 'container' && args[1] === 'run') {
    args = args.slice(1);
  }

  let candidate: Candidate | null = null;
  if (run === 'npx' || run === 'pnpx' || run === 'bunx') {
    const spec = positional(args, NPX_VALUE, new Set(['-p', '--package']));
    candidate = spec ? npmPackage(spec) : null;
  } else if (run === 'uvx') {
    const spec = positional(args, UVX_VALUE, new Set(['--from']));
    candidate = spec ? pypiPackage(spec) : null;
  } else if (run === 'pipx') {
    const spec = positional(args, new Set(['--python', '--pip-args', '--index-url']), new Set(['--spec']));
    candidate = spec ? pypiPackage(spec) : null;
  } else if ((run === 'docker' || run === 'podman') && args[0] === 'run') {
    const ref = positional(args.slice(1), DOCKER_VALUE);
    candidate = ref ? imageCandidate(ref) : null;
  }
  return candidate ? { candidate } : { unchecked: 'local' };
}

/** Says what couldn't be checked; empty when everything could. */
export function uncheckedNote(local: number, remote: number): string {
  if (local + remote === 0) return '';
  const parts = [
    local > 0 ? `${local} ${local === 1 ? 'runs' : 'run'} local code or a command Vulnder doesn't recognise` : '',
    remote > 0 ? `${remote} ${remote === 1 ? 'is a remote server' : 'are remote servers'}` : '',
  ].filter(Boolean);
  const one = local + remote === 1;
  return `${local + remote} MCP ${one ? "server wasn't" : "servers weren't"} checked: ${parts.join(' and ')}. Check ${one ? 'it' : 'them'} with ${one ? 'its' : 'their'} publisher.`;
}

export const mcpConfig: ManifestParser = {
  id: 'MCP config',
  matchesFilename: (f) => f === '.mcp.json' || f === 'mcp.json' || f === 'claude_desktop_config.json',
  sniff: (t) => servers(t) !== null,
  parse(text): ParsedManifest {
    const list = servers(text);
    if (!list) throw new Error('not an MCP config');
    const candidates: Candidate[] = [];
    let local = 0;
    let remote = 0;
    for (const s of list) {
      const got = server(s);
      if ('candidate' in got) candidates.push(got.candidate);
      else if (got.unchecked === 'remote') remote++;
      else local++;
    }
    const note = uncheckedNote(local, remote);
    return note ? { candidates, note } : { candidates };
  },
};
