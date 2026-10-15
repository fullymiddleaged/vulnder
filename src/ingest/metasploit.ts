import { z } from 'zod';
import { CVE_ID } from '../lib/normalize';
import type { ExploitRow, ExploitSpec } from './exploits';

/**
 * Metasploit Framework's module index (BSD-3-Clause): about 7,200 modules in
 * one ~11 MB JSON file, 3,200 of them naming CVEs. A CVE with an exploit
 * module is one anyone can attack with a ready-made tool; one named only by an
 * auxiliary module (scanners, denial of service, information disclosure) has
 * public attack code. Post-exploitation modules, payloads and the rest are
 * left out.
 */

export const METASPLOIT_URL = 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json';
const MODULE_BASE = 'https://github.com/rapid7/metasploit-framework/blob/master';

/** A module's file in the repository, as the index gives it: "/modules/exploits/windows/smb/ms17_010_eternalblue.rb". */
const MODULE_PATH = /^\/modules\/(exploits|auxiliary)\/[\w/.-]+\.(rb|py|go)$/;
/** Most references read from one module; the largest real one has a few dozen. */
const MAX_REFERENCES = 200;

const Module = z.object({
  type: z.enum(['exploit', 'auxiliary']),
  path: z.string().max(300).regex(MODULE_PATH).refine((p) => !p.includes('..')),
  references: z.array(z.unknown()),
});

/** One row per CVE: an exploit module wins over an auxiliary one, then the first path. */
export function parseMetasploit(body: string): ExploitRow[] {
  const json: unknown = JSON.parse(body);
  if (typeof json !== 'object' || json === null || Array.isArray(json)) throw new Error('Metasploit: not a module index');
  const best = new Map<string, ExploitRow>();
  for (const raw of Object.values(json)) {
    const m = Module.safeParse(raw);
    if (!m.success) continue;
    const kind = m.data.type;
    const url = `${MODULE_BASE}${m.data.path}`;
    for (const ref of m.data.references.slice(0, MAX_REFERENCES)) {
      const id = typeof ref === 'string' ? ref.trim() : '';
      if (!CVE_ID.test(id)) continue;
      const had = best.get(id);
      if (!had || (kind === 'exploit' && had.kind !== 'exploit') || (kind === had.kind && url < had.url)) best.set(id, { cve_id: id, kind, url });
    }
  }
  return [...best.values()];
}

export const metasploitSpec: ExploitSpec = { source: 'metasploit', url: METASPLOIT_URL, label: 'Metasploit', parse: parseMetasploit };
