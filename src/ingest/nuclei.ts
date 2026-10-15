import { z } from 'zod';
import { CVE_ID } from '../lib/normalize';
import type { ExploitRow, ExploitSpec } from './exploits';

/**
 * ProjectDiscovery's nuclei-templates (MIT): cves.json lists every CVE
 * template, one JSON object per line (about 4,500 lines, 2.2 MB). A template
 * means the bug can be found across the internet with a scanner, so ranking
 * treats it as automatable when CISA hasn't said.
 */

export const NUCLEI_URL = 'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json';
const TEMPLATE_BASE = 'https://github.com/projectdiscovery/nuclei-templates/blob/main/';

/** A template's file in the repository: "http/cves/2021/CVE-2021-44228.yaml". */
const TEMPLATE_PATH = /^[A-Za-z0-9_][\w/.-]*\.yaml$/;

const Line = z.object({
  ID: z.string().max(32),
  file_path: z.string().max(300).regex(TEMPLATE_PATH).refine((p) => !p.includes('..')),
});

/** One row per CVE, the first template by path when there are several. Lines that don't parse are skipped. */
export function parseNuclei(body: string): ExploitRow[] {
  const best = new Map<string, ExploitRow>();
  for (const line of body.split('\n')) {
    if (!line.trim()) continue;
    let raw: unknown;
    try {
      raw = JSON.parse(line);
    } catch {
      continue;
    }
    const t = Line.safeParse(raw);
    if (!t.success) continue;
    const id = t.data.ID.trim();
    if (!CVE_ID.test(id)) continue;
    const url = `${TEMPLATE_BASE}${t.data.file_path}`;
    const had = best.get(id);
    if (!had || url < had.url) best.set(id, { cve_id: id, kind: 'template', url });
  }
  return [...best.values()];
}

export const nucleiSpec: ExploitSpec = { source: 'nuclei', url: NUCLEI_URL, label: 'Nuclei templates', parse: parseNuclei };
