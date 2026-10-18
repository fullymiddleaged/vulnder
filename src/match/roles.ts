import { ownValue } from '../lib/normalize';

/**
 * What a CVE gives an attacker, for chain rules (docs/plans/chain-risk-and-cve-roles.md).
 * What it needs first (network position, a login, a user's help) comes from the
 * CVSS vector through reach() in priority.ts, so this says only what it gives.
 *
 * A label, never a rank: nothing reads it to order results yet, and when
 * something does, a written rule in priority.ts decides with a reason. Code
 * only: a fixed CWE map, then the title's wording, then 'other'.
 */
export type Role = 'code-exec' | 'auth-bypass' | 'priv-esc' | 'info-leak' | 'dos' | 'other';

/** When CWEs disagree, the one that gives an attacker the most wins. */
export const ROLE_ORDER: Role[] = ['code-exec', 'auth-bypass', 'priv-esc', 'info-leak', 'dos', 'other'];

const role = (r: Role, ids: number[]) => ids.map((n) => [`CWE-${n}`, r] as const);

/**
 * CWEs that say what the bug gives. Broad ones (CWE-20 input validation,
 * CWE-284 access control) are left out: the title decides those. SQL injection
 * counts as an information leak, its usual outcome.
 */
const ROLE_BY_CWE: Readonly<Record<string, Role>> = Object.fromEntries([
  ...role('code-exec', [77, 78, 94, 95, 96, 97, 98, 434, 470, 502, 917, 1336]),
  ...role('auth-bypass', [285, 287, 288, 290, 294, 302, 303, 304, 305, 306, 425, 620, 639, 640, 798, 862, 863, 1390, 1391]),
  ...role('priv-esc', [250, 266, 267, 268, 269, 270, 271, 272, 273, 274, 276, 279, 281, 648, 732]),
  ...role('info-leak', [22, 23, 24, 35, 36, 89, 125, 200, 201, 203, 209, 212, 532, 538, 548, 552, 611, 918]),
  ...role('dos', [369, 400, 404, 405, 407, 476, 617, 674, 770, 772, 789, 834, 835, 1050, 1333]),
]);

/**
 * Memory corruption runs code only sometimes. It counts as code execution when
 * the vector rates confidentiality, integrity and availability all high, and as
 * a denial of service when only availability is high.
 */
const MEMORY_CORRUPTION = new Set([119, 120, 121, 122, 190, 415, 416, 787, 843].map((n) => `CWE-${n}`));

/** Title wording, checked in ROLE_ORDER. No nested quantifiers, so each is linear in the title. */
const BY_TITLE: [Role, RegExp][] = [
  ['code-exec', /\b(?:remote|arbitrary)\s+(?:code|command)\s+execution\b|\bcode\s+execution\b|\bRCE\b|\b(?:os\s+)?command\s+injection\b|\bcode\s+injection\b|\bdeserializ/i],
  ['auth-bypass', /\b(?:authentication|auth|login|authorization)\s+bypass|\bbypass(?:es|ing)?\s+(?:the\s+)?(?:authentication|authorization)\b|\bmissing\s+(?:authentication|authorization)\b|\bhard-?coded\s+(?:credentials?|passwords?)\b/i],
  ['priv-esc', /\bprivilege\s+escalation\b|\belevation\s+of\s+privilege\b|\bescalate\s+privileges?\b/i],
  ['info-leak', /\binformation\s+(?:disclosure|leak|exposure)\b|\b(?:path|directory)\s+traversal\b|\bsql\s+injection\b|\bsensitive\s+(?:data|information)\s+(?:exposure|disclosure)\b/i],
  ['dos', /\bdenial[\s-]+of[\s-]+service\b/i],
];
/** Titles are a CNA's text; a long one is cut before matching. */
const MAX_TITLE = 600;

export function roleOf(cwe: readonly string[], title: string | null, vector: string | null): Role {
  const impact = impactOf(vector);
  let best: Role | null = null;
  let corrupted = false;
  for (const id of cwe) {
    let r = ownValue(ROLE_BY_CWE, id);
    if (!r && MEMORY_CORRUPTION.has(id)) {
      corrupted = true;
      if (impact?.allHigh) r = 'code-exec';
    }
    if (r && (best === null || ROLE_ORDER.indexOf(r) < ROLE_ORDER.indexOf(best))) best = r;
  }
  if (best) return best;
  const text = title?.slice(0, MAX_TITLE) ?? '';
  for (const [r, re] of BY_TITLE) if (re.test(text)) return r;
  return corrupted && impact?.availability ? 'dos' : 'other';
}

/** Confidentiality, integrity and availability from a CVSS 3.x or 4.0 vector (4.0 names them VC, VI, VA). */
function impactOf(vector: string | null): { allHigh: boolean; availability: boolean } | null {
  if (!vector || !/^CVSS:(3\.[01]|4\.0)\//.test(vector)) return null;
  const metrics = new Map(vector.split('/').slice(1).map((m) => m.split(':', 2) as [string, string]));
  const high = (k: string) => (metrics.get(k) ?? metrics.get(`V${k}`)) === 'H';
  return { allHigh: high('C') && high('I') && high('A'), availability: high('A') };
}
