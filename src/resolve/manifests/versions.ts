/**
 * Exact-version helpers. A manifest range (^1.2.0, >=2, ~=1.4) does not say
 * which version is installed, so it becomes "no version" rather than a guess.
 */

const SEMVERISH = /^v?\d+(\.\d+){0,3}([-+][0-9A-Za-z.-]+)?$/;

/** npm / composer: "1.2.3", "=1.2.3", "v1.2.3". */
export function exactSemver(spec: unknown): string | null {
  if (typeof spec !== 'string') return null;
  const s = spec.trim().replace(/^=\s*/, '');
  return SEMVERISH.test(s) ? s.replace(/^v(?=\d)/, '') : null;
}

/** Cargo: only "=1.2.3" is exact; "1.2.3" means ^1.2.3. */
export function exactCargo(spec: unknown): string | null {
  if (typeof spec !== 'string') return null;
  const m = /^=\s*(\S+)$/.exec(spec.trim());
  return m && SEMVERISH.test(m[1]!) ? m[1]! : null;
}

/** PEP 508 requirement: name, extras, and an exact `==` / `===` pin if present. */
export function parsePep508(req: string): { name: string; version: string | null } | null {
  const s = req.split(';')[0]!.split('#')[0]!.trim();
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/.exec(s);
  if (!m) return null;
  const spec = m[3]!.replace(/^\(|\)$/g, '').trim();
  const pin = /^===?\s*([^\s,*]+)$/.exec(spec);
  return { name: m[1]!, version: pin ? pin[1]! : null };
}
