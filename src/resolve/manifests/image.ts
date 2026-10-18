import type { Candidate } from '../types';

/**
 * A container image reference ([registry/][namespace/]name[:tag][@digest]) as
 * a product candidate: the image name, its namespace as the vendor (none for
 * Docker's `library`), and a version when the tag starts with one. Null for a
 * reference that names no image (`scratch`) or still holds a variable.
 */
export function imageCandidate(ref: string): Candidate | null {
  if (!ref || ref === 'scratch' || ref.includes('$')) return null;
  const noDigest = ref.split('@')[0]!;
  const colon = noDigest.lastIndexOf(':');
  const hasTag = colon > noDigest.lastIndexOf('/');
  const path = hasTag ? noDigest.slice(0, colon) : noDigest;
  const tag = hasTag ? noDigest.slice(colon + 1) : null;
  const parts = path.split('/');
  const name = parts[parts.length - 1]!;
  if (!name) return null;
  const vendor = parts.length > 1 && !parts[parts.length - 2]!.includes('.') ? parts[parts.length - 2]! : null;
  const version = tag && /^\d/.test(tag) ? ((/^[\d.]+/.exec(tag)?.[0] ?? null)?.replace(/\.$/, '') ?? null) : null;
  return { kind: 'product', name, vendor: vendor === 'library' ? null : vendor, version, direct: true };
}
