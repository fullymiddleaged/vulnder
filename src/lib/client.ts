/**
 * The key a client is rate-limited and counted by: its IPv4 address, or the
 * /64 of its IPv6 address. One connection usually holds a whole /64, so keying
 * by the full IPv6 address would give it 2^64 fresh buckets.
 */
export function clientKey(ip: string | null | undefined): string {
  if (!ip) return 'unknown';
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped) return mapped[1]!;
  if (!ip.includes(':')) return ip;
  const [head, tail, ...rest] = ip.split('::');
  if (rest.length > 0) return ip;
  const front = head ? head.split(':') : [];
  const back = tail === undefined ? [] : tail ? tail.split(':') : [];
  const groups = tail === undefined ? front : [...front, ...Array<string>(Math.max(0, 8 - front.length - back.length)).fill('0'), ...back];
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return ip;
  return `${groups
    .slice(0, 4)
    .map((g) => parseInt(g, 16).toString(16))
    .join(':')}::/64`;
}
