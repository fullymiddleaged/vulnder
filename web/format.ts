import type { Change } from './api';

/** Pure formatting helpers for the UI, kept DOM-free so they can be tested. */

export function describeChange(c: Change): string {
  const name = c.title ? `${c.vulnId}: ${c.title}` : c.vulnId;
  switch (c.type) {
    case 'kev_added':
      return `${name} was added to CISA KEV (known exploited).`;
    case 'epss_crossed':
      return `${name}: EPSS rose to ${pct(c.detail.to as number)} (predicted, not observed, exploitation).`;
    case 'fix_released':
      return `${name}: fix released in ${String(c.detail.package ?? c.detail.product ?? '')} ${String(c.detail.fixedVersion ?? '')}.`;
    default:
      return `${name} was published.`;
  }
}

export function pct(v: number): string {
  return `${(v * 100).toFixed(v < 0.01 ? 2 : 1)}%`;
}

export function ordinal(n: number): string {
  const s = ['th', 'st', 'nd', 'rd'];
  const v = n % 100;
  return `${n}${s[(v - 20) % 10] ?? s[v] ?? s[0]}`;
}

export function ago(iso: string, now = Date.now()): string {
  const minutes = Math.round((now - Date.parse(iso)) / 60_000);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  return hours < 48 ? `${hours} h ago` : `${Math.round(hours / 24)} days ago`;
}
