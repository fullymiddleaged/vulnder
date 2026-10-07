const DAY_MS = 86_400_000;

/** 'YYYY-MM-DD' in UTC. */
export function utcDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}

export function addDays(d: Date, days: number): Date {
  return new Date(d.getTime() + days * DAY_MS);
}

export function addHours(d: Date, hours: number): Date {
  return new Date(d.getTime() + hours * 3_600_000);
}

/** The next calendar day for a 'YYYY-MM-DD' string. */
export function nextDay(day: string): string {
  return utcDay(addDays(new Date(`${day}T00:00:00Z`), 1));
}

/**
 * Parses a date or timestamp into canonical ISO form, or null when it is
 * missing or unparseable. Date-only strings ('2026-10-02') become midnight UTC.
 */
export function toIso(value: unknown): string | null {
  if (typeof value !== 'string' || value === '') return null;
  const s = /^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T00:00:00Z` : value;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

/** A response window for people: 24 → "24 hours", 168 → "7 days". */
export function describeHours(hours: number): string {
  return hours < 72 ? `${hours} hours` : `${Math.round(hours / 24)} days`;
}

/** Start of the retention window, as an ISO string. */
export function windowStart(now: Date, days: number): string {
  return addDays(now, -days).toISOString();
}
