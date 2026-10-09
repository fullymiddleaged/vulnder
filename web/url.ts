/**
 * Whether search engines may index the page at this query string. A stack in
 * the URL describes someone's infrastructure, so only the bare page is.
 */
export function indexable(search: string): boolean {
  return !new URLSearchParams(search).has('s');
}

/** Only http(s) links are ever rendered, so a stored javascript: URL cannot run. */
export function safeHref(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : null;
  } catch {
    return null;
  }
}
