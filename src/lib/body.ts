/** The body was over the cap, by its Content-Length or by what arrived. */
export class BodyTooLarge extends Error {
  constructor() {
    super('request too large');
    this.name = 'BodyTooLarge';
  }
}

/**
 * Reads a request body as text, stopping as soon as it passes `maxBytes`.
 * Content-Length alone isn't enough: a chunked body has none, and
 * `req.json()` would otherwise read all of it (up to Workers' 100 MB).
 */
export async function readCapped(req: Request, maxBytes: number): Promise<string> {
  const declared = Number(req.headers.get('content-length'));
  if (declared > maxBytes) throw new BodyTooLarge();
  if (!req.body) return '';
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel();
      throw new BodyTooLarge();
    }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.byteLength;
  }
  return new TextDecoder().decode(all);
}
