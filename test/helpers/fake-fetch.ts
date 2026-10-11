type Matcher = (url: URL, req: Request) => boolean;
type Handler = (req: Request) => Response | Promise<Response>;

/**
 * A fetch stand-in that serves recorded fixtures. Any request without a route
 * fails the test, so nothing reaches the network.
 */
export class FakeFetch {
  readonly calls: Request[] = [];
  private readonly routes: [Matcher, Handler][] = [];

  on(match: string | RegExp | Matcher, handler: Handler): this {
    const matcher: Matcher =
      typeof match === 'string'
        ? (u) => u.href === match || u.href.startsWith(match)
        : match instanceof RegExp
          ? (u) => match.test(u.href)
          : match;
    this.routes.push([matcher, handler]);
    return this;
  }

  readonly fetch: typeof fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    this.calls.push(req);
    const url = new URL(req.url);
    for (const [m, h] of this.routes) if (m(url, req)) return h(req);
    throw new Error(`unexpected fetch: ${req.url}`);
  }) as typeof fetch;

  urls(): string[] {
    return this.calls.map((c) => c.url);
  }
}

/** A gzipped body, served like a plain file (no Content-Encoding). */
export function gzipResponse(text: string): Response {
  return new Response(new Blob([text]).stream().pipeThrough(new CompressionStream('gzip')));
}

export function jsonResponse(body: unknown, init: { status?: number; headers?: Record<string, string> } = {}): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { 'content-type': 'application/json', ...init.headers },
  });
}
