# Contributing to Vulnder

Thanks for helping. Two kinds of contribution are especially useful: a new **data source** and a new **manifest parser**. Both have a small, fixed interface.

Before opening a pull request, run:

```sh
npm run lint && npm run typecheck && npm test
```

Tests must not touch the network: use recorded fixtures (see below). CI runs the same checks on every pull request.

## Adding a manifest parser

Parsers live in [`src/resolve/manifests/index.ts`](src/resolve/manifests/index.ts). They run in the browser, so a lockfile never leaves the user's machine, and they're tested server-side.

1. Write a `ManifestParser`:
   - `id`: the format name shown to users, e.g. `'poetry.lock'`.
   - `matchesFilename(name)`: true when the file name alone identifies the format.
   - `sniff(text)`: true when pasted content identifies the format. Be strict. Free-text stack descriptions must not match, and a bare word list must not look like a `requirements.txt`.
   - `parse(text)`: returns `Candidate[]`. Use OSV ecosystem names (`npm`, `PyPI`, `crates.io`, `Go`, `Maven`, …). Only return **exact** versions; turn ranges like `^1.2` into `version: null`, because a range doesn't say what is installed. Set `direct: false` for transitive dependencies from lockfiles.
2. Add it to `PARSERS`. More specific formats go first.
3. Add tests to [`test/manifests.test.ts`](test/manifests.test.ts) with a realistic sample. Cover exact versus range versions, direct versus transitive dependencies, and anything that should be skipped.
4. If the format belongs to a new ecosystem, add its prefix to `PREFIXES` in [`src/stack/format.ts`](src/stack/format.ts) and to [docs/STACK_FORMAT.md](docs/STACK_FORMAT.md). Prefixes are a public contract, so never rename one.

## Adding a data source

Sources live in [`src/ingest/sources/`](src/ingest/sources/) and implement `Source<Cursor>` from [`src/ingest/types.ts`](src/ingest/types.ts):

```ts
interface Source<C> {
  name: SourceName;
  initialCursor(now: Date): C;
  fetchChanges(cursor: C, ctx: SourceContext): Promise<{ records: VulnPatch[]; nextCursor: C; done: boolean }>;
}
```

Rules that keep ingest resumable and inside free-plan limits:

- **Use `ctx.fetch`, never the global `fetch`.** It charges the run's budget and applies a timeout.
- **Return one page per call.** The runner stores each page's writes and the new cursor in one batch, then calls you again until you return `done: true` or the budget runs out. Make pages small enough that one fits comfortably in a run.
- **Cursors must be JSON-serialisable** and must let a later run continue exactly where this one stopped. Re-reading a little is fine, because merging is idempotent. Skipping is not.
- **Use only Web APIs** (no Node built-ins). The same code runs in the Worker and in Node.
- **Return `VulnPatch`es, not rows.** A patch is one source's view of one vulnerability. The merge in [`src/ingest/merge.ts`](src/ingest/merge.ts) decides precedence between sources, detects events (`published`, `kev_added`, `epss_crossed`, `fix_released`) and skips writes that change nothing. A new source needs an entry in `SOURCE_FLAGS` and `RANK`, and a migration if it adds `affected.source` values.
- **Throw `RateLimited`** when the upstream says to back off. The run then stops that source cleanly.

Register the source in `SOURCES` and `SOURCE_ORDER` in [`src/ingest/run.ts`](src/ingest/run.ts), and add a staleness threshold in [`src/config.ts`](src/config.ts).

### Fixtures

Add a recorder for your source to [`scripts/record-fixtures.ts`](scripts/record-fixtures.ts). Record a few real, trimmed responses into `test/fixtures/<source>/`, and serve them in tests with `FakeFetch` ([`test/helpers/fake-fetch.ts`](test/helpers/fake-fetch.ts)). Any request without a route fails the test. Then test:

- parsing of the recorded responses;
- paging and cursor movement, including resuming from a saved cursor;
- failure behaviour: rate limits, server errors and malformed responses.

## Style

- TypeScript, strict. Match the surrounding code; comments explain *why*, not what.
- Never log stack URLs, request bodies or free text.
- Wording: only CISA KEV earns "exploited". EPSS is always a *predicted probability*.
- Keep commits small and messages clear.

## Licence

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), as its section 5 describes.
