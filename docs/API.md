# Machine API (v1)

Two POST endpoints for scripts and scheduled runners, such as an Azure Function, a Logic App or a cron job feeding a SIEM. They take the stack in the request body, so you never build a compressed `s` value or put a stack in a URL. There's no account, key or Turnstile check.

| Endpoint | In | Out |
|---|---|---|
| `POST /api/v1/stack` | Product and package names with versions, and/or CVE IDs | A stack in the [stack format](STACK_FORMAT.md), and what each name matched |
| `POST /api/v1/rank` | A stack and/or CVE IDs | One flat row per CVE, ranked exactly as the [JSON feed](RANKING.md#in-the-feeds) ranks them, plus recent changes |

Usually you call `stack` when the inventory changes (daily, say) and keep the `stack` it returns. Then you call `rank` on a schedule (hourly) with that stack. A tenant that already has CVE findings, from Defender Vulnerability Management or a scanner, can skip `stack` and send the IDs to `rank`.

## POST /api/v1/stack

```json
{
  "products": [{ "name": "Google Chrome", "vendor": "Google LLC", "version": "130.0.6723.92" }, { "name": "FortiOS", "version": "7.4.3" }],
  "packages": [{ "ecosystem": "npm", "name": "next", "version": "14.2.3" }],
  "cves": ["CVE-2021-44228"]
}
```

- `products`: `name` is required, and `vendor` and `version` are optional. They're matched against the catalog of products in CVE records. A model is never called, so send names, not descriptions.
- `packages`: `ecosystem` is a stack-format prefix (`npm`, `pypi`, `maven`, `go`, `cargo`, `nuget`, `composer`, `gem`, `hex`, `pub`, `swift`, `actions`).
- `cves`: up to 2,000 IDs, carried into the stack as `cve:` items.

Up to 5,000 products and 5,000 packages per request, but no more than 200 distinct products. A stack holds 200 components, so collapse an inventory to one entry per product first.

```json
{
  "schema": 1,
  "stack": "~y0vNL0rM0zM...",
  "resolved": [{ "input": "FortiOS 7.4.3", "items": [{ "item": "p:fortinet/fortios@7.4.3", "label": "FortiOS", "close": false, "known": true }] }],
  "unrecognised": ["Contoso Line-of-Business App"]
}
```

`close: true` marks a close match: a broad name expanded to the products it may mean (see [STACK_FORMAT.md](STACK_FORMAT.md#close-matches)). `known: false` means the catalog holds no CVEs for that item yet. Names in `unrecognised` weren't checked. If nothing at all is recognised, the answer is 422 and still includes `unrecognised`.

## POST /api/v1/rank

```json
{ "stack": "~y0vNL0rM0zM...", "cves": ["CVE-2024-3400"], "days": 30 }
```

Send `stack`, `cves` or both. `days` is the window for new CVEs (1–90, default 30). Listed CVEs are ranked whatever their age.

```json
{
  "schema": 1,
  "stack": "…",
  "days": 30,
  "generatedAt": "2026-10-21T09:00:00.000Z",
  "dataVersion": 1234,
  "versionCheckUnavailable": false,
  "priorities": { "act": 2, "attend": 0, "watch": 1, "track": 0 },
  "rows": [
    {
      "cve": "CVE-2026-1001", "title": "…", "priority": "act", "score": 92, "respondWithinHours": 24,
      "reasons": ["On CISA KEV", "…"], "exploited": true, "kevAddedAt": "…", "kevDueDate": null,
      "knownRansomware": false, "ssvcExploitation": "active", "epss": 0.41, "epssPercentile": 0.98,
      "cvss": 9.1, "publishedAt": "…", "beforeWindow": false, "matched": ["npm:next@14.2.3"],
      "match": "exact", "confidence": "version_confirmed", "fixedVersions": ["14.2.5"], "mitigation": null,
      "advisory": "https://…", "patch": null, "exploitRef": null
    }
  ],
  "changes": [{ "id": "CVE-2026-1001/kev_added/2026-10-18T00:00:00.000Z", "cve": "CVE-2026-1001", "type": "kev_added", "occurredAt": "…", "title": "…", "priority": "act" }],
  "fixFirst": [],
  "support": [],
  "targeted": [],
  "watching": [],
  "links": { "page": "…", "json": "…", "atom": "…", "badge": "…" }
}
```

- Each row holds only scalars and arrays of strings, so it maps straight onto a log table's columns, such as a custom table written through Azure Monitor's Logs Ingestion API.
- `exploited` is true only for CVEs on CISA KEV. `ssvcExploitation` is CISA's Vulnrichment value (`active`, `poc`, `none` or null). `epss` is a predicted probability. `score` orders results within a priority and isn't a probability. Field meanings are in [RANKING.md](RANKING.md).
- `changes` covers the last 7 days: CVEs published, added to KEV, reported exploited by CISA, crossing the EPSS threshold, or getting a fix. Its `id` stays the same from one poll to the next, so deduplicate on it.
- `occurredAt` is when the change happened, not when Vulnder learned of it. A CVE can arrive with an older date, so don't use it as a cursor. To alert on what's new, compare each poll's rows with the last poll's: a CVE that wasn't there before, or whose priority rose.
- `fixFirst`, `support`, `targeted`, `watching` and `listed` are as in the JSON feed. An item in `watching` matched nothing in the window, which can also mean Vulnder doesn't know its key, so don't report it as safe.

## Versioning

`schema` goes up only when a field is removed or changes meaning. New fields can appear at any time, so ignore fields you don't know. The `/api/v1/` paths keep working as long as schema 1 is served.

## Limits

- `stack`: per IP address, 20 new requests a minute and 200 lookups of names a day (a request with only CVE IDs doesn't count toward the 200). Lookups cost catalog reads, so keep the stack and reuse it.
- `rank`: the feed's limits, in a bucket of their own: 60 new lookups a minute, or 6 for very large stacks such as the Linux kernel. Repeats are served from the edge cache and aren't limited. The cache refreshes when new data arrives, roughly hourly.
- Over a limit, you get HTTP 429 with `Retry-After`. Wait that long; don't retry in a loop.
- Runners on shared cloud addresses (Azure Functions and Logic Apps on consumption plans) share their region's outbound IPs with other customers, and so share these limits. Polling once an hour is well inside them. If you're refused anyway, give the runner its own outbound IP (a NAT gateway), or self-host.

## Privacy

Vulnder doesn't log or store request bodies, and neither endpoint calls a model. The stack travels in the body, not a URL. IPs are used only as rate-limit keys, and the daily count of `stack` lookups is kept under a hash of the IP salted afresh each day, deleted with that day's counters. Cloudflare, which runs the service, sees every request.

## Self-hosting

No new bindings or secrets. `stack` uses `RESOLVE_LIMITER` and `rank` uses `FEED_LIMITER` and `FEED_HEAVY_LIMITER`, both under keys prefixed `api:`. See [SELF_HOSTING.md](SELF_HOSTING.md).
