# Stack URL format (version 1)

A stack is the list of things you run. Vulnder puts it in the `s` query parameter, so the same stack works for the page, the JSON feed, the Atom feed and the badge:

```
/?s=npm:next@14.2.3,pypi:fastapi,p:postgresql/postgresql@16,p:cisco/ios_xe
/api/feed?s=…   /feed.xml?s=…   /badge.svg?s=…
```

This format is a public contract: once a feed URL is bookmarked, it has to keep working. Changes are additive, and a breaking change would get a new version marker (see [Versioning](#versioning)).

## Items

`s` is a comma-separated list of items. Each item is a package or a product, with an optional version after `@`.

| Item | Meaning |
|---|---|
| `npm:next@14.2.3` | npm package `next`, version 14.2.3 |
| `npm:@angular/core` | Scoped npm package, any version |
| `pypi:fastapi` | PyPI package |
| `maven:org.apache.logging.log4j:log4j-core@2.17.1` | Maven `group:artifact` |
| `go:github.com/containers/podman/v5@v5.6.0` | Go module |
| `p:cisco/ios_xe@17.9` | Product: vendor `cisco`, product `ios_xe` |

### Package prefixes

| Prefix | Ecosystem |
|---|---|
| `npm` | npm |
| `pypi` | PyPI |
| `cargo` | crates.io |
| `go` | Go |
| `maven` | Maven |
| `nuget` | NuGet |
| `composer` | Packagist |
| `gem` | RubyGems |
| `hex` | Hex |
| `pub` | Pub |
| `swift` | Swift (package URL) |
| `actions` | GitHub Actions |

Prefixes are lowercase and never change meaning.

### Products

`p:vendor/product` names a product the way CVE records and CPEs do. Vendor and product are normalised to lowercase, with any run of characters other than `a–z` and `0–9` turned into `_`. So `p:Cisco/IOS XE` becomes `p:cisco/ios_xe`.

### Versions

The version is everything after the last `@`. An `@` in the first position doesn't count, because npm scopes start with `@`. Versions are 1–64 characters from `A–Z a–z 0–9 . _ + ~ : - ^ *`.

For packages, a version lets Vulnder check whether that exact version is affected. Without one, results are labelled **Product match**.

### Close matches

An item starting with `?` is a **close match**: something your description loosely fits rather than names outright. For example, "Cisco switches" becomes `?p:cisco/ios_xe,?p:cisco/nx_os,…`. Close matches are shown, labelled "Close match", and ranked after exact matches in the same tier. If the same item appears both with and without `?`, the exact one wins, and a close match of something also named exactly, at any version, is dropped (products match whatever the version, so it would only repeat the exact item's CVEs). Older URLs without `?` items mean exactly what they did before.

### Teams

An item ending in `;` and a team is **owned by that team**: `p:cisco/ios_xe@17.9;network`. The teams are `network`, `database`, `frontend`, `backend`, `platform`, `endpoints` and `business`, lowercase. An item without one is Unassigned. Vulnder adds teams only for stacks described as enterprise (see [RANKING.md](RANKING.md#teams)); you can add or change them by hand. A team only groups results; it never changes them.

The team comes after the version, and after the close-match mark: `?p:f5/nginx@1.27;platform`. If the same item appears with different teams, the first one wins.

### Edge devices

A product ending in `;edge` **faces the internet**, and one ending in `;internal` **doesn't**: `p:acme/customer_portal;edge`, `p:fortinet/fortios;internal`. Without either, Vulnder decides from the product: VPNs, edge firewalls, gateways and ADCs are edge devices, everything else isn't. Edge devices get CISA's BOD 26-04 deadlines for an internet-facing system (see [RANKING.md](RANKING.md#edge-devices)). The tag comes last, after the team if there is one: `?p:fortinet/fortios@7.4;network;internal`. Only products take it. If the same item appears with different tags, the first one wins.

`;` is reserved for the team and the edge tag, so an item with any other `;` suffix, with them out of order, or with either one twice, is invalid.

### Escaping

Inside an item, write `,` as `%2C` and `%` as `%25`. Everything else is handled by normal URL encoding of the query value.

## Canonical form

Vulnder rewrites every stack into one canonical form, so equivalent stacks share a URL and a cache entry:

- package names are normalised the way their registry compares them (for example, PyPI names follow PEP 503, so `Django_REST.framework` becomes `django-rest-framework`, and npm names are lowercased);
- duplicate items are removed, keeping the exact item over a `?` close match, and the first team and edge tag;
- a `?` close match of an item also given exactly, at any version, is removed;
- items are sorted.

The JSON feed returns the canonical value as `stack`.

## Compressed form

Long stacks are compressed. A value starting with `~` is the rest of the plain value, compressed with raw DEFLATE (RFC 1951) and encoded as unpadded base64url (RFC 4648 §5):

```
s=~y0vNL0rM0zM...
```

Vulnder compresses any stack whose plain form is longer than 1,500 characters. Either form is accepted on input.

## Limits

- At most **200 items**. For larger stacks, self-host Vulnder.
- At most 16,000 characters in `s` itself, and 65,536 characters once decompressed.

Requests over these limits get HTTP 400 with an explanation.

## Versioning

This document describes version 1, which has no marker. A future incompatible version would start with `vN;` (for example `s=v2;…`). `v` followed by a digit and `;` is not a valid version 1 item, so the two can never be confused. Version 1 URLs will keep working.
