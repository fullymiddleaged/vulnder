# Forking and redeploying Vulnder

For anyone copying, forking or running their own public copy of [Vulnder](https://github.com/fullymiddleaged/vulnder). Deploying is covered in [SELF_HOSTING.md](SELF_HOSTING.md).

## What the licence requires

Vulnder is licensed under the [Apache License 2.0](../LICENSE), copyright 2026 Pete Salmond. Anyone may use, change, deploy and sell it. When you copy, modify or redistribute it, as source or as a running service built from it, section 4 asks four things:

1. **Keep [LICENSE](../LICENSE)** and pass it on with the code.
2. **Keep [NOTICE](../NOTICE).** Its attribution goes with every redistribution: in a NOTICE file, in the documentation, or wherever the product shows third-party notices. You may add your own attribution below it, never in place of it.
3. **Keep existing copyright and attribution notices** in the files you keep.
4. **Mark files you change** with a prominent notice saying you changed them, for example a comment at the top: `// Modified by <you>, 2026: <what changed>`.

You can license your own changes under other terms, but the code that came from Vulnder stays Apache-2.0.

Material inside the repository has licences of its own. Keep them with it:

- `public/fonts/`: SIL Open Font License 1.1. Keep the OFL files beside the fonts.
- `test/fixtures/injection/corpus.json`: text from garak (Apache-2.0) and PayloadsAllTheThings (MIT). See its README.
- `.claude/skills/humanizer/`: MIT, from [blader/humanizer](https://github.com/blader/humanizer). Keep its LICENSE beside it.
- Data shown by a deployment: the GitHub Advisory Database is CC BY 4.0, and FIRST asks for "EPSS scores courtesy of FIRST". Keep the data credits in the page footer of any public deployment.

This is a summary. [LICENSE](../LICENSE) is what binds.

## The name and logo

The licence grants no rights to the name (section 6). "Vulnder" and its logo identify this project, so a fork or a public deployment needs a name and logo of its own. Saying where it came from ("based on Vulnder") is fine and welcome.

To rename a deployment, change `DISPLAY_NAME` and `BASE_URL` in `wrangler.jsonc`, the name and `vulnder.com` in `public/index.html`, `public/robots.txt`, `public/sitemap.xml` and `public/llms.txt`, the logo in every page's header (`public/*.html`), the loader in `web/main.ts`, `public/favicon.svg` and the files in `public/brand/` (including the `og:image` social card every page links to), and `name` in `package.json`. Rewrite or delete `public/brand.html`, which describes Vulnder's logo. Point `public/.well-known/security.txt` at your own security contact, or delete it, so reports about your deployment reach you.

## Requests from the author (not required by the licence)

- **Credit the original** in your fork's README: `Based on [Vulnder](https://github.com/fullymiddleaged/vulnder) by Pete Salmond.`
- **Send fixes upstream.** If a fork fixes something general, a pull request helps everyone. See [CONTRIBUTING.md](../CONTRIBUTING.md).
- **Star the repository** if it's useful to you. It helps other people find it and tells the author it's in use.
