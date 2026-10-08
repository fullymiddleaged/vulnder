/**
 * Input limits shared by the Worker and the page. Kept free of imports so the
 * front-end bundle can use them without pulling in server code.
 */

/** Plenty for a description ("Next.js 14 on Vercel, Postgres 16, …" is under 100); longer lists belong in a manifest. */
export const MAX_TEXT_CHARS = 500;

/** Manifest files are read in the browser, so this guards the page, not the Worker; a big monorepo lockfile is a few MB. */
export const MAX_MANIFEST_BYTES = 10_000_000;
/** About what 10 MB of lockfile holds; stops a line-based file (requirements.txt, a Dockerfile) of junk tying up the page. */
export const MAX_MANIFEST_LINES = 300_000;
/** Entries one lookup may send, which the Worker enforces; when a file has more, direct dependencies go first. */
export const MAX_MANIFEST_ENTRIES = 5000;
