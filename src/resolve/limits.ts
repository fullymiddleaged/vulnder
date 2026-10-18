/**
 * Input limits and time budgets shared by the Worker and the page. Kept free of
 * imports so the front-end bundle can use them without pulling in server code.
 */

/** Plenty for a description ("Next.js 14 on Vercel, Postgres 16, …" is under 100); longer lists belong in a manifest. */
export const MAX_TEXT_CHARS = 500;

/** Manifest files are read in the browser, so this guards the page, not the Worker; a big monorepo lockfile is a few MB. */
export const MAX_MANIFEST_BYTES = 10_000_000;
/** About what 10 MB of lockfile holds; stops a line-based file (requirements.txt, a Dockerfile) of junk tying up the page. */
export const MAX_MANIFEST_LINES = 300_000;
/** Entries one lookup may send, which the Worker enforces; when a file has more, direct dependencies go first. */
export const MAX_MANIFEST_ENTRIES = 5000;

/** Each Jev call gives up after this and parsing carries on without it. Measured 0.4-1.4 s in October 2026. */
export const JEV_TIMEOUT_MS = 3_000;
/**
 * Extraction asks the fallback model too once the first has taken this long,
 * or as soon as the first fails. The first measured 3.3-5.4 s on 2026-10-11
 * and 1.6-8.9 s on 2026-10-18; the fallback 1.2-2.1 s.
 */
export const EXTRACT_HEDGE_MS = 8_000;
/** Both extraction models are given up after this, and the request falls back to adding items by hand. */
export const EXTRACT_DEADLINE_MS = 16_000;
/** The longest reading a description spends on model calls: Jev's screen, extraction, then Jev's judgement. */
export const READ_DEADLINE_MS = JEV_TIMEOUT_MS + EXTRACT_DEADLINE_MS + JEV_TIMEOUT_MS;
