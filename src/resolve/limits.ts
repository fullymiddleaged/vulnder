/**
 * Input limits shared by the Worker and the page. Kept free of imports so the
 * front-end bundle can use them without pulling in server code.
 */

/** Plenty for a description ("Next.js 14 on Vercel, Postgres 16, …" is under 100); longer lists belong in a manifest. */
export const MAX_TEXT_CHARS = 500;
