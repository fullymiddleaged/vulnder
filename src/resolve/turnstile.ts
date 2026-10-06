/** Server-side Turnstile validation (https://developers.cloudflare.com/turnstile/get-started/server-side-validation/). */

export const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

/** The widget's action for stack submissions; a token minted for anything else is refused. */
export const TURNSTILE_ACTION = 'resolve';

/** Cloudflare's test secrets answer with hostname "localhost" and action "test", so the checks below don't apply. */
const TEST_SECRET = /^[123]x0+AA$/;

export interface TurnstileExpectations {
  /** Where the widget must have been served, e.g. vulnder.dev. */
  hostname?: string;
  action?: string;
}

export async function verifyTurnstile(
  fetchImpl: typeof fetch,
  secret: string,
  token: string,
  remoteIp: string | null,
  expect: TurnstileExpectations = {},
): Promise<{ success: boolean; errors: string[] }> {
  if (!token || token.length > 2048) return { success: false, errors: ['missing-input-response'] };
  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  if (remoteIp) form.append('remoteip', remoteIp);
  try {
    const res = await fetchImpl(SITEVERIFY_URL, { method: 'POST', body: form, signal: AbortSignal.timeout(5000) });
    const body = (await res.json()) as { success?: boolean; 'error-codes'?: string[]; hostname?: string; action?: string };
    if (body.success !== true) return { success: false, errors: body['error-codes'] ?? [] };
    if (!TEST_SECRET.test(secret)) {
      if (expect.hostname && body.hostname !== expect.hostname) return { success: false, errors: ['hostname-mismatch'] };
      if (expect.action && body.action !== expect.action) return { success: false, errors: ['action-mismatch'] };
    }
    return { success: true, errors: [] };
  } catch (err) {
    // The reason never contains the token or the secret.
    console.error(`turnstile siteverify failed: ${err instanceof Error ? `${err.name}: ${err.message}` : String(err)}`);
    return { success: false, errors: ['internal-error'] };
  }
}
