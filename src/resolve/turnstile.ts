/** Server-side Turnstile validation (https://developers.cloudflare.com/turnstile/get-started/server-side-validation/). */

export const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

export async function verifyTurnstile(
  fetchImpl: typeof fetch,
  secret: string,
  token: string,
  remoteIp: string | null,
): Promise<{ success: boolean; errors: string[] }> {
  if (!token || token.length > 2048) return { success: false, errors: ['missing-input-response'] };
  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  if (remoteIp) form.append('remoteip', remoteIp);
  try {
    const res = await fetchImpl(SITEVERIFY_URL, { method: 'POST', body: form, signal: AbortSignal.timeout(5000) });
    const body = (await res.json()) as { success?: boolean; 'error-codes'?: string[] };
    return { success: body.success === true, errors: body['error-codes'] ?? [] };
  } catch (err) {
    // The reason never contains the token or the secret.
    console.error(`turnstile siteverify failed: ${err instanceof Error ? `${err.name}: ${err.message}` : String(err)}`);
    return { success: false, errors: ['internal-error'] };
  }
}
