export interface TurnstileResult {
  ok: boolean;
  error?: string;
}

export async function verifyTurnstile(
  token: string | undefined,
  secretKey: string | undefined,
  remoteIp?: string
): Promise<TurnstileResult> {
  if (!secretKey) {
    return { ok: false, error: 'Turnstile secret key is not configured on the server.' };
  }
  if (!token || !token.trim()) {
    return { ok: false, error: 'Please complete the Cloudflare Turnstile verification.' };
  }

  const form = new URLSearchParams();
  form.set('secret', secretKey);
  form.set('response', token.trim());
  if (remoteIp) form.set('remoteip', remoteIp);

  try {
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    if (!resp.ok) {
      return { ok: false, error: 'Turnstile verification service unavailable.' };
    }
    const data = (await resp.json()) as { success?: boolean; 'error-codes'?: string[] };
    if (!data.success) {
      return {
        ok: false,
        error: `Turnstile check failed (${(data['error-codes'] || ['invalid']).join(', ')}).`,
      };
    }
    return { ok: true };
  } catch {
    return { ok: false, error: 'Failed to reach Cloudflare Turnstile verification endpoint.' };
  }
}
