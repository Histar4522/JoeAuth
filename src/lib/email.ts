import type { Bindings } from '../types';

export interface SendEmailInput {
  to: string;
  subject: string;
  html: string;
  text: string;
}

export interface SendEmailResult {
  sent: boolean;
  skipped?: boolean;
  error?: string;
}

export async function sendEmail(env: Bindings, input: SendEmailInput): Promise<SendEmailResult> {
  if (!env.RESEND_API_KEY) {
    console.warn(`[JoeAuth Email Skipped - RESEND_API_KEY missing] To: ${input.to} | Subject: ${input.subject}`);
    return { sent: false, skipped: true };
  }

  try {
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: env.EMAIL_FROM || 'JoeAuth <onboarding@resend.dev>',
        to: [input.to],
        subject: input.subject,
        html: input.html,
        text: input.text,
      }),
    });

    if (!resp.ok) {
      const errText = await resp.text().catch(() => '');
      console.error(`Resend API error (${resp.status}): ${errText}`);
      return { sent: false, error: `Email delivery failed (${resp.status}).` };
    }

    return { sent: true };
  } catch (err) {
    console.error('Resend fetch error:', err);
    return { sent: false, error: 'Failed to reach Resend email service.' };
  }
}

export function verificationEmailContent(appName: string, verifyUrl: string, purpose: 'verify' | 'email_change') {
  const title = purpose === 'email_change' ? `Confirm your new email for ${appName}` : `Verify your ${appName} email`;
  const lead =
    purpose === 'email_change'
      ? 'Click the button below to confirm changing your JoeAuth email address.'
      : 'Welcome to the Joe Universe! Click the button below to verify your email address.';
  return {
    subject: title,
    text: `${title}\n\n${lead}\n\n${verifyUrl}\n\nThis link expires in 30 minutes.`,
    html: `
      <div style="font-family:system-ui,-apple-system,sans-serif;max-width:520px;margin:24px auto;padding:24px;border:1px solid #e5e7eb;border-radius:12px;">
        <h2 style="margin:0 0 12px;color:#111827;">${title}</h2>
        <p style="color:#374151;line-height:1.5;">${lead}</p>
        <p style="margin:24px 0;">
          <a href="${verifyUrl}" style="background:#2563eb;color:#ffffff;padding:12px 20px;border-radius:8px;text-decoration:none;font-weight:600;">Confirm Email</a>
        </p>
        <p style="font-size:12px;color:#6b7280;word-break:break-all;">Or copy this link: ${verifyUrl}</p>
      </div>
    `,
  };
}

export function passwordResetEmailContent(appName: string, resetUrl: string) {
  const subject = `Reset your ${appName} password`;
  return {
    subject,
    text: `${subject}\n\nUse the link below to set a new password (valid for 20 minutes):\n${resetUrl}\n\nIf you did not request this, ignore this email.`,
    html: `
      <div style="font-family:system-ui,-apple-system,sans-serif;max-width:520px;margin:24px auto;padding:24px;border:1px solid #e5e7eb;border-radius:12px;">
        <h2 style="margin:0 0 12px;color:#111827;">${subject}</h2>
        <p style="color:#374151;line-height:1.5;">Click below to reset your password. This link expires in 20 minutes.</p>
        <p style="margin:24px 0;">
          <a href="${resetUrl}" style="background:#2563eb;color:#ffffff;padding:12px 20px;border-radius:8px;text-decoration:none;font-weight:600;">Reset Password</a>
        </p>
        <p style="font-size:12px;color:#6b7280;">If you didn't request a password reset, you can safely ignore this message.</p>
      </div>
    `,
  };
}
