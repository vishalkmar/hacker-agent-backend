import { env } from '../../config/env.js';

// Parse `EMAIL_FROM` = "Name <email@x>" or "email@x" into { name, email }.
export function parseFrom(from) {
  const m = /^\s*(.*?)\s*<([^>]+)>\s*$/.exec(from || '');
  if (m) return { name: m[1] || 'CypherMind', email: m[2].trim() };
  return { name: 'CypherMind', email: (from || 'no-reply@cyphermind.local').trim() };
}

// Send via Brevo transactional HTTP API. attachments: [{ name, base64 }].
// Returns { messageId } or throws.
export async function sendBrevoEmail({ to, subject, html, text, attachments }) {
  const sender = parseFrom(env.email.from);
  const body = {
    sender,
    to: [{ email: to }],
    subject,
    htmlContent: html || `<p>${text || ''}</p>`,
    textContent: text || undefined,
  };
  if (attachments?.length) {
    body.attachment = attachments.map((a) => ({ name: a.name, content: a.base64 }));
  }
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': env.email.brevoApiKey,
      'Content-Type': 'application/json',
      accept: 'application/json',
    },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(`Brevo send failed (${res.status}): ${json.message || JSON.stringify(json).slice(0, 200)}`);
  }
  return { messageId: json.messageId };
}
