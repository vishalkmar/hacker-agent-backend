import nodemailer from 'nodemailer';
import { env } from '../../config/env.js';

let _transport = null;
function transport() {
  if (_transport) return _transport;
  if (!env.email.host) return null; // dev mode: no SMTP configured
  _transport = nodemailer.createTransport({
    host: env.email.host,
    port: env.email.port,
    secure: env.email.port === 465,
    auth: env.email.user ? { user: env.email.user, pass: env.email.pass } : undefined,
  });
  return _transport;
}

// Send an email. In dev (no SMTP) it logs to the console and returns ok so flows still work.
export async function sendMail({ to, subject, html, text }) {
  const t = transport();
  if (!t) {
    console.log(`\n[email:dev] To: ${to}\n[email:dev] ${subject}\n[email:dev] ${text || ''}\n`);
    return { dev: true };
  }
  await t.sendMail({ from: env.email.from, to, subject, html, text });
  return { sent: true };
}

const shell = (title, body) => `
<div style="font-family:Inter,system-ui,sans-serif;background:#F8FAFC;padding:32px">
  <div style="max-width:480px;margin:auto;background:#fff;border:1px solid #E2E8F0;border-radius:16px;padding:28px">
    <div style="font-size:22px;font-weight:700;color:#2563EB">🛡️ CypherMind</div>
    <h2 style="color:#0F172A;margin:18px 0 8px">${title}</h2>
    ${body}
    <p style="color:#64748B;font-size:12px;margin-top:24px">For authorized security testing &amp; learning. If you didn't request this, ignore this email.</p>
  </div>
</div>`;

export function otpEmail(code) {
  return {
    subject: `Your CypherMind code: ${code}`,
    text: `Your CypherMind verification code is ${code}. It expires in ${env.otp.ttlMin} minutes.`,
    html: shell(
      'Verify your email',
      `<p style="color:#475569">Enter this code to continue:</p>
       <div style="font-size:34px;font-weight:800;letter-spacing:10px;color:#0F172A;background:#EFF6FF;border-radius:12px;text-align:center;padding:16px 0;margin:8px 0">${code}</div>
       <p style="color:#64748B;font-size:13px">Expires in ${env.otp.ttlMin} minutes.</p>`
    ),
  };
}

export function receiptEmail(planName, amount) {
  return {
    subject: `Payment receipt — CypherMind ${planName}`,
    text: `Thank you! Your payment of ₹${amount} for the ${planName} plan was successful.`,
    html: shell(
      'Payment successful 🎉',
      `<p style="color:#475569">Thank you! Your <b>${planName}</b> plan is now active.</p>
       <div style="background:#EFF6FF;border-radius:12px;padding:14px 16px;margin:10px 0;color:#0F172A">
         <b>Amount paid:</b> ₹${amount}<br/><b>Plan:</b> ${planName}
       </div>
       <a href="${env.email.appBaseUrl}" style="display:inline-block;margin-top:8px;background:#2563EB;color:#fff;text-decoration:none;padding:10px 18px;border-radius:10px;font-weight:600">Open CypherMind</a>`
    ),
  };
}

export function expiryReminderEmail(planName, days) {
  return {
    subject: `Your CypherMind ${planName} plan expires in ${days} day${days === 1 ? '' : 's'}`,
    text: `Your ${planName} plan expires in ${days} day(s). Renew to keep your limits.`,
    html: shell(
      'Your plan is expiring soon',
      `<p style="color:#475569">Your <b>${planName}</b> plan expires in <b>${days} day${days === 1 ? '' : 's'}</b>. Renew to keep your higher limits and features.</p>
       <a href="${env.email.appBaseUrl}" style="display:inline-block;margin-top:8px;background:#2563EB;color:#fff;text-decoration:none;padding:10px 18px;border-radius:10px;font-weight:600">Renew now</a>`
    ),
  };
}

export function welcomeEmail(name) {
  return {
    subject: 'Welcome to CypherMind 🛡️',
    text: `Welcome${name ? ', ' + name : ''}! Your CypherMind account is ready.`,
    html: shell(
      `Welcome${name ? ', ' + name : ''}!`,
      `<p style="color:#475569">Your account is ready. Jump back in and start working with your AI security copilot.</p>
       <a href="${env.email.appBaseUrl}" style="display:inline-block;margin-top:12px;background:#2563EB;color:#fff;text-decoration:none;padding:10px 18px;border-radius:10px;font-weight:600">Open CypherMind</a>`
    ),
  };
}
