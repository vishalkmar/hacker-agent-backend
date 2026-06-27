import bcrypt from 'bcryptjs';
import { query, newId } from '../../db/index.js';
import { env } from '../../config/env.js';
import { sendMail, otpEmail } from '../email/mailer.js';

function httpErr(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

const normEmail = (e) => String(e || '').trim().toLowerCase();
const genCode = () => String(Math.floor(100000 + Math.random() * 900000)); // 6 digits

// Create + email an OTP. Enforces a resend cooldown per email.
export async function issueOtp(email, purpose = 'auth') {
  const e = normEmail(email);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) throw httpErr(400, 'Valid email is required');

  const recent = await query(
    `SELECT created_at FROM email_otps WHERE email = $1 ORDER BY created_at DESC LIMIT 1`,
    [e]
  );
  if (recent[0]) {
    const ageSec = (Date.now() - new Date(recent[0].created_at).getTime()) / 1000;
    if (ageSec < env.otp.resendCooldownSec) {
      throw httpErr(429, `Please wait ${Math.ceil(env.otp.resendCooldownSec - ageSec)}s before requesting another code`);
    }
  }

  // Invalidate previous codes for this email, then store the new one.
  await query(`DELETE FROM email_otps WHERE email = $1`, [e]);
  const code = genCode();
  const codeHash = await bcrypt.hash(code, 8);
  const expiresAt = new Date(Date.now() + env.otp.ttlMin * 60_000);
  await query(
    `INSERT INTO email_otps (id, email, code_hash, purpose, expires_at) VALUES ($1,$2,$3,$4,$5)`,
    [newId(), e, codeHash, purpose, expiresAt]
  );

  const mail = otpEmail(code);
  await sendMail({ to: e, ...mail });
  return { sent: true, cooldownSec: env.otp.resendCooldownSec };
}

// Verify a submitted code. Throws on invalid/expired/too-many-attempts. Consumes on success.
export async function verifyOtp(email, code) {
  const e = normEmail(email);
  const rows = await query(
    `SELECT id, code_hash, attempts, expires_at FROM email_otps WHERE email = $1 ORDER BY created_at DESC LIMIT 1`,
    [e]
  );
  const otp = rows[0];
  if (!otp) throw httpErr(400, 'No code found — request a new one');
  if (new Date(otp.expires_at).getTime() < Date.now()) {
    await query(`DELETE FROM email_otps WHERE email = $1`, [e]);
    throw httpErr(400, 'Code expired — request a new one');
  }
  if (otp.attempts >= env.otp.maxAttempts) {
    await query(`DELETE FROM email_otps WHERE email = $1`, [e]);
    throw httpErr(429, 'Too many attempts — request a new code');
  }
  const ok = await bcrypt.compare(String(code || ''), otp.code_hash);
  if (!ok) {
    await query(`UPDATE email_otps SET attempts = attempts + 1 WHERE id = $1`, [otp.id]);
    throw httpErr(401, 'Incorrect code');
  }
  await query(`DELETE FROM email_otps WHERE email = $1`, [e]); // consume
  return true;
}
