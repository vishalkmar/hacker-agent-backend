import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { query, newId } from '../../db/index.js';
import { env } from '../../config/env.js';
import { issueOtp, verifyOtp } from './otp.js';
import { sendMail, welcomeEmail } from '../email/mailer.js';

const SAFE_USER = 'id, email, display_name, role, daily_message_limit, daily_messages_used, email_verified, created_at';

function planLimit(role) {
  switch (role) {
    case 'pro': return 500;
    case 'enterprise': return 100000;
    case 'student': return 200;
    case 'admin': return 1000000;
    default: return env.auth.freeDailyLimit;
  }
}

export function issueToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, role: user.role }, env.auth.jwtSecret, {
    expiresIn: env.auth.tokenTtl,
  });
}

export function verifyToken(token) {
  try {
    return jwt.verify(token, env.auth.jwtSecret);
  } catch {
    return null;
  }
}

export function isAdminEmail(email) {
  return !!email && env.auth.adminEmails.includes(String(email).toLowerCase());
}

export async function getUserById(id) {
  const rows = await query(`SELECT ${SAFE_USER} FROM users WHERE id = $1`, [id]);
  const u = rows[0];
  if (u) u.is_admin = isAdminEmail(u.email);
  return u || null;
}

export async function updateProfile(id, { display_name, avatar_url }) {
  const name = (display_name || '').toString().trim();
  if (name) await query('UPDATE users SET display_name = $1 WHERE id = $2', [name.slice(0, 80), id]);
  if (avatar_url !== undefined) await query('UPDATE users SET avatar_url = $1 WHERE id = $2', [avatar_url, id]);
  return getUserById(id);
}

export async function register({ email, password, name }) {
  const e = String(email || '').trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) throw httpErr(400, 'Valid email is required');
  if (!password || String(password).length < 8) throw httpErr(400, 'Password must be at least 8 characters');

  const exists = await query('SELECT id FROM users WHERE email = $1', [e]);
  if (exists.length) throw httpErr(409, 'Email already registered');

  const hash = await bcrypt.hash(String(password), 10);
  const id = newId();
  const role = 'free';
  await query(
    `INSERT INTO users (id, email, password_hash, display_name, role, daily_message_limit)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [id, e, hash, name || e.split('@')[0], role, planLimit(role)]
  );
  const user = await getUserById(id);
  return { user, token: issueToken(user) };
}

export async function login({ email, password }) {
  const e = String(email || '').trim().toLowerCase();
  const rows = await query(`SELECT id, email, password_hash, role FROM users WHERE email = $1`, [e]);
  const u = rows[0];
  if (!u || !u.password_hash) throw httpErr(401, 'Invalid email or password');
  const ok = await bcrypt.compare(String(password || ''), u.password_hash);
  if (!ok) throw httpErr(401, 'Invalid email or password');
  const user = await getUserById(u.id);
  return { user, token: issueToken(user) };
}

// ----- Phase 12: passwordless email-OTP flow -----

// Step 1: user enters email (+ name if new). We send an OTP and tell the client the mode.
export async function startOtp({ email, name }) {
  const e = String(email || '').trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) throw httpErr(400, 'Valid email is required');

  const rows = await query('SELECT id, email_verified FROM users WHERE email = $1', [e]);
  let mode = 'login';
  if (!rows[0]) {
    // Create a pending (unverified) user so the name is captured now.
    const role = 'free';
    await query(
      `INSERT INTO users (id, email, display_name, role, daily_message_limit, email_verified)
       VALUES ($1,$2,$3,$4,$5,false)`,
      [newId(), e, name || e.split('@')[0], role, planLimit(role)]
    );
    mode = 'register';
  } else if (!rows[0].email_verified) {
    mode = 'register';
  }
  await issueOtp(e, 'auth');
  return { mode, email: e };
}

// Step 2: verify the code -> mark verified, (welcome email on first verify), issue JWT.
export async function verifyOtpLogin({ email, code }) {
  const e = String(email || '').trim().toLowerCase();
  await verifyOtp(e, code);
  const before = (await query('SELECT id, email_verified, display_name FROM users WHERE email = $1', [e]))[0];
  if (!before) throw httpErr(404, 'Account not found');
  if (!before.email_verified) {
    await query('UPDATE users SET email_verified = true WHERE id = $1', [before.id]);
    sendMail({ to: e, ...welcomeEmail(before.display_name) }).catch(() => {});
  }
  const user = await getUserById(before.id);
  return { user, token: issueToken(user) };
}

// Returns { allowed, used, limit }. Resets the daily counter when the date rolls over.
export async function checkAndCountMessage(userId) {
  const rows = await query(
    `SELECT role, daily_message_limit, daily_messages_used, last_daily_reset FROM users WHERE id = $1`,
    [userId]
  );
  const u = rows[0];
  if (!u) return { allowed: true, used: 0, limit: 0 };

  // Reset if a new day.
  await query(
    `UPDATE users SET daily_messages_used = 0, last_daily_reset = CURRENT_DATE
     WHERE id = $1 AND last_daily_reset < CURRENT_DATE`,
    [userId]
  );
  const fresh = (await query(`SELECT daily_message_limit, daily_messages_used FROM users WHERE id = $1`, [userId]))[0];
  if (fresh.daily_messages_used >= fresh.daily_message_limit) {
    return { allowed: false, used: fresh.daily_messages_used, limit: fresh.daily_message_limit };
  }
  await query(`UPDATE users SET daily_messages_used = daily_messages_used + 1 WHERE id = $1`, [userId]);
  return { allowed: true, used: fresh.daily_messages_used + 1, limit: fresh.daily_message_limit };
}

function httpErr(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}
