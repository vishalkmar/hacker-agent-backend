import { Router } from 'express';
import { register, login, getUserById, startOtp, verifyOtpLogin, updateProfile } from '../services/auth/auth.js';
import { issueOtp } from '../services/auth/otp.js';
import { currentUser } from '../middleware/currentUser.js';

export const authRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ----- Phase 12: passwordless email-OTP -----

// POST /auth/start { email, name? } -> sends OTP, returns { mode: 'register'|'login' }
authRouter.post(
  '/start',
  wrap(async (req, res) => {
    const r = await startOtp(req.body || {});
    res.json(r);
  })
);

// POST /auth/verify-otp { email, code } -> { user, token }
authRouter.post(
  '/verify-otp',
  wrap(async (req, res) => {
    const { email, code } = req.body || {};
    const r = await verifyOtpLogin({ email, code });
    res.json(r);
  })
);

// POST /auth/resend-otp { email }
authRouter.post(
  '/resend-otp',
  wrap(async (req, res) => {
    const r = await issueOtp((req.body || {}).email, 'auth');
    res.json(r);
  })
);

// POST /api/auth/register { email, password, name }
authRouter.post(
  '/register',
  wrap(async (req, res) => {
    const { user, token } = await register(req.body || {});
    res.status(201).json({ user, token });
  })
);

// POST /api/auth/login { email, password }
authRouter.post(
  '/login',
  wrap(async (req, res) => {
    const { user, token } = await login(req.body || {});
    res.json({ user, token });
  })
);

// GET /api/auth/me  (resolves the user from the token)
authRouter.get(
  '/me',
  currentUser,
  wrap(async (req, res) => {
    const user = await getUserById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  })
);

// PATCH /api/auth/me  { display_name }
authRouter.patch(
  '/me',
  currentUser,
  wrap(async (req, res) => {
    const user = await updateProfile(req.userId, req.body || {});
    res.json({ user });
  })
);
