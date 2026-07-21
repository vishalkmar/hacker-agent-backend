import { Router } from 'express';
import { query } from '../db/index.js';
import { LEGAL_VERSION, LEGAL_SECTIONS } from '../services/legal/content.js';
import { currentUser } from '../middleware/currentUser.js';
import { getUserById } from '../services/auth/auth.js';

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Public: the current legal docs + version (so the consent gate can render them).
export const legalRouter = Router();
legalRouter.get('/', (_req, res) => {
  res.json({ version: LEGAL_VERSION, sections: LEGAL_SECTIONS });
});

// Authed: record that the current user accepted the current legal version.
export const consentRouter = Router();
consentRouter.post(
  '/',
  currentUser,
  wrap(async (req, res) => {
    await query('UPDATE users SET consent_version = $1, consent_at = now() WHERE id = $2', [
      LEGAL_VERSION,
      req.userId,
    ]);
    const user = await getUserById(req.userId);
    res.json({ ok: true, version: LEGAL_VERSION, user });
  })
);
