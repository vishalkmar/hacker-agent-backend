import { DEFAULT_USER_ID } from '../db/index.js';
import { env } from '../config/env.js';
import { verifyToken } from '../services/auth/auth.js';

// Resolve the current user from a JWT (Authorization: Bearer <token>).
// - Valid token -> req.userId from the token.
// - No token + AUTH_REQUIRED=false (dev) -> fall back to the local user.
// - No/invalid token + AUTH_REQUIRED=true -> 401.
export function currentUser(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : null;

  if (token) {
    const payload = verifyToken(token);
    if (payload?.sub) {
      req.userId = payload.sub;
      req.userRole = payload.role;
      return next();
    }
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  if (env.auth.required) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  req.userId = DEFAULT_USER_ID;
  next();
}
