import { DEFAULT_USER_ID } from '../db/index.js';
import { env } from '../config/env.js';
import { verifyToken } from '../services/auth/auth.js';

// Resolve the current user from a JWT (Authorization: Bearer <token>).
// - Valid token -> req.userId from the token.
// - No token + AUTH_REQUIRED=false (dev) -> fall back to the local user.
// - No/invalid token + AUTH_REQUIRED=true -> 401.
//
// Phase D3 (desktop): the embedded local backend may receive a JWT minted by the WEB backend. If it shares
// the web's JWT_SECRET (backend/.env is the same), verifyToken succeeds locally — the fast path. If it does
// NOT (secret intentionally not shipped in the app), it validates the token against `${WEB_API_URL}/api/auth/me`
// instead, so no secret ever leaves the server. Validated tokens are cached briefly to avoid a web call per request.

const webCache = new Map(); // token -> { userId, role, adm, exp }
const WEB_CACHE_TTL = 5 * 60 * 1000;

async function validateViaWeb(token) {
  if (!env.webApiUrl) return null;
  const hit = webCache.get(token);
  if (hit && hit.exp > Date.now()) return hit;
  try {
    const res = await fetch(`${env.webApiUrl}/api/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return null;
    const { user } = await res.json();
    if (!user?.id) return null;
    const entry = { userId: user.id, role: user.role, adm: user.is_admin === true, exp: Date.now() + WEB_CACHE_TTL };
    webCache.set(token, entry);
    return entry;
  } catch {
    return null; // web unreachable — fall through to 401
  }
}

export async function currentUser(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : null;

  if (token) {
    // Fast path: verify locally (shared JWT_SECRET).
    const payload = verifyToken(token);
    if (payload?.sub) {
      req.userId = payload.sub;
      req.userRole = payload.role;
      req.tokenAdmin = payload.adm === true; // admin JWT (Phase 2B)
      return next();
    }
    // Desktop trust bridge: can't verify locally → ask the web API to vouch for it.
    const web = await validateViaWeb(token);
    if (web) {
      req.userId = web.userId;
      req.userRole = web.role;
      req.tokenAdmin = web.adm;
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
