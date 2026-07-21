import { getUserById } from '../services/auth/auth.js';

// Gate admin-only routes. Must run after currentUser (req.userId + req.tokenAdmin set).
// Accepts a DB admin JWT (adm:true) OR a user whose email is in ADMIN_EMAILS (legacy).
export async function requireAdmin(req, res, next) {
  try {
    if (req.tokenAdmin) { req.adminId = req.userId; return next(); }
    const user = await getUserById(req.userId);
    if (!user?.is_admin) return res.status(403).json({ error: 'Admin access required' });
    req.adminUser = user;
    next();
  } catch (e) {
    next(e);
  }
}
