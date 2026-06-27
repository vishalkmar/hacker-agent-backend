import { getUserById } from '../services/auth/auth.js';

// Gate admin-only routes. Must run after currentUser (req.userId set).
export async function requireAdmin(req, res, next) {
  try {
    const user = await getUserById(req.userId);
    if (!user?.is_admin) return res.status(403).json({ error: 'Admin access required' });
    req.adminUser = user;
    next();
  } catch (e) {
    next(e);
  }
}
