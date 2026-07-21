import { Router } from 'express';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { adminMetrics, adminAnalytics, adminListUsers, adminGetUser, adminListTransactions } from '../db/admin.repo.js';
import {
  listPlans, getPlan, upsertPlan, deletePlan, activateSubscription,
} from '../db/billing.repo.js';
import { query } from '../db/index.js';

export const adminRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

adminRouter.use(requireAdmin);

// Confirm the caller is an authenticated admin (used by the admin app to gate the shell).
adminRouter.get('/me', wrap(async (req, res) => {
  const { getAdminById } = await import('../services/auth/auth.js');
  const admin = req.adminId ? await getAdminById(req.adminId) : { username: req.adminUser?.email };
  res.json({ ok: true, admin: admin || { username: 'admin' } });
}));

adminRouter.get('/metrics', wrap(async (_req, res) => res.json(await adminMetrics())));

// Rich analytics for the dashboard (users + revenue counts, series, comparisons) over a range.
adminRouter.get('/analytics', wrap(async (req, res) => {
  res.json(await adminAnalytics({ from: req.query.from, to: req.query.to }));
}));

adminRouter.get('/users', wrap(async (req, res) => {
  const { q = '', plan = '', limit, offset } = req.query;
  res.json(await adminListUsers({ q: String(q), plan: String(plan), limit: Number(limit) || 50, offset: Number(offset) || 0 }));
}));

adminRouter.get('/users/:id', wrap(async (req, res) => {
  const data = await adminGetUser(req.params.id);
  if (!data) return res.status(404).json({ error: 'User not found' });
  res.json(data);
}));

// Change a user's plan (admin grant, no payment; optional custom validity `days`) or verify them.
adminRouter.patch('/users/:id', wrap(async (req, res) => {
  const { planCode, email_verified, days } = req.body || {};
  if (planCode) {
    const plan = await getPlan(String(planCode).toLowerCase());
    if (!plan) return res.status(404).json({ error: 'Plan not found' });
    await activateSubscription(req.params.id, plan, { days: Number(days) || 0 });
  }
  if (email_verified !== undefined) {
    await query('UPDATE users SET email_verified = $1 WHERE id = $2', [!!email_verified, req.params.id]);
  }
  res.json(await adminGetUser(req.params.id));
}));

adminRouter.delete('/users/:id', wrap(async (req, res) => {
  const { query } = await import('../db/index.js');
  await query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.json({ deleted: true });
}));

adminRouter.get('/transactions', wrap(async (req, res) => {
  const r = await adminListTransactions({
    status: String(req.query.status || ''), q: String(req.query.q || ''),
    from: String(req.query.from || ''), to: String(req.query.to || ''),
    limit: Number(req.query.limit) || 50, offset: Number(req.query.offset) || 0,
  });
  res.json(r); // { transactions, total }
}));

// Support chat (admin side): conversation list + a user's thread.
adminRouter.get('/support/conversations', wrap(async (_req, res) => {
  const { listConversations } = await import('../db/support.repo.js');
  res.json({ conversations: await listConversations() });
}));
adminRouter.get('/support/thread/:userId', wrap(async (req, res) => {
  const { getThread } = await import('../db/support.repo.js');
  res.json({ messages: await getThread(req.params.userId) });
}));

// Plan management (full list incl. inactive).
adminRouter.get('/plans', wrap(async (_req, res) => res.json({ plans: await listPlans({ activeOnly: false }) })));
adminRouter.post('/plans', wrap(async (req, res) => res.json({ plan: await upsertPlan(req.body || {}) })));
adminRouter.patch('/plans/:code', wrap(async (req, res) =>
  res.json({ plan: await upsertPlan({ ...(req.body || {}), code: req.params.code }) })));
adminRouter.delete('/plans/:code', wrap(async (req, res) =>
  res.json({ deleted: await deletePlan(req.params.code) })));
