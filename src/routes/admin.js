import { Router } from 'express';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { adminMetrics, adminListUsers, adminGetUser, adminListTransactions } from '../db/admin.repo.js';
import {
  listPlans, getPlan, upsertPlan, deletePlan, activateSubscription,
} from '../db/billing.repo.js';
import { query } from '../db/index.js';

export const adminRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

adminRouter.use(requireAdmin);

adminRouter.get('/metrics', wrap(async (_req, res) => res.json(await adminMetrics())));

adminRouter.get('/users', wrap(async (req, res) => {
  const { q = '', limit, offset } = req.query;
  res.json(await adminListUsers({ q: String(q), limit: Number(limit) || 50, offset: Number(offset) || 0 }));
}));

adminRouter.get('/users/:id', wrap(async (req, res) => {
  const data = await adminGetUser(req.params.id);
  if (!data) return res.status(404).json({ error: 'User not found' });
  res.json(data);
}));

// Change a user's plan (admin grant) or verify them.
adminRouter.patch('/users/:id', wrap(async (req, res) => {
  const { planCode, email_verified } = req.body || {};
  if (planCode) {
    const plan = await getPlan(String(planCode).toLowerCase());
    if (!plan) return res.status(404).json({ error: 'Plan not found' });
    await activateSubscription(req.params.id, plan);
  }
  if (email_verified !== undefined) {
    await query('UPDATE users SET email_verified = $1 WHERE id = $2', [!!email_verified, req.params.id]);
  }
  res.json(await adminGetUser(req.params.id));
}));

adminRouter.get('/transactions', wrap(async (req, res) => {
  res.json({ transactions: await adminListTransactions({ status: String(req.query.status || ''), limit: Number(req.query.limit) || 100 }) });
}));

// Plan management (full list incl. inactive).
adminRouter.get('/plans', wrap(async (_req, res) => res.json({ plans: await listPlans({ activeOnly: false }) })));
adminRouter.post('/plans', wrap(async (req, res) => res.json({ plan: await upsertPlan(req.body || {}) })));
adminRouter.patch('/plans/:code', wrap(async (req, res) =>
  res.json({ plan: await upsertPlan({ ...(req.body || {}), code: req.params.code }) })));
adminRouter.delete('/plans/:code', wrap(async (req, res) =>
  res.json({ deleted: await deletePlan(req.params.code) })));
