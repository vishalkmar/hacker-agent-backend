import { Router } from 'express';
import { generatePayload } from '../services/payloads/templates.js';
import { savePayload, listPayloads, deletePayload } from '../db/payloads.repo.js';

export const payloadsRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// POST /api/payloads/generate
payloadsRouter.post(
  '/generate',
  wrap(async (req, res) => {
    res.json({ payload: generatePayload(req.body || {}) });
  })
);

// GET /api/payloads  (saved library)
payloadsRouter.get(
  '/',
  wrap(async (req, res) => {
    res.json({ payloads: await listPayloads(req.userId) });
  })
);

// POST /api/payloads  (save one)
payloadsRouter.post(
  '/',
  wrap(async (req, res) => {
    const b = req.body || {};
    if (!b.name || !b.code) return res.status(400).json({ error: 'name and code are required' });
    const id = await savePayload(req.userId, b);
    res.status(201).json({ id });
  })
);

// DELETE /api/payloads/:id
payloadsRouter.delete(
  '/:id',
  wrap(async (req, res) => {
    const ok = await deletePayload(req.userId, req.params.id);
    if (!ok) return res.status(404).json({ error: 'Payload not found' });
    res.json({ ok: true });
  })
);
