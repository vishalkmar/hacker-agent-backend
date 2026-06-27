import { Router } from 'express';
import { getSession } from '../db/sessions.repo.js';
import { listFindings, findingStats, addFindings, updateFinding, deleteFinding } from '../db/findings.repo.js';

export const findingsRouter = Router();
// Separate router for /api/findings/:id (not nested under a session).
export const findingItemRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// GET /api/sessions/:id/findings
findingsRouter.get(
  '/:id/findings',
  wrap(async (req, res) => {
    const session = await getSession(req.userId, req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json({ findings: await listFindings(session.id), stats: await findingStats(session.id) });
  })
);

// POST /api/sessions/:id/findings  (manual finding)
findingsRouter.post(
  '/:id/findings',
  wrap(async (req, res) => {
    const session = await getSession(req.userId, req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    const f = req.body || {};
    if (!f.title) return res.status(400).json({ error: 'title is required' });
    const n = await addFindings(session.id, req.userId, [{ ...f, source: f.source || 'manual' }]);
    res.status(201).json({ added: n, stats: await findingStats(session.id) });
  })
);

// PATCH /api/findings/:id  (status, severity, remediation, cve, cvss_score, title)
findingItemRouter.patch(
  '/:id',
  wrap(async (req, res) => {
    const updated = await updateFinding(req.userId, req.params.id, req.body || {});
    if (!updated) return res.status(404).json({ error: 'Finding not found or no valid fields' });
    res.json({ finding: updated });
  })
);

// DELETE /api/findings/:id
findingItemRouter.delete(
  '/:id',
  wrap(async (req, res) => {
    const ok = await deleteFinding(req.userId, req.params.id);
    if (!ok) return res.status(404).json({ error: 'Finding not found' });
    res.json({ ok: true });
  })
);
