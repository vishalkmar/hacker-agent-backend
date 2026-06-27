import { Router } from 'express';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { retrieveTools, getTool, toolStats, seedSampleTools, ingestNdjson } from '../services/tools/index.js';
import { ingestFromContainer } from '../services/tools/extract.js';
import { listToolCapabilities, runSelfTest } from '../services/tools/selftest.js';
import { auditTools } from '../services/tools/audit.js';

export const toolsRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ----- read (any logged-in user) -----
toolsRouter.get('/search', wrap(async (req, res) => {
  const tools = await retrieveTools(String(req.query.q || ''), Number(req.query.k) || 6);
  res.json({ tools });
}));
toolsRouter.get('/stats', wrap(async (_req, res) => res.json(await toolStats())));

// Audit which tools are actually installed in the active container (everything check).
toolsRouter.get('/audit', wrap(async (req, res) => res.json(await auditTools({ sessionId: req.query.sessionId || 'tools' }))));
toolsRouter.get('/capabilities', wrap(async (req, res) =>
  res.json({ capabilities: await listToolCapabilities(String(req.query.status || '')) })));
toolsRouter.get('/:name', wrap(async (req, res) => {
  const tool = await getTool(req.params.name);
  if (!tool) return res.status(404).json({ error: 'Tool not found' });
  res.json({ tool });
}));

// ----- admin: build the index + run self-tests -----
toolsRouter.post('/seed', requireAdmin, wrap(async (_req, res) => res.json({ ingested: await seedSampleTools() })));

toolsRouter.post('/ingest', requireAdmin, wrap(async (req, res) => {
  const ndjson = typeof req.body === 'string' ? req.body : (req.body?.ndjson || '');
  res.json({ ingested: await ingestNdjson(ndjson) });
}));

// Extract real docs from the Kali container, then index them (heavy).
toolsRouter.post('/reindex', requireAdmin, wrap(async (req, res) => {
  const r = await ingestFromContainer({
    sessionId: req.body?.sessionId || 'tools',
    maxTools: Number(req.body?.maxTools) || 100000,
  });
  if (r.error) return res.status(503).json(r);
  res.json(r);
}));

// Autonomous self-test sweep (scope: all | category:<x> | tool:<name>).
toolsRouter.post('/selftest', requireAdmin, wrap(async (req, res) => {
  const r = await runSelfTest({
    scope: req.body?.scope || 'all',
    sessionId: req.body?.sessionId || 'tools',
    limit: Number(req.body?.limit) || 25,
  });
  res.json(r);
}));
