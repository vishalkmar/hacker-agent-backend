import { Router } from 'express';
import { getSession } from '../db/sessions.repo.js';
import { listFindings, findingStats } from '../db/findings.repo.js';
import { generateReport } from '../services/report/generate.js';
import { saveReport, getReport, listReports } from '../db/reports.repo.js';

// Nested under /api/sessions for generate/list.
export const reportsRouter = Router();
// Standalone /api/reports/:id for fetch/download.
export const reportItemRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// POST /api/sessions/:id/reports  -> generate + save a report
reportsRouter.post(
  '/:id/reports',
  wrap(async (req, res) => {
    const session = await getSession(req.userId, req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    const findings = await listFindings(session.id);
    const stats = await findingStats(session.id);
    const { markdown, html, title } = await generateReport(session, findings, stats);
    const id = await saveReport(session.id, req.userId, { title, markdown, html, stats });
    res.status(201).json({ report: { id, title }, stats });
  })
);

// GET /api/sessions/:id/reports -> list
reportsRouter.get(
  '/:id/reports',
  wrap(async (req, res) => {
    const session = await getSession(req.userId, req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json({ reports: await listReports(session.id) });
  })
);

// GET /api/reports/:id -> full report JSON
reportItemRouter.get(
  '/:id',
  wrap(async (req, res) => {
    const r = await getReport(req.userId, req.params.id);
    if (!r) return res.status(404).json({ error: 'Report not found' });
    res.json({ report: r });
  })
);

// GET /api/reports/:id/download?format=md|html -> file
reportItemRouter.get(
  '/:id/download',
  wrap(async (req, res) => {
    const r = await getReport(req.userId, req.params.id);
    if (!r) return res.status(404).json({ error: 'Report not found' });
    const fmt = (req.query.format || 'html').toString();
    const safe = (r.title || 'report').replace(/[^\w.-]+/g, '_');
    if (fmt === 'md') {
      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${safe}.md"`);
      return res.send(r.markdown || '');
    }
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `inline; filename="${safe}.html"`);
    res.send(r.html || '');
  })
);
