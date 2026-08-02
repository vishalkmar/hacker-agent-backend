import { Router } from 'express';
import { startJob, readJob, writeJob, stopJob, listJobs } from '../services/exec/jobs.js';
import { manageJob } from '../services/exec/manage.js';

// Live background-jobs API — powers the Sessions/Terminal panel: list running listeners/shells, stream their
// output incrementally, send input, and stop them. Also lets the user open their OWN terminal (start a job).
export const jobsRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// GET /api/jobs?sessionId= -> list this user's background jobs
jobsRouter.get('/', (req, res) => {
  res.json({ jobs: listJobs({ userId: req.userId, sessionId: req.query.sessionId || undefined }) });
});

// POST /api/jobs { command, sessionId?, label? } -> start a long-lived job (a manual terminal / listener)
jobsRouter.post('/', wrap(async (req, res) => {
  const command = (req.body?.command || '').toString();
  if (!command.trim()) return res.status(400).json({ error: 'command is required' });
  const job = await startJob({ command, sessionId: req.body?.sessionId || null, userId: req.userId, label: req.body?.label });
  res.status(201).json({ job });
}));

// GET /api/jobs/:id?offset=N -> incremental output since offset
jobsRouter.get('/:id', (req, res) => {
  const r = readJob(req.params.id, req.query.offset);
  if (r.error) return res.status(404).json(r);
  res.json(r);
});

// POST /api/jobs/:id/input { input } -> type into the job's stdin
jobsRouter.post('/:id/input', (req, res) => {
  const r = writeJob(req.params.id, (req.body?.input ?? '').toString());
  if (r.error) return res.status(400).json(r);
  res.json(r);
});

// POST /api/jobs/:id/stop -> kill the job
jobsRouter.post('/:id/stop', (req, res) => {
  const r = stopJob(req.params.id);
  if (r.error) return res.status(404).json(r);
  res.json(r);
});

// POST /api/jobs/:id/manage { prompt } -> AI operates this live session from a natural-language request
// (summarise captures / run a sibling command / type into the console). Powers the management prompt box.
jobsRouter.post('/:id/manage', wrap(async (req, res) => {
  const prompt = (req.body?.prompt ?? '').toString();
  if (!prompt.trim()) return res.status(400).json({ error: 'prompt is required' });
  const r = await manageJob({ id: req.params.id, prompt, userId: req.userId });
  if (r.error) return res.status(r.error === 'job not found' ? 404 : 400).json(r);
  res.json(r);
}));
