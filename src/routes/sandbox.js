import { Router } from 'express';
import { env } from '../config/env.js';
import { dockerDaemonUp, resolveBackend, listContainers, resetContainer } from '../services/exec/docker.js';

export const sandboxRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// GET /api/sandbox/status
sandboxRouter.get(
  '/status',
  wrap(async (_req, res) => {
    const dockerUp = await dockerDaemonUp();
    const backend = await resolveBackend();
    res.json({
      configuredBackend: env.exec.backend,
      activeBackend: backend,
      dockerUp,
      image: env.exec.image,
      net: env.exec.net,
      containers: dockerUp ? await listContainers() : [],
      hint: dockerUp
        ? undefined
        : 'Docker daemon not reachable — start Docker Desktop. Running on host shell meanwhile.',
    });
  })
);

// POST /api/sandbox/reset { sessionId }
sandboxRouter.post(
  '/reset',
  wrap(async (req, res) => {
    const sessionId = req.body?.sessionId || null;
    const r = await resetContainer(sessionId);
    res.json({ ok: r.ok, name: r.name, error: r.error });
  })
);
