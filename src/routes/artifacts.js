import { Router } from 'express';
import fs from 'node:fs';
import { getArtifact, listArtifacts } from '../db/artifacts.repo.js';
import { getSession } from '../db/sessions.repo.js';

// Standalone /api/artifacts/:id (download/meta).
export const artifactItemRouter = Router();
// Nested under /api/sessions for listing.
export const artifactsRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// GET /api/sessions/:id/artifacts -> list this session's generated files
artifactsRouter.get(
  '/:id/artifacts',
  wrap(async (req, res) => {
    const session = await getSession(req.userId, req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json({ artifacts: await listArtifacts(session.id) });
  })
);

// GET /api/artifacts/:id -> metadata
artifactItemRouter.get(
  '/:id',
  wrap(async (req, res) => {
    const a = await getArtifact(req.userId, req.params.id);
    if (!a) return res.status(404).json({ error: 'Artifact not found' });
    const { path, ...meta } = a;
    res.json({ artifact: meta });
  })
);

// GET /api/artifacts/:id/download -> the actual file (attachment)
artifactItemRouter.get(
  '/:id/download',
  wrap(async (req, res) => {
    const a = await getArtifact(req.userId, req.params.id);
    if (!a) return res.status(404).json({ error: 'Artifact not found' });
    if (!a.path || !fs.existsSync(a.path)) {
      return res.status(410).json({ error: 'File is no longer available on the server' });
    }
    const safe = (a.name || 'download').replace(/[^\w.\-() ]+/g, '_');
    res.setHeader('Content-Type', a.mime || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${safe}"`);
    res.setHeader('Content-Length', a.size_bytes || fs.statSync(a.path).size);
    fs.createReadStream(a.path).pipe(res);
  })
);
