import { Router } from 'express';
import { recallMemories } from '../db/memory.repo.js';
import { isMemoryReady } from '../db/index.js';
import { env } from '../config/env.js';

export const memoryRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// GET /api/memory/info
memoryRouter.get('/info', (_req, res) => {
  res.json({ ready: isMemoryReady(), provider: env.embed.provider, model: env.embed.model, dim: env.embed.dim });
});

// POST /api/memory/search { query }
memoryRouter.post(
  '/search',
  wrap(async (req, res) => {
    const query = (req.body?.query || '').toString();
    if (!query.trim()) return res.status(400).json({ error: 'query is required' });
    const results = await recallMemories(req.userId, query, { topK: env.embed.topK });
    res.json({ results });
  })
);
