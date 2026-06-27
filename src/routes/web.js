import { Router } from 'express';
import { webSearch } from '../services/web/search.js';
import { fetchUrl } from '../services/web/fetch.js';
import { reconUrl } from '../services/web/recon.js';

export const webRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// POST /api/web/search { query }
webRouter.post(
  '/search',
  wrap(async (req, res) => {
    const query = (req.body?.query || '').toString();
    if (!query.trim()) return res.status(400).json({ error: 'query is required' });
    res.json(await webSearch(query, { max: req.body?.max || 8 }));
  })
);

// POST /api/web/fetch { url }
webRouter.post(
  '/fetch',
  wrap(async (req, res) => {
    const url = (req.body?.url || '').toString();
    if (!url.trim()) return res.status(400).json({ error: 'url is required' });
    res.json({ page: await fetchUrl(url) });
  })
);

// POST /api/web/recon { url }
webRouter.post(
  '/recon',
  wrap(async (req, res) => {
    const url = (req.body?.url || '').toString();
    if (!url.trim()) return res.status(400).json({ error: 'url is required' });
    res.json(await reconUrl(url));
  })
);
