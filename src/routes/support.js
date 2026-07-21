import { Router } from 'express';
import { getThread, userUnseenCount } from '../db/support.repo.js';

// User-side support endpoints (mounted under currentUser).
export const supportRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

supportRouter.get('/thread', wrap(async (req, res) => {
  res.json({ messages: await getThread(req.userId) });
}));
supportRouter.get('/unseen', wrap(async (req, res) => {
  res.json({ unseen: await userUnseenCount(req.userId) });
}));
