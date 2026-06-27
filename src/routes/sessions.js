import { Router } from 'express';
import {
  listSessions,
  getSession,
  createSession,
  renameSession,
  deleteSession,
} from '../db/sessions.repo.js';
import { listMessages } from '../db/messages.repo.js';

export const sessionsRouter = Router();

// Wrap async handlers so rejected promises hit the error middleware.
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// GET /api/sessions -> list of the user's chats (newest first)
sessionsRouter.get(
  '/',
  wrap(async (req, res) => {
    res.json({ sessions: await listSessions(req.userId) });
  })
);

// POST /api/sessions -> create a new chat
sessionsRouter.post(
  '/',
  wrap(async (req, res) => {
    const title = (req.body?.title || 'New chat').toString().slice(0, 200);
    res.status(201).json({ session: await createSession(req.userId, title) });
  })
);

// GET /api/sessions/:id -> session + full message history
sessionsRouter.get(
  '/:id',
  wrap(async (req, res) => {
    const session = await getSession(req.userId, req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json({ session, messages: await listMessages(session.id) });
  })
);

// PATCH /api/sessions/:id -> rename
sessionsRouter.patch(
  '/:id',
  wrap(async (req, res) => {
    const session = await getSession(req.userId, req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    const title = (req.body?.title || '').toString().trim().slice(0, 200);
    if (!title) return res.status(400).json({ error: 'title is required' });
    res.json({ session: await renameSession(req.userId, session.id, title) });
  })
);

// DELETE /api/sessions/:id
sessionsRouter.delete(
  '/:id',
  wrap(async (req, res) => {
    const ok = await deleteSession(req.userId, req.params.id);
    if (!ok) return res.status(404).json({ error: 'Session not found' });
    res.json({ ok: true });
  })
);
