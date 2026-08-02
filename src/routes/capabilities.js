import { Router } from 'express';
import { getCapabilities } from '../services/capabilities/index.js';

// Phase D4 — GET /api/capabilities: what powers are live on this machine (host exec, Docker, Wi-Fi, BT, tools).
// Public (behind currentUser via /api mount); read-only probe of the local exec host.
export const capabilitiesRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

capabilitiesRouter.get('/', wrap(async (_req, res) => {
  res.json(await getCapabilities());
}));
