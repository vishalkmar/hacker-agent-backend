import { Router } from 'express';
import multer from 'multer';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeFile, classify } from '../services/files/analyze.js';
import { createFile, getFile } from '../db/files.repo.js';

const backendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const UPLOAD_DIR = path.resolve(backendRoot, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const safe = file.originalname.replace(/[^\w.\-]+/g, '_').slice(0, 80);
    cb(null, Date.now() + '_' + safe);
  },
});
const upload = multer({ storage, limits: { fileSize: 25 * 1024 * 1024 } }); // 25 MB

export const filesRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// POST /api/files/upload  (multipart: field "file", optional "sessionId")
filesRouter.post(
  '/upload',
  upload.single('file'),
  wrap(async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'file is required' });

    const { originalname, mimetype, size, path: filePath } = req.file;
    const analysis = await analyzeFile(filePath, originalname, mimetype);

    const file = await createFile({
      userId: req.userId,
      sessionId: req.body?.sessionId || null,
      name: originalname,
      kind: analysis.kind,
      mime: mimetype,
      sizeBytes: size,
      path: filePath,
      extracted: analysis.extracted,
      meta: analysis.meta,
    });

    res.status(201).json({ file });
  })
);

// GET /api/files/:id
filesRouter.get(
  '/:id',
  wrap(async (req, res) => {
    const file = await getFile(req.userId, req.params.id);
    if (!file) return res.status(404).json({ error: 'File not found' });
    res.json({ file });
  })
);

export { classify };
