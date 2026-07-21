import { Router } from 'express';
import multer from 'multer';
import { env } from '../config/env.js';

// Optional server-side speech-to-text. The chat mic uses the browser Web Speech API by default; this route is
// the fallback (and true auto language-detection) via any OpenAI-compatible /audio/transcriptions endpoint —
// e.g. Groq's free Whisper. Enabled only when STT_BASE_URL + STT_API_KEY are set.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024 } });

export const voiceRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

export function sttEnabled() {
  return !!(env.llm.sttBaseUrl && env.llm.sttApiKey);
}

// POST /api/voice/transcribe  (multipart: field "audio"; optional "language" hint, else auto-detected)
voiceRouter.post(
  '/transcribe',
  upload.single('audio'),
  wrap(async (req, res) => {
    if (!sttEnabled()) {
      return res.status(501).json({ error: 'Server-side transcription is not configured. The browser mic (Web Speech API) works without it; to enable this fallback set STT_BASE_URL and STT_API_KEY.' });
    }
    if (!req.file) return res.status(400).json({ error: 'audio file is required' });

    const form = new FormData();
    const blob = new Blob([req.file.buffer], { type: req.file.mimetype || 'audio/webm' });
    form.append('file', blob, req.file.originalname || 'audio.webm');
    form.append('model', env.llm.sttModel);
    form.append('response_format', 'verbose_json'); // includes detected "language"
    if (req.body?.language && req.body.language !== 'auto') form.append('language', String(req.body.language));

    const url = `${env.llm.sttBaseUrl.replace(/\/$/, '')}/audio/transcriptions`;
    const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${env.llm.sttApiKey}` }, body: form });
    if (!r.ok) {
      const detail = await r.text().catch(() => '');
      return res.status(502).json({ error: 'Transcription provider error', detail: detail.slice(0, 300) });
    }
    const json = await r.json();
    res.json({ text: (json.text || '').trim(), language: json.language || null });
  })
);
