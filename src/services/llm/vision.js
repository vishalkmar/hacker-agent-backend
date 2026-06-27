import fs from 'node:fs';
import path from 'node:path';
import { env } from '../../config/env.js';

const MIME = {
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
  '.webp': 'image/webp', '.bmp': 'image/bmp', '.tiff': 'image/tiff',
};

export function visionEnabled() {
  return !!(env.llm.visionModel && env.llm.visionBaseUrl && env.llm.visionApiKey);
}

// Ask a vision model to describe/understand an image. Returns the text, or null on failure.
export async function describeImage(filePath, mime = '', prompt) {
  if (!visionEnabled()) return null;
  try {
    const ext = path.extname(filePath).toLowerCase();
    const m = mime && mime.startsWith('image/') ? mime : MIME[ext] || 'image/png';
    const b64 = fs.readFileSync(filePath).toString('base64');
    const dataUrl = `data:${m};base64,${b64}`;

    const url = `${env.llm.visionBaseUrl.replace(/\/$/, '')}/chat/completions`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${env.llm.visionApiKey}` },
      body: JSON.stringify({
        model: env.llm.visionModel,
        max_tokens: 700,
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: prompt || 'Describe this image in detail. Transcribe any visible text, identify UI/screenshots, code, diagrams, network/security artifacts, and note anything actionable.' },
              { type: 'image_url', image_url: { url: dataUrl } },
            ],
          },
        ],
      }),
    });
    if (!res.ok) return null;
    const json = await res.json();
    return (json.choices?.[0]?.message?.content || '').trim() || null;
  } catch {
    return null;
  }
}
