import fs from 'node:fs';
import path from 'node:path';
import { scanSecrets } from './secrets.js';
import { describeImage, visionEnabled } from '../llm/vision.js';

const MAX_TEXT = 12000;

const CODE_EXT = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.py', '.rb', '.php', '.go', '.rs', '.java', '.c', '.h',
  '.cpp', '.cs', '.sh', '.ps1', '.pl', '.lua', '.sql', '.html', '.css', '.json', '.yaml',
  '.yml', '.xml', '.ini', '.env', '.conf', '.toml',
]);
const TEXT_EXT = new Set(['.txt', '.md', '.log', '.csv']);

export function classify(name, mime = '') {
  const ext = path.extname(name).toLowerCase();
  if (mime.startsWith('image/') || ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff'].includes(ext))
    return 'image';
  if (mime === 'application/pdf' || ext === '.pdf') return 'pdf';
  if (CODE_EXT.has(ext)) return 'code';
  if (TEXT_EXT.has(ext)) return 'text';
  return 'other';
}

async function analyzePdf(filePath) {
  // pdf-parse v2 — class-based API.
  const { PDFParse } = await import('pdf-parse');
  const buf = fs.readFileSync(filePath);
  const parser = new PDFParse({ data: new Uint8Array(buf) });
  try {
    const data = await parser.getText();
    const text = (data.text || '').trim().slice(0, MAX_TEXT);
    return { extracted: text, meta: { pages: data.total, secrets: scanSecrets(text) } };
  } finally {
    await parser.destroy().catch(() => {});
  }
}

function analyzeCodeOrText(filePath, kind) {
  const raw = fs.readFileSync(filePath, 'utf8');
  const text = raw.slice(0, MAX_TEXT);
  const secrets = kind === 'code' || kind === 'text' ? scanSecrets(raw) : [];
  return {
    extracted: text,
    meta: { lines: raw.split('\n').length, truncated: raw.length > MAX_TEXT, secrets },
  };
}

async function analyzeImage(filePath, mime) {
  // Phase 11: prefer true vision understanding (a multimodal model), and also run OCR for
  // exact text. Both degrade gracefully so an image always yields *some* usable context.
  let vision = null;
  if (visionEnabled()) vision = await describeImage(filePath, mime).catch(() => null);

  let ocrText = '';
  let ocrMeta = { ocr: false };
  try {
    const { createWorker } = await import('tesseract.js');
    const worker = await createWorker('eng');
    const { data } = await worker.recognize(filePath);
    await worker.terminate();
    ocrText = (data.text || '').trim().slice(0, MAX_TEXT);
    ocrMeta = { ocr: true, confidence: data.confidence };
  } catch (e) {
    ocrMeta = { ocr: false, error: e.message };
  }

  const parts = [];
  if (vision) parts.push('AI description:\n' + vision);
  if (ocrText) parts.push('OCR text:\n' + ocrText);
  const extracted = parts.join('\n\n').slice(0, MAX_TEXT) || '(no content detected in image)';
  return {
    extracted,
    meta: { ...ocrMeta, vision: !!vision, secrets: scanSecrets(`${vision || ''}\n${ocrText}`) },
  };
}

// Analyze an uploaded file by kind. Returns { kind, extracted, meta }.
export async function analyzeFile(filePath, name, mime = '') {
  const kind = classify(name, mime);
  let result;
  switch (kind) {
    case 'pdf':
      result = await analyzePdf(filePath);
      break;
    case 'image':
      result = await analyzeImage(filePath, mime);
      break;
    case 'code':
    case 'text':
      result = analyzeCodeOrText(filePath, kind);
      break;
    default:
      result = { extracted: '(binary/unsupported file — stored but not parsed)', meta: {} };
  }
  return { kind, ...result };
}

// Build the text block injected into the LLM context for an attached file.
export function renderFileContext(file) {
  const lines = [`[Attached ${file.kind} file: ${file.name}]`];
  const meta = file.meta || {};
  if (meta.secrets?.length) {
    lines.push(
      'Potential secrets found: ' + meta.secrets.map((s) => `${s.type} (${s.preview})`).join('; ')
    );
  }
  if (meta.pages) lines.push(`Pages: ${meta.pages}`);
  if (meta.ocr === false) lines.push('(image text could not be extracted)');
  lines.push('Content:\n' + (file.extracted || '(empty)'));
  return lines.join('\n');
}
