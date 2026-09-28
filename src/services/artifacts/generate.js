// Artifact generation (added 2026-07-16).
// Turns AI-produced content into a REAL downloadable file — txt/md/csv/json/html/xml,
// Excel (.xlsx), Word (.docx), PDF (.pdf) — saved to disk + DB so the user gets a working
// download link (like ChatGPT/Claude "here's your file"). Also can PULL a file the agent
// already created inside the Kali sandbox/workspace and turn it into a download.
//
// Existing behaviour is untouched — this is a new, additive tool.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import PDFDocument from 'pdfkit';
import { runCommand } from '../exec/runner.js';

// This file lives in src/services/artifacts, so backend root is three levels up. Keeping the
// output OUTSIDE src/ matters: `npm run dev` uses `node --watch src/`, and writing generated files
// under src/ would restart the server on every download.
const backendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
export const ARTIFACT_DIR = path.resolve(backendRoot, process.env.ARTIFACT_DIR || 'artifacts');
fs.mkdirSync(ARTIFACT_DIR, { recursive: true });

// Extensions we write as-is (UTF-8 text). Everything Excel/Word/PDF is handled specially.
const TEXT_EXTS = new Set([
  'txt', 'md', 'markdown', 'log', 'conf', 'cfg', 'ini', 'csv', 'tsv', 'json',
  'xml', 'html', 'htm', 'yaml', 'yml', 'py', 'sh', 'bash', 'ps1', 'js', 'ts',
  'sql', 'php', 'rb', 'go', 'c', 'cpp', 'java', 'rs', 'env', 'lst', 'dic', 'rc',
]);

const MIME = {
  txt: 'text/plain', md: 'text/markdown', markdown: 'text/markdown', log: 'text/plain',
  csv: 'text/csv', tsv: 'text/tab-separated-values', json: 'application/json',
  xml: 'application/xml', html: 'text/html', htm: 'text/html', yaml: 'text/yaml', yml: 'text/yaml',
  py: 'text/x-python', sh: 'application/x-sh', js: 'text/javascript', sql: 'application/sql',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  pdf: 'application/pdf',
};

function sanitizeName(name) {
  const base = String(name || 'file').trim().replace(/[\\/]+/g, '_').replace(/[^\w.\-() ]+/g, '_').slice(0, 90);
  return base || 'file';
}
function extOf(name) {
  const m = /\.([A-Za-z0-9]{1,8})$/.exec(name || '');
  return m ? m[1].toLowerCase() : '';
}

// Parse the ```artifact block into a spec.
//   Line 1  = filename.ext   (format inferred from extension)
//   Lines 2+ = the file content
//   OR:  pull /workspace/out.txt [as results.txt]   -> export a sandbox file
export function parseArtifactSpec(body) {
  const lines = String(body || '').replace(/\r/g, '').split('\n');
  while (lines.length && !lines[0].trim()) lines.shift();
  const first = (lines[0] || '').trim();

  const pull = /^(?:pull|from|export)\s+(.+?)(?:\s+as\s+(.+?))?\s*$/i.exec(first);
  if (pull) {
    const srcPath = pull[1].trim().replace(/^["']|["']$/g, '');
    const asName = (pull[2] || '').trim().replace(/^["']|["']$/g, '');
    return { mode: 'pull', path: srcPath, name: sanitizeName(asName || path.posix.basename(srcPath)) };
  }

  // Treat line 1 as a filename only if it actually looks like one.
  if (/^[\w .()\-]{1,80}\.[A-Za-z0-9]{1,8}$/.test(first)) {
    return { mode: 'inline', name: sanitizeName(first), content: lines.slice(1).join('\n') };
  }
  return { mode: 'inline', name: 'cyphermind-output.txt', content: lines.join('\n') };
}

// ---- tabular parsing (for Excel) ----
// Accepts JSON (array of objects / array of arrays) or delimited text (TSV/CSV).
function toRows(content) {
  const text = String(content || '').trim();
  if (text.startsWith('[') || text.startsWith('{')) {
    try {
      const data = JSON.parse(text);
      const arr = Array.isArray(data) ? data : [data];
      if (arr.length && !Array.isArray(arr[0]) && typeof arr[0] === 'object') {
        const cols = [...new Set(arr.flatMap((o) => Object.keys(o)))];
        return [cols, ...arr.map((o) => cols.map((c) => o[c] ?? ''))];
      }
      if (arr.length && Array.isArray(arr[0])) return arr;
    } catch {
      /* not JSON — fall through to delimited parsing */
    }
  }
  const rows = text.split('\n').filter((l) => l.length);
  const delim = rows[0]?.includes('\t') ? '\t' : rows.some((r) => r.includes(',')) ? ',' : /\s{2,}|\s/;
  return rows.map((r) => (typeof delim === 'string' ? r.split(delim) : r.split(delim)).map((c) => c.trim()));
}

async function xlsxBuffer(content) {
  const ExcelJS = (await import('exceljs')).default;
  const wb = new ExcelJS.Workbook();
  wb.creator = 'CypherMind AI';
  const ws = wb.addWorksheet('Sheet1');
  const rows = toRows(content);
  rows.forEach((r) => ws.addRow(r));
  if (rows.length) {
    ws.getRow(1).font = { bold: true };
    ws.columns.forEach((col) => {
      let max = 10;
      col.eachCell?.({ includeEmpty: false }, (cell) => {
        max = Math.max(max, String(cell.value ?? '').length + 2);
      });
      col.width = Math.min(max, 60);
    });
  }
  return Buffer.from(await wb.xlsx.writeBuffer());
}

async function docxBuffer(content) {
  const { Document, Packer, Paragraph, HeadingLevel, TextRun } = await import('docx');
  const children = String(content || '').split('\n').map((line) => {
    if (/^#\s+/.test(line)) return new Paragraph({ text: line.replace(/^#\s+/, ''), heading: HeadingLevel.HEADING_1 });
    if (/^##\s+/.test(line)) return new Paragraph({ text: line.replace(/^##\s+/, ''), heading: HeadingLevel.HEADING_2 });
    if (/^###\s+/.test(line)) return new Paragraph({ text: line.replace(/^###\s+/, ''), heading: HeadingLevel.HEADING_3 });
    if (/^[-*]\s+/.test(line)) return new Paragraph({ text: line.replace(/^[-*]\s+/, ''), bullet: { level: 0 } });
    if (/^\d+\.\s+/.test(line)) return new Paragraph({ text: line.replace(/^\d+\.\s+/, ''), numbering: undefined });
    return new Paragraph({ children: [new TextRun(line)] });
  });
  const doc = new Document({ creator: 'CypherMind AI', sections: [{ children }] });
  return Packer.toBuffer(doc);
}

function pdfBuffer(content) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 54, size: 'A4', info: { Author: 'CypherMind AI' } });
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    for (const raw of String(content || '').split('\n')) {
      const line = raw.replace(/\t/g, '    ');
      if (/^#\s+/.test(line)) doc.font('Helvetica-Bold').fontSize(18).text(line.replace(/^#\s+/, ''));
      else if (/^##\s+/.test(line)) doc.font('Helvetica-Bold').fontSize(14).text(line.replace(/^##\s+/, ''));
      else if (/^###\s+/.test(line)) doc.font('Helvetica-Bold').fontSize(12).text(line.replace(/^###\s+/, ''));
      else if (/^[-*]\s+/.test(line)) doc.font('Helvetica').fontSize(11).text('•  ' + line.replace(/^[-*]\s+/, ''), { indent: 12 });
      else if (!line.trim()) doc.moveDown(0.5);
      else doc.font('Helvetica').fontSize(11).text(line);
    }
    doc.end();
  });
}

// Build a buffer for the given filename + content. Returns { buffer, name, ext, mime }.
export async function buildArtifactBuffer({ name, content }) {
  let finalName = sanitizeName(name);
  let ext = extOf(finalName);
  let buffer;

  if (ext === 'xlsx' || ext === 'xls') {
    buffer = await xlsxBuffer(content);
    if (ext === 'xls') { finalName = finalName.replace(/\.xls$/i, '.xlsx'); ext = 'xlsx'; }
  } else if (ext === 'docx' || ext === 'doc') {
    buffer = await docxBuffer(content);
    if (ext === 'doc') { finalName = finalName.replace(/\.doc$/i, '.docx'); ext = 'docx'; }
  } else if (ext === 'pdf') {
    buffer = await pdfBuffer(content);
  } else {
    if (!TEXT_EXTS.has(ext)) { finalName += '.txt'; ext = 'txt'; }
    buffer = Buffer.from(String(content ?? ''), 'utf8');
  }
  return { buffer, name: finalName, ext, mime: MIME[ext] || 'application/octet-stream' };
}

// Pull a file the agent created in the sandbox/workspace and return its bytes.
async function pullFromSandbox(srcPath, sessionId) {
  // base64 preserves binary; head -c cap keeps huge files from blowing up.
  const cmd = `if [ -f "${srcPath}" ]; then base64 "${srcPath}" | head -c 60000000; else echo __CM_NOFILE__; fi`;
  const r = await runCommand(cmd, { sessionId, timeoutMs: 60_000 });
  const out = (r.stdout || '').trim();
  if (!out || out.includes('__CM_NOFILE__')) {
    throw new Error(`file not found in sandbox: ${srcPath} (create it first, then pull it)`);
  }
  return Buffer.from(out.replace(/\s+/g, ''), 'base64');
}

// Full pipeline: spec -> file on disk. Returns { name, ext, mime, sizeBytes, storedPath }.
export async function generateArtifactFile(spec, { sessionId } = {}) {
  let name;
  let ext;
  let mime;
  let buffer;

  if (spec.mode === 'pull') {
    buffer = await pullFromSandbox(spec.path, sessionId);
    name = sanitizeName(spec.name);
    ext = extOf(name) || 'bin';
    mime = MIME[ext] || 'application/octet-stream';
  } else {
    const built = await buildArtifactBuffer({ name: spec.name, content: spec.content });
    ({ buffer, name, ext, mime } = built);
  }

  const stamp = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  const storedPath = path.join(ARTIFACT_DIR, `${stamp}_${name}`);
  fs.writeFileSync(storedPath, buffer);
  return { name, ext, mime, sizeBytes: buffer.length, storedPath };
}

export function humanSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
