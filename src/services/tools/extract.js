import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execInContainer } from '../exec/docker.js';
import { ingestNdjson } from './index.js';

const backendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const SCRIPT = path.join(backendRoot, 'docker', 'extract-tool-docs.sh');

// Run the extractor inside the Kali container, then ingest the NDJSON it produced in batches.
// Returns { ingested } or { error }. Heavy — meant for the everything image.
export async function ingestFromContainer({ sessionId = 'tools', maxTools = 100000, onProgress } = {}) {
  let script;
  try {
    script = fs.readFileSync(SCRIPT, 'utf8');
  } catch (e) {
    return { error: 'extractor script missing: ' + e.message };
  }

  // 1. Run extraction (writes /workspace/tool-docs.ndjson). Allow a long timeout.
  onProgress?.({ phase: 'extracting' });
  const run = await execInContainer(
    sessionId,
    `cat > /tmp/_extract.sh <<'CMEOF'\n${script}\nCMEOF\nbash /tmp/_extract.sh ${maxTools}`,
    { timeoutMs: 45 * 60 * 1000 }
  );
  if (run.error) return { error: run.error };
  const wrote = /WROTE\s+(\d+)/.exec(run.stdout || '');
  const total = wrote ? Number(wrote[1]) : 0;
  if (!total) return { error: 'extractor produced no docs (stderr: ' + (run.stderr || '').slice(0, 300) + ')' };

  // 2. Read the NDJSON file in line-batches and ingest each (keeps output bounded).
  const BATCH = 40;
  let ingested = 0;
  for (let start = 1; start <= total; start += BATCH) {
    const end = Math.min(start + BATCH - 1, total);
    const slice = await execInContainer(sessionId, `sed -n '${start},${end}p' /workspace/tool-docs.ndjson`, {
      timeoutMs: 60_000,
    });
    if (slice.error) break;
    ingested += await ingestNdjson(slice.stdout || '');
    onProgress?.({ phase: 'ingesting', done: end, total, ingested });
  }
  return { ingested, total };
}
