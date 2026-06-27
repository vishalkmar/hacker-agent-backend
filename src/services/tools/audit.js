import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execInContainer, resolveBackend, dockerDaemonUp } from '../exec/docker.js';
import { env } from '../../config/env.js';

const backendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const SCRIPT = path.join(backendRoot, 'docker', 'audit-tools.sh');

// Audit which tools are available inside the active Kali container.
// Returns the parsed JSON report, plus context about the image/backend, or a clear error
// when Docker/the image isn't ready.
export async function auditTools({ sessionId = 'tools' } = {}) {
  const context = {
    configuredImage: env.exec.image,
    backend: env.exec.backend,
    isEverythingImage: /everything/i.test(env.exec.image),
  };

  const daemon = await dockerDaemonUp();
  if (!daemon) {
    return {
      ready: false,
      ...context,
      error: 'Docker daemon is not running. Start Docker Desktop, build the image, then retry.',
    };
  }

  let script;
  try {
    script = fs.readFileSync(SCRIPT, 'utf8');
  } catch (e) {
    return { ready: false, ...context, error: 'audit script missing: ' + e.message };
  }

  const run = await execInContainer(
    sessionId,
    `cat > /tmp/_audit.sh <<'CMEOF'\n${script}\nCMEOF\nbash /tmp/_audit.sh`,
    { timeoutMs: 120_000 }
  );
  if (run.error) return { ready: false, ...context, error: run.error };

  let report = null;
  try {
    const line = (run.stdout || '').trim().split('\n').filter(Boolean).pop();
    report = JSON.parse(line);
  } catch {
    return { ready: false, ...context, error: 'could not parse audit output', raw: (run.stdout || '').slice(0, 500) };
  }
  const activeBackend = await resolveBackend();
  return { ready: true, ...context, activeBackend, report };
}
