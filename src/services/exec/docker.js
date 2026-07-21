import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { env } from '../../config/env.js';

// Bind-mount the user's rockyou wordlist (backend/rockyou.txt) read-only into the sandbox at the Kali path,
// so crack commands referencing /usr/share/wordlists/rockyou.txt work with the real, uncompressed list.
function wordlistMount() {
  try {
    if (env.exec.wordlist && fs.existsSync(env.exec.wordlist)) {
      return ['-v', `${env.exec.wordlist}:${env.exec.wordlistMount}:ro`];
    }
  } catch { /* ignore */ }
  return [];
}

// Run a docker CLI command, capturing output. onChunk(stream, text) optional.
function docker(args, { timeoutMs = 0, onChunk } = {}) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn('docker', args, { windowsHide: true });
    } catch (e) {
      return resolve({ code: 127, stdout: '', stderr: e.message });
    }
    let stdout = '';
    let stderr = '';
    let timer = null;
    if (timeoutMs > 0) timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.stdout.on('data', (c) => {
      stdout += c.toString();
      onChunk?.('stdout', c.toString());
    });
    child.stderr.on('data', (c) => {
      stderr += c.toString();
      onChunk?.('stderr', c.toString());
    });
    child.on('error', (e) => {
      if (timer) clearTimeout(timer);
      resolve({ code: 127, stdout, stderr: stderr + e.message });
    });
    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      resolve({ code: code ?? 0, stdout, stderr });
    });
  });
}

// ---- daemon availability (cached briefly) ----
let _daemon = { up: false, at: 0 };
export async function dockerDaemonUp() {
  const now = Date.now();
  if (now - _daemon.at < 10_000) return _daemon.up;
  const r = await docker(['info', '--format', '{{.ServerVersion}}'], { timeoutMs: 6000 });
  _daemon = { up: r.code === 0 && r.stdout.trim().length > 0, at: now };
  return _daemon.up;
}

// Resolve which backend to actually use right now.
export async function resolveBackend() {
  if (env.exec.backend === 'host') return 'host';
  const up = await dockerDaemonUp();
  if (env.exec.backend === 'docker') return up ? 'docker' : 'host'; // fall back if forced but down
  return up ? 'docker' : 'host'; // auto
}

function safeName(sessionId) {
  return 'cyphermind_' + String(sessionId || 'default').replace(/[^a-zA-Z0-9_.-]/g, '').slice(0, 40);
}
function volName(sessionId) {
  return 'cmws_' + String(sessionId || 'default').replace(/[^a-zA-Z0-9_.-]/g, '').slice(0, 40);
}

async function imageExists() {
  const r = await docker(['image', 'inspect', env.exec.image], { timeoutMs: 8000 });
  return r.code === 0;
}

// Ensure a per-session container is running. Returns { ok, name, error }.
export async function ensureContainer(sessionId) {
  const name = safeName(sessionId);

  // already running?
  let r = await docker(['ps', '-q', '-f', `name=^${name}$`], { timeoutMs: 8000 });
  if (r.code === 0 && r.stdout.trim()) return { ok: true, name };

  // exists but stopped? start it
  r = await docker(['ps', '-aq', '-f', `name=^${name}$`], { timeoutMs: 8000 });
  if (r.code === 0 && r.stdout.trim()) {
    const s = await docker(['start', name], { timeoutMs: 15000 });
    return s.code === 0 ? { ok: true, name } : { ok: false, error: s.stderr };
  }

  // need image
  if (!(await imageExists())) {
    return {
      ok: false,
      error: `Image "${env.exec.image}" not found. Build it: cd backend/docker && docker build -t ${env.exec.image} -f Dockerfile.kali .`,
    };
  }

  // create + run
  // Pentest tools (nmap SYN scan, masscan, arp/ping, aircrack, hping...) need raw-socket and
  // net-admin capabilities, and many trip the default seccomp profile ("Operation not permitted").
  // This is the user's own isolated sandbox for authorized testing, so grant them. Toggle via
  // EXEC_NET_CAPS=false to run locked-down.
  const capArgs = env.exec.netCaps
    ? ['--cap-add', 'NET_RAW', '--cap-add', 'NET_ADMIN', '--security-opt', 'seccomp=unconfined']
    : [];
  // Wi-Fi passthrough: --privileged + host networking so a monitor-capable USB radio on the exec host is
  // visible to airmon-ng/airodump-ng inside the container. Only when EXEC_WIFI=true (Linux host + adapter).
  // In Wi-Fi mode use --privileged + host networking (radio visibility); otherwise the normal isolated network.
  const netArgs = env.exec.wifi ? ['--privileged', '--network', 'host'] : ['--network', env.exec.net];
  const run = await docker(
    [
      'run', '-d',
      '--name', name,
      '--memory', env.exec.mem,
      '--cpus', env.exec.cpus,
      ...netArgs,
      ...capArgs,
      '-v', `${volName(sessionId)}:/workspace`,
      ...wordlistMount(),
      '-w', '/workspace',
      env.exec.image,
      'sleep', 'infinity',
    ],
    { timeoutMs: 30000 }
  );
  return run.code === 0 ? { ok: true, name } : { ok: false, error: run.stderr || 'docker run failed' };
}

// Execute a command inside the session's container.
// Returns { stdout, stderr, exitCode } or { error } if the container couldn't be prepared.
export async function execInContainer(sessionId, command, { timeoutMs, onChunk } = {}) {
  const ensured = await ensureContainer(sessionId);
  if (!ensured.ok) return { error: ensured.error };
  const r = await docker(['exec', ensured.name, 'bash', '-lc', command], {
    timeoutMs: timeoutMs ?? env.exec.timeoutMs,
    onChunk,
  });
  return { stdout: r.stdout, stderr: r.stderr, exitCode: r.code };
}

export async function listContainers() {
  const r = await docker(['ps', '--format', '{{.Names}}\t{{.Status}}', '-f', 'name=cyphermind_'], {
    timeoutMs: 8000,
  });
  if (r.code !== 0) return [];
  return r.stdout
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const [name, ...status] = line.split('\t');
      return { name, status: status.join(' ') };
    });
}

export async function resetContainer(sessionId) {
  const name = safeName(sessionId);
  await docker(['rm', '-f', name], { timeoutMs: 15000 });
  return ensureContainer(sessionId);
}
