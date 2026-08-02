// Background job manager — runs LONG-LIVED processes (Metasploit multi/handler, netcat listeners,
// msfconsole, live captures) that must stay alive across HTTP requests, and streams their output. This is the
// "sessions stay alive / multiple shells" core. Backend-aware so it is stable in BOTH modes:
//   • host/desktop  → spawns a native shell child (persistent, interactive stdin)
//   • docker (web)  → spawns `docker exec -i <session-container>` (persistent while the container lives)
//   • ssh           → spawns `ssh … bash -lc` (persistent while the tunnel lives)
// Processes live as long as the backend server runs; on desktop that's the user's own machine (true
// persistence). Output is ring-buffered per job and read incrementally by offset (poll or SSE).

import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { env } from '../../config/env.js';
import { resolveBackend, ensureContainer } from './docker.js';

const MAX_BUF = 512 * 1024;      // per-job output ring buffer (bytes)
const MAX_JOBS = 40;             // safety cap on concurrent tracked jobs
const REAP_AFTER_MS = 30 * 60_000; // drop finished jobs from the registry after 30 min

// Kinds that constitute a "Live Hack Environment": a persistent, callback/capture-driven session the
// user manages live (auto-open panel + AI-driven management prompt box). Plain shells/terminals aren't.
export const LIVE_KINDS = new Set(['hound', 'camphish', 'msf', 'set']);
// Of those, the ones you TYPE into (a live interactive stdin console) vs. capture servers you INSPECT
// with sibling commands. Used by the manager to pick SEND (stdin) vs RUN (sibling command).
export const INTERACTIVE_KINDS = new Set(['msf', 'shell', 'terminal']);

/** @type {Map<string, any>} */
const jobs = new Map();

function shellSpawn(command) {
  const shell = env.exec.shell;
  if (shell === 'powershell') return { file: 'powershell.exe', args: ['-NoProfile', '-Command', command] };
  if (shell === 'pwsh') return { file: 'pwsh', args: ['-NoProfile', '-Command', command] };
  if (shell === 'cmd') return { file: 'cmd.exe', args: ['/d', '/s', '/c', command] };
  if (shell === 'sh') return { file: 'sh', args: ['-c', command] };
  return { file: 'bash', args: ['-lc', command] };
}

// Resolve how to spawn a persistent process for the active exec backend.
async function resolveSpawn(command, sessionId) {
  if (env.exec.backend === 'ssh' && env.exec.ssh.host) {
    const { host, user, port, key } = env.exec.ssh;
    const args = ['-tt', '-o', 'StrictHostKeyChecking=no', '-p', String(port || 22)];
    if (key) args.push('-i', key);
    args.push(`${user}@${host}`, command);
    return { file: 'ssh', args, backend: `ssh:${user}@${host}` };
  }
  const backend = await resolveBackend();
  if (backend === 'docker') {
    const ensured = await ensureContainer(sessionId);
    if (ensured.ok) return { file: 'docker', args: ['exec', '-i', ensured.name, 'bash', '-lc', command], backend: `docker:${ensured.name}` };
    // fall through to host if the sandbox couldn't be prepared
  }
  const { file, args } = shellSpawn(command);
  return { file, args, backend: `host:${env.exec.shell}` };
}

function append(job, text) {
  job.output += text;
  const over = job.output.length - MAX_BUF;
  if (over > 0) { job.output = job.output.slice(over); job.dropped += over; }
  job.lastAt = Date.now();
}

// Start a long-lived background job. Returns a summary { id, label, status, backend, startedAt }.
//   kind: 'shell'|'terminal'|'hound'|'camphish'|'msf'|'set' — drives the Live Hack Environment UX.
//   meta: freeform tags for the environment (e.g. { link } for a tracker's public URL).
export async function startJob({ command, sessionId = null, userId = null, label, kind = 'shell', meta = {}, live, interactive } = {}) {
  const cmd = String(command || '').trim();
  if (!cmd) throw new Error('command is required');
  if ([...jobs.values()].filter((j) => j.status === 'running').length >= MAX_JOBS) {
    throw new Error(`too many running jobs (max ${MAX_JOBS}) — stop some first`);
  }
  const id = randomUUID().slice(0, 8);
  const { file, args, backend } = await resolveSpawn(cmd, sessionId);
  const job = {
    id, label: label || cmd.slice(0, 60), command: cmd, sessionId, userId, backend,
    kind, meta: { ...meta },
    live: live ?? LIVE_KINDS.has(kind),                 // caller can force a generic live command on
    interactive: interactive ?? INTERACTIVE_KINDS.has(kind), // you type INTO it (stdin) vs. inspect it
    status: 'running', exitCode: null, startedAt: Date.now(), lastAt: Date.now(),
    output: '', dropped: 0, child: null,
  };
  let child;
  try {
    child = spawn(file, args, { windowsHide: true });
  } catch (e) {
    job.status = 'error'; job.exitCode = 127; append(job, `[spawn error] ${e.message}\n`);
    jobs.set(id, job);
    return summary(job);
  }
  job.child = child;
  child.stdout?.on('data', (c) => append(job, c.toString()));
  child.stderr?.on('data', (c) => append(job, c.toString()));
  child.on('error', (e) => { append(job, `\n[error] ${e.message}\n`); job.status = 'error'; });
  child.on('close', (code) => { job.status = 'exited'; job.exitCode = code; append(job, `\n[process exited with code ${code}]\n`); });
  jobs.set(id, job);
  reap();
  return summary(job);
}

// Send a line of input to a running job's stdin (interactive msfconsole, etc.).
export function writeJob(id, input) {
  const job = jobs.get(id);
  if (!job) return { error: 'job not found' };
  if (job.status !== 'running' || !job.child?.stdin?.writable) return { error: 'job is not running' };
  const line = String(input ?? '');
  job.child.stdin.write(line.endsWith('\n') ? line : line + '\n');
  append(job, `\x1b[2m> ${line}\x1b[0m\n`); // echo the input into the transcript (dim)
  return { ok: true };
}

// Read incremental output from an offset (for polling/streaming).
export function readJob(id, offset = 0) {
  const job = jobs.get(id);
  if (!job) return { error: 'job not found' };
  const off = Math.max(0, Number(offset) || 0);
  const from = Math.max(0, off - job.dropped);
  return {
    id, label: job.label, status: job.status, exitCode: job.exitCode, backend: job.backend,
    kind: job.kind, meta: job.meta, live: job.live, interactive: job.interactive,
    text: job.output.slice(from), nextOffset: job.dropped + job.output.length,
  };
}

// Return the raw job record (for the manager: kind, meta, sessionId, full tail).
export function getJob(id) {
  return jobs.get(id) || null;
}

// Merge freeform metadata into a job (e.g. set the tracker link once it's discovered).
export function updateJobMeta(id, patch = {}) {
  const job = jobs.get(id);
  if (!job) return { error: 'job not found' };
  job.meta = { ...job.meta, ...patch };
  return { ok: true, meta: job.meta };
}

// Append text into a job's transcript (so sibling commands the manager runs show up in the terminal).
export function appendToJob(id, text) {
  const job = jobs.get(id);
  if (!job) return { error: 'job not found' };
  append(job, String(text ?? ''));
  return { ok: true };
}

export function stopJob(id) {
  const job = jobs.get(id);
  if (!job) return { error: 'job not found' };
  try { job.child?.kill('SIGKILL'); } catch { /* noop */ }
  job.status = 'stopped';
  return { ok: true };
}

export function listJobs({ sessionId, userId } = {}) {
  reap();
  return [...jobs.values()]
    .filter((j) => (sessionId ? j.sessionId === sessionId : true) && (userId ? j.userId === userId : true))
    .sort((a, b) => b.startedAt - a.startedAt)
    .map(summary);
}

function summary(job) {
  return {
    id: job.id, label: job.label, command: job.command.slice(0, 200), status: job.status,
    exitCode: job.exitCode, backend: job.backend, startedAt: job.startedAt,
    kind: job.kind, meta: job.meta, live: job.live, interactive: job.interactive,
    bytes: job.dropped + job.output.length, sessionId: job.sessionId,
  };
}

// Drop finished jobs that have been idle a while (keeps the registry small).
function reap() {
  const now = Date.now();
  for (const [id, job] of jobs) {
    if (job.status !== 'running' && now - job.lastAt > REAP_AFTER_MS) jobs.delete(id);
  }
}

// Best-effort cleanup on shutdown.
export function stopAllJobs() {
  for (const job of jobs.values()) { try { job.child?.kill('SIGKILL'); } catch { /* noop */ } }
}
