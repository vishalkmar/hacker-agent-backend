import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { env } from '../../config/env.js';
import { checkDenylist } from './denylist.js';
import { resolveBackend, execInContainer } from './docker.js';
import { execOverSsh } from './ssh.js';

// Ensure the workspace dir exists (host backend).
fs.mkdirSync(env.exec.workspace, { recursive: true });

// Map a shell name to the executable + args that run a single command string.
function shellInvocation(shell, command) {
  switch (shell) {
    case 'powershell':
    case 'pwsh':
      // Drop the curl/wget aliases so real curl.exe/wget.exe are used when present.
      return {
        file: shell === 'pwsh' ? 'pwsh' : 'powershell.exe',
        args: [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          'Remove-Item alias:curl,alias:wget -ErrorAction SilentlyContinue; ' + command,
        ],
      };
    case 'cmd':
      return { file: 'cmd.exe', args: ['/d', '/s', '/c', command] };
    case 'sh':
      return { file: 'sh', args: ['-c', command] };
    case 'bash':
    default:
      return { file: 'bash', args: ['-lc', command] };
  }
}

// Run a command directly on the host shell.
function runOnHost(cmd, { timeout, onChunk, workdir }) {
  const { shell } = env.exec;
  const limit = env.exec.maxOutputBytes;
  return new Promise((resolve) => {
    const { file, args } = shellInvocation(shell, cmd);
    const started = Date.now();
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let child;
    try {
      child = spawn(file, args, { cwd: workdir, windowsHide: true });
    } catch (err) {
      return resolve({ stdout: '', stderr: `Failed to start shell "${file}": ${err.message}`, exitCode: 127, durationMs: 0, timedOut: false });
    }
    const cap = (buf, chunk) => (buf.length < limit ? (buf + chunk).slice(0, limit) : buf);
    child.stdout.on('data', (c) => {
      stdout = cap(stdout, c.toString());
      onChunk?.('stdout', c.toString());
    });
    child.stderr.on('data', (c) => {
      stderr = cap(stderr, c.toString());
      onChunk?.('stderr', c.toString());
    });
    const killer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeout);
    child.on('error', (err) => {
      clearTimeout(killer);
      resolve({ stdout, stderr: stderr + `\n[spawn error] ${err.message}`, exitCode: 127, durationMs: Date.now() - started, timedOut });
    });
    child.on('close', (code) => {
      clearTimeout(killer);
      if (timedOut) stderr += `\n[timed out after ${timeout}ms]`;
      resolve({ stdout, stderr, exitCode: code ?? (timedOut ? 124 : 0), durationMs: Date.now() - started, timedOut });
    });
  });
}

// Run a single command, in the Docker sandbox when available, else on the host.
//   opts: { cwd, timeoutMs, onChunk, sessionId }
// Returns { command, shell, backend, blocked, reason, stdout, stderr, exitCode, durationMs, timedOut }
export async function runCommand(command, { cwd, timeoutMs, onChunk, sessionId } = {}) {
  const cmd = String(command || '').trim();
  const { shell, workspace } = env.exec;
  const timeout = timeoutMs ?? env.exec.timeoutMs;

  if (!cmd) {
    return { command: cmd, shell, backend: 'host', blocked: false, stdout: '', stderr: 'empty command', exitCode: 1, durationMs: 0, timedOut: false };
  }

  // Host-protection denylist applies to BOTH backends.
  if (env.exec.guardHost) {
    const guard = checkDenylist(cmd);
    if (guard.blocked) {
      onChunk?.('stderr', guard.reason);
      return { command: cmd, shell, backend: 'guard', blocked: true, reason: guard.reason, stdout: '', stderr: guard.reason, exitCode: 126, durationMs: 0, timedOut: false };
    }
  }

  // SSH "full OS" backend takes precedence when explicitly configured.
  if (env.exec.backend === 'ssh') {
    const started = Date.now();
    const res = await execOverSsh(cmd, { timeoutMs: timeout, onChunk });
    if (!res.error) {
      return {
        command: cmd, shell: `ssh:${env.exec.ssh.user}@${env.exec.ssh.host}`, backend: 'ssh',
        blocked: false, stdout: res.stdout, stderr: res.stderr, exitCode: res.exitCode,
        durationMs: Date.now() - started, timedOut: false,
      };
    }
    const host = await runOnHost(cmd, { timeout, onChunk, workdir: cwd || workspace });
    return {
      command: cmd, shell: `${shell} (host-fallback)`, backend: 'host-fallback', blocked: false,
      stdout: host.stdout, stderr: `[ssh unavailable: ${res.error}] — ran on host instead.\n${host.stderr}`,
      exitCode: host.exitCode, durationMs: host.durationMs, timedOut: host.timedOut,
    };
  }

  const backend = await resolveBackend();

  if (backend === 'docker') {
    const started = Date.now();
    const res = await execInContainer(sessionId, cmd, { timeoutMs: timeout, onChunk });
    if (!res.error) {
      return {
        command: cmd,
        shell: `docker:${env.exec.image}`,
        backend: 'docker',
        blocked: false,
        stdout: res.stdout,
        stderr: res.stderr,
        exitCode: res.exitCode,
        durationMs: Date.now() - started,
        timedOut: false,
      };
    }
    // Sandbox couldn't be prepared — fall back to host and tell the caller why.
    const host = await runOnHost(cmd, { timeout, onChunk, workdir: cwd || workspace });
    return {
      command: cmd,
      shell: `${shell} (host-fallback)`,
      backend: 'host-fallback',
      blocked: false,
      stdout: host.stdout,
      stderr: `[sandbox unavailable: ${res.error}] — ran on host instead.\n${host.stderr}`,
      exitCode: host.exitCode,
      durationMs: host.durationMs,
      timedOut: host.timedOut,
    };
  }

  // Host backend.
  const host = await runOnHost(cmd, { timeout, onChunk, workdir: cwd || workspace });
  return { command: cmd, shell, backend: 'host', blocked: false, ...host };
}
