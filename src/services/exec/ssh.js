import { spawn } from 'node:child_process';
import { env } from '../../config/env.js';

// Run a command on a remote host over SSH (the "full OS" backend).
// Uses the system `ssh` client. Returns { stdout, stderr, exitCode, error? }.
export function execOverSsh(command, { timeoutMs, onChunk } = {}) {
  const { host, user, port, key } = env.exec.ssh;
  if (!host) return Promise.resolve({ error: 'SSH_HOST not configured' });

  const args = [
    '-o', 'StrictHostKeyChecking=no',
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=10',
    '-p', String(port),
  ];
  if (key) args.push('-i', key);
  args.push(`${user}@${host}`, command);

  const timeout = timeoutMs ?? env.exec.timeoutMs;
  const limit = env.exec.maxOutputBytes;

  return new Promise((resolve) => {
    let child;
    try {
      child = spawn('ssh', args, { windowsHide: true });
    } catch (e) {
      return resolve({ error: 'ssh client not available: ' + e.message });
    }
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const cap = (b, c) => (b.length < limit ? (b + c).slice(0, limit) : b);
    child.stdout.on('data', (c) => { stdout = cap(stdout, c.toString()); onChunk?.('stdout', c.toString()); });
    child.stderr.on('data', (c) => { stderr = cap(stderr, c.toString()); onChunk?.('stderr', c.toString()); });
    const killer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeout);
    child.on('error', (e) => { clearTimeout(killer); resolve({ error: 'ssh failed: ' + e.message }); });
    child.on('close', (code) => {
      clearTimeout(killer);
      if (timedOut) stderr += `\n[timed out after ${timeout}ms]`;
      resolve({ stdout, stderr, exitCode: code ?? (timedOut ? 124 : 0) });
    });
  });
}
