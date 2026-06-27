import { Router } from 'express';
import { env } from '../config/env.js';
import { runCommand } from '../services/exec/runner.js';
import { logCommand } from '../db/commands.repo.js';

export const terminalRouter = Router();

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// GET /api/terminal/info -> shell + workspace config (for the UI)
terminalRouter.get('/info', (_req, res) => {
  res.json({
    enabled: env.exec.enabled,
    shell: env.exec.shell,
    workspace: env.exec.workspace,
    guardHost: env.exec.guardHost,
    timeoutMs: env.exec.timeoutMs,
    backend: env.exec.backend,
    image: env.exec.image,
  });
});

// POST /api/terminal/run -> run a command directly (manual terminal / testing)
// Body: { command, sessionId? }
terminalRouter.post(
  '/run',
  wrap(async (req, res) => {
    const command = (req.body?.command || '').toString();
    if (!command.trim()) return res.status(400).json({ error: 'command is required' });

    const result = await runCommand(command, { sessionId: req.body?.sessionId || null });
    await logCommand({
      sessionId: req.body?.sessionId || null,
      userId: req.userId,
      source: 'user',
      shell: result.shell,
      command,
      stdout: result.stdout,
      stderr: result.stderr,
      exitCode: result.exitCode,
      blocked: result.blocked,
      durationMs: result.durationMs,
    });

    res.json({ result });
  })
);
