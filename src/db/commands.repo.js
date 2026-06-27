import { query, newId } from './index.js';

export async function logCommand({
  sessionId = null,
  userId = null,
  source = 'ai',
  shell,
  command,
  stdout = '',
  stderr = '',
  exitCode = null,
  blocked = false,
  durationMs = null,
}) {
  const id = newId();
  await query(
    `INSERT INTO command_executions
       (id, session_id, user_id, source, shell, command, stdout, stderr, exit_code, blocked, duration_ms)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [id, sessionId, userId, source, shell, command, stdout, stderr, exitCode, blocked, durationMs]
  );
  return id;
}

export async function listCommands(sessionId) {
  return query(
    `SELECT id, source, shell, command, exit_code, blocked, duration_ms, created_at
     FROM command_executions WHERE session_id = $1 ORDER BY created_at ASC`,
    [sessionId]
  );
}
