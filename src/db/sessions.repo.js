import { query, newId } from './index.js';

export async function listSessions(userId) {
  return query(
    `SELECT id, title, created_at, updated_at
     FROM sessions WHERE user_id = $1
     ORDER BY updated_at DESC`,
    [userId]
  );
}

export async function getSession(userId, sessionId) {
  const rows = await query(
    'SELECT id, title, created_at, updated_at FROM sessions WHERE id = $1 AND user_id = $2',
    [sessionId, userId]
  );
  return rows[0] || null;
}

export async function createSession(userId, title = 'New chat') {
  const id = newId();
  await query('INSERT INTO sessions (id, user_id, title) VALUES ($1, $2, $3)', [id, userId, title]);
  return getSession(userId, id);
}

export async function renameSession(userId, sessionId, title) {
  await query(
    `UPDATE sessions SET title = $1, updated_at = now() WHERE id = $2 AND user_id = $3`,
    [title, sessionId, userId]
  );
  return getSession(userId, sessionId);
}

export async function touchSession(sessionId) {
  await query(`UPDATE sessions SET updated_at = now() WHERE id = $1`, [sessionId]);
}

export async function deleteSession(userId, sessionId) {
  const res = await query('DELETE FROM sessions WHERE id = $1 AND user_id = $2 RETURNING id', [
    sessionId,
    userId,
  ]);
  return res.length > 0;
}
