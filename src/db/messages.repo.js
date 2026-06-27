import { query, newId } from './index.js';

export async function listMessages(sessionId) {
  return query(
    `SELECT id, session_id, role, content, model, created_at
     FROM messages WHERE session_id = $1
     ORDER BY created_at ASC`,
    [sessionId]
  );
}

export async function addMessage({ sessionId, userId, role, content, model = null }) {
  const id = newId();
  const rows = await query(
    `INSERT INTO messages (id, session_id, user_id, role, content, model)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, session_id, role, content, model, created_at`,
    [id, sessionId, userId, role, content, model]
  );
  return rows[0];
}

// History formatted for the LLM (role/content pairs only).
export async function historyForLlm(sessionId) {
  const rows = await query(
    `SELECT role, content FROM messages WHERE session_id = $1 ORDER BY created_at ASC`,
    [sessionId]
  );
  return rows.map((m) => ({ role: m.role, content: m.content }));
}
