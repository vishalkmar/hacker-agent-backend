import { query, newId } from './index.js';

export async function saveArtifact({ sessionId, userId, name, format, mime, sizeBytes, path }) {
  const id = newId();
  await query(
    `INSERT INTO artifacts (id, session_id, user_id, name, format, mime, size_bytes, path)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [id, sessionId, userId, name, format, mime, sizeBytes, path]
  );
  return id;
}

export async function getArtifact(userId, id) {
  const rows = await query(
    `SELECT id, session_id, user_id, name, format, mime, size_bytes, path, created_at
     FROM artifacts WHERE id = $1 AND user_id = $2`,
    [id, userId]
  );
  return rows[0] || null;
}

export async function listArtifacts(sessionId) {
  return query(
    `SELECT id, name, format, mime, size_bytes, created_at
     FROM artifacts WHERE session_id = $1 ORDER BY created_at DESC`,
    [sessionId]
  );
}
