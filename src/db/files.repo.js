import { query, newId } from './index.js';

export async function createFile({
  userId,
  sessionId = null,
  name,
  kind,
  mime,
  sizeBytes,
  path: filePath,
  extracted,
  meta,
}) {
  const id = newId();
  await query(
    `INSERT INTO files (id, user_id, session_id, name, kind, mime, size_bytes, path, extracted, meta)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [id, userId, sessionId, name, kind, mime, sizeBytes, filePath, extracted, JSON.stringify(meta || {})]
  );
  return getFile(userId, id);
}

export async function getFile(userId, id) {
  const rows = await query(
    `SELECT id, name, kind, mime, size_bytes, extracted, meta, created_at
     FROM files WHERE id = $1 AND user_id = $2`,
    [id, userId]
  );
  const f = rows[0];
  if (f && typeof f.meta === 'string') {
    try {
      f.meta = JSON.parse(f.meta);
    } catch {
      /* leave as-is */
    }
  }
  return f || null;
}
