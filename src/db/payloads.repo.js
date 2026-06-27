import { query, newId } from './index.js';

export async function savePayload(userId, { name, payload_type, language, code, params }) {
  const id = newId();
  await query(
    `INSERT INTO payloads (id, user_id, name, payload_type, language, code, params)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [id, userId, name, payload_type || null, language || null, code, params ? JSON.stringify(params) : null]
  );
  return id;
}

export async function listPayloads(userId) {
  return query(
    `SELECT id, name, payload_type, language, code, created_at FROM payloads
     WHERE user_id = $1 ORDER BY created_at DESC`,
    [userId]
  );
}

export async function deletePayload(userId, id) {
  const r = await query('DELETE FROM payloads WHERE id = $1 AND user_id = $2 RETURNING id', [id, userId]);
  return r.length > 0;
}
