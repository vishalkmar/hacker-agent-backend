import { query, newId } from './index.js';

export async function saveReport(sessionId, userId, { title, report_type, markdown, html, stats }) {
  const id = newId();
  await query(
    `INSERT INTO reports (id, session_id, user_id, title, report_type, markdown, html, stats)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [id, sessionId, userId, title, report_type || 'pentest', markdown, html, stats ? JSON.stringify(stats) : null]
  );
  return id;
}

export async function getReport(userId, id) {
  const rows = await query(
    `SELECT id, session_id, title, report_type, markdown, html, stats, created_at
     FROM reports WHERE id = $1 AND user_id = $2`,
    [id, userId]
  );
  return rows[0] || null;
}

export async function listReports(sessionId) {
  return query(
    `SELECT id, title, report_type, created_at FROM reports WHERE session_id = $1 ORDER BY created_at DESC`,
    [sessionId]
  );
}
