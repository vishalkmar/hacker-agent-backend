import { query, newId } from './index.js';

// Insert findings, ignoring duplicates (the unique dedup index). Returns inserted count.
export async function addFindings(sessionId, userId, items) {
  if (!items?.length) return 0;
  let n = 0;
  for (const f of items) {
    try {
      const rows = await query(
        `INSERT INTO findings
           (id, session_id, user_id, title, finding_type, severity, host, port, protocol, service, version, evidence, source, cvss_score, cvss_vector, cve, remediation)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
         ON CONFLICT DO NOTHING
         RETURNING id`,
        [
          newId(), sessionId, userId,
          f.title, f.finding_type || 'info', f.severity || 'info',
          f.host || null, f.port ?? null, f.protocol || null,
          f.service || null, f.version || null, f.evidence || null, f.source || 'ai',
          f.cvss_score ?? null, f.cvss_vector || null, f.cve || null, f.remediation || null,
        ]
      );
      if (rows.length) n++;
    } catch (e) {
      console.warn('addFinding failed:', e.message);
    }
  }
  return n;
}

export async function listFindings(sessionId) {
  return query(
    `SELECT id, title, finding_type, severity, host, port, protocol, service, version, evidence,
            source, status, cvss_score, cvss_vector, cve, remediation, created_at
     FROM findings WHERE session_id = $1
     ORDER BY array_position(ARRAY['critical','high','medium','low','info'], severity), created_at DESC`,
    [sessionId]
  );
}

const UPDATABLE = ['status', 'severity', 'remediation', 'cve', 'cvss_score', 'cvss_vector', 'title', 'finding_type'];

export async function updateFinding(userId, id, patch) {
  const sets = [];
  const vals = [];
  let i = 1;
  for (const k of UPDATABLE) {
    if (patch[k] !== undefined) {
      sets.push(`${k} = $${i++}`);
      vals.push(patch[k]);
    }
  }
  if (!sets.length) return null;
  sets.push(`updated_at = now()`);
  vals.push(id, userId);
  const rows = await query(
    `UPDATE findings SET ${sets.join(', ')} WHERE id = $${i++} AND user_id = $${i}
     RETURNING id, title, finding_type, severity, status, cvss_score, cve, remediation`,
    vals
  );
  return rows[0] || null;
}

export async function deleteFinding(userId, id) {
  const rows = await query('DELETE FROM findings WHERE id = $1 AND user_id = $2 RETURNING id', [id, userId]);
  return rows.length > 0;
}

export async function findingStats(sessionId) {
  const rows = await query(
    `SELECT severity, COUNT(*)::int AS n FROM findings WHERE session_id = $1 GROUP BY severity`,
    [sessionId]
  );
  const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const r of rows) {
    stats[r.severity] = r.n;
    stats.total += r.n;
  }
  return stats;
}
