import { query, newId, isMemoryReady } from './index.js';
import { embed, embedOne, toVectorLiteral } from '../services/memory/embed.js';

// Store one or more text chunks as memories (embedded as 'passage').
export async function storeMemories(userId, sessionId, items) {
  if (!isMemoryReady() || !items?.length) return 0;
  const texts = items.map((i) => i.content);
  let vectors;
  try {
    vectors = await embed(texts, 'passage');
  } catch {
    return 0;
  }
  let n = 0;
  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    try {
      await query(
        `INSERT INTO memory_chunks (id, user_id, session_id, source, role, content, embedding)
         VALUES ($1,$2,$3,$4,$5,$6,$7::vector)`,
        [newId(), userId, sessionId, it.source || 'message', it.role || null, it.content, toVectorLiteral(vectors[i])]
      );
      n++;
    } catch (e) {
      console.warn('storeMemory failed:', e.message);
    }
  }
  return n;
}

// Semantic recall: top-K memory chunks most similar to `queryText` for this user.
// Optionally exclude the current session so we surface *past* context.
export async function recallMemories(userId, queryText, { topK, excludeSessionId } = {}) {
  if (!isMemoryReady() || !queryText?.trim()) return [];
  const k = topK || 6;
  let qvec;
  try {
    qvec = await embedOne(queryText, 'query');
  } catch {
    return [];
  }
  const params = [userId, toVectorLiteral(qvec), k];
  let sql = `
    SELECT id, session_id, source, role, content, created_at,
           1 - (embedding <=> $2::vector) AS score
    FROM memory_chunks
    WHERE user_id = $1`;
  if (excludeSessionId) {
    sql += ` AND (session_id IS DISTINCT FROM $4)`;
    params.push(excludeSessionId);
  }
  sql += ` ORDER BY embedding <=> $2::vector ASC LIMIT $3`;
  try {
    return await query(sql, params);
  } catch (e) {
    console.warn('recallMemories failed:', e.message);
    return [];
  }
}
