import { query, newId } from './index.js';

export async function addSupportMessage(userId, sender, content) {
  const id = newId();
  const rows = await query(
    `INSERT INTO support_messages (id, user_id, sender, content) VALUES ($1,$2,$3,$4)
     RETURNING id, user_id, sender, content, seen, created_at`,
    [id, userId, sender, String(content).slice(0, 4000)]
  );
  return rows[0];
}

export async function getThread(userId, limit = 200) {
  return query(
    `SELECT id, user_id, sender, content, seen, created_at FROM support_messages
     WHERE user_id = $1 ORDER BY created_at ASC LIMIT $2`,
    [userId, limit]
  );
}

// Mark messages FROM `senderToMark` (the other party) as seen by the recipient.
export async function markSeen(userId, senderToMark) {
  await query(
    `UPDATE support_messages SET seen = true WHERE user_id = $1 AND sender = $2 AND seen = false`,
    [userId, senderToMark]
  );
}

// Admin conversation list: one row per user with a message, last message + unseen (from user) count.
export async function listConversations() {
  return query(
    `SELECT u.id AS user_id, u.email, u.display_name,
            lm.content AS last_message, lm.created_at AS last_at, lm.sender AS last_sender,
            COALESCE(un.c, 0)::int AS unseen
     FROM users u
     JOIN LATERAL (
       SELECT content, created_at, sender FROM support_messages
       WHERE user_id = u.id ORDER BY created_at DESC LIMIT 1
     ) lm ON true
     LEFT JOIN LATERAL (
       SELECT COUNT(*) c FROM support_messages
       WHERE user_id = u.id AND sender = 'user' AND seen = false
     ) un ON true
     ORDER BY lm.created_at DESC`
  );
}

// Unseen admin->user messages count (for the user's widget badge).
export async function userUnseenCount(userId) {
  const [r] = await query(
    `SELECT COUNT(*)::int c FROM support_messages WHERE user_id = $1 AND sender = 'admin' AND seen = false`,
    [userId]
  );
  return r.c;
}
