import { query, newId } from './index.js';

const parsePlan = (p) => (p ? { ...p, price_inr: Number(p.price_inr), features: safeJson(p.features) } : p);
function safeJson(s) { try { return JSON.parse(s || '[]'); } catch { return []; } }

// ----- Plans -----
export async function listPlans({ activeOnly = true } = {}) {
  const rows = await query(
    `SELECT * FROM plans ${activeOnly ? 'WHERE is_active = true' : ''} ORDER BY sort ASC, price_inr ASC`
  );
  return rows.map(parsePlan);
}
export async function getPlan(code) {
  return parsePlan((await query('SELECT * FROM plans WHERE code = $1', [code]))[0]);
}
export async function upsertPlan(p) {
  await query(
    `INSERT INTO plans (code, name, price_inr, period, daily_limit, features, is_active, sort)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
     ON CONFLICT (code) DO UPDATE SET
       name=$2, price_inr=$3, period=$4, daily_limit=$5, features=$6, is_active=$7, sort=$8`,
    [p.code, p.name, p.price_inr || 0, p.period || 'monthly', p.daily_limit || 50,
     JSON.stringify(p.features || []), p.is_active !== false, p.sort || 0]
  );
  return getPlan(p.code);
}
export async function deletePlan(code) {
  if (code === 'free') return false;
  const r = await query('DELETE FROM plans WHERE code = $1 RETURNING code', [code]);
  return r.length > 0;
}

// ----- Subscriptions -----
export async function getActiveSubscription(userId) {
  const rows = await query(
    `SELECT * FROM subscriptions WHERE user_id = $1 AND status = 'active'
       AND (expires_at IS NULL OR expires_at > now()) ORDER BY started_at DESC LIMIT 1`,
    [userId]
  );
  return rows[0] || null;
}

// Activate (or extend) a subscription and sync the user's role + daily limit.
export async function activateSubscription(userId, plan) {
  // Cancel any existing active subs for a clean state.
  await query(`UPDATE subscriptions SET status='cancelled' WHERE user_id=$1 AND status='active'`, [userId]);
  const expires = plan.period === 'lifetime' || plan.code === 'free'
    ? null
    : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // monthly
  await query(
    `INSERT INTO subscriptions (id, user_id, plan_code, status, expires_at) VALUES ($1,$2,$3,'active',$4)`,
    [newId(), userId, plan.code, expires]
  );
  await query(`UPDATE users SET role=$1, daily_message_limit=$2 WHERE id=$3`,
    [plan.code, plan.daily_limit, userId]);
  return { expires_at: expires };
}

// Subscriptions expiring within `days` that haven't been reminded yet. Marks them reminded.
export async function takeExpiringForReminder(days = 3) {
  const rows = await query(
    `UPDATE subscriptions s SET reminded = true
     FROM users u
     WHERE s.user_id = u.id AND s.status='active' AND s.reminded = false
       AND s.expires_at IS NOT NULL
       AND s.expires_at BETWEEN now() AND now() + ($1 || ' days')::interval
     RETURNING u.email, s.plan_code, s.expires_at`,
    [String(days)]
  );
  return rows;
}

// Expire due subscriptions -> downgrade users to Free. Returns affected user ids.
export async function expireDueSubscriptions(freeLimit = 50) {
  const due = await query(
    `UPDATE subscriptions SET status='expired'
       WHERE status='active' AND expires_at IS NOT NULL AND expires_at <= now()
     RETURNING user_id`
  );
  for (const r of due) {
    await query(`UPDATE users SET role='free', daily_message_limit=$1 WHERE id=$2`, [freeLimit, r.user_id]);
  }
  return due.map((r) => r.user_id);
}

// ----- Transactions -----
export async function createTransaction({ userId, planCode, amount, cfOrderId }) {
  const id = newId();
  await query(
    `INSERT INTO transactions (id, user_id, plan_code, amount, cf_order_id) VALUES ($1,$2,$3,$4,$5)`,
    [id, userId, planCode, amount, cfOrderId]
  );
  return id;
}
export async function getTransactionByOrder(orderId) {
  return (await query('SELECT * FROM transactions WHERE cf_order_id = $1', [orderId]))[0] || null;
}
export async function markTransaction(orderId, { status, cfPaymentId, method, raw }) {
  await query(
    `UPDATE transactions SET status=$1, cf_payment_id=COALESCE($2,cf_payment_id),
       method=COALESCE($3,method), raw=COALESCE($4,raw), updated_at=now() WHERE cf_order_id=$5`,
    [status, cfPaymentId || null, method || null, raw ? JSON.stringify(raw).slice(0, 4000) : null, orderId]
  );
}
export async function listTransactions(userId) {
  return query('SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC', [userId]);
}
