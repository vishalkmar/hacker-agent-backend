import { query } from './index.js';

// Aggregate metrics for the admin dashboard.
export async function adminMetrics() {
  const [totals] = await query(`SELECT
      COUNT(*)::int AS users,
      COUNT(*) FILTER (WHERE email_verified)::int AS verified,
      COUNT(*) FILTER (WHERE created_at > now() - interval '7 days')::int AS new_7d
    FROM users`);

  const byPlan = await query(
    `SELECT role AS plan, COUNT(*)::int AS count FROM users GROUP BY role ORDER BY count DESC`
  );

  const signups = await query(
    `SELECT to_char(d::date,'YYYY-MM-DD') AS date, COALESCE(c,0)::int AS count
     FROM generate_series(current_date - interval '13 days', current_date, interval '1 day') d
     LEFT JOIN (
       SELECT created_at::date AS day, COUNT(*) AS c FROM users GROUP BY day
     ) s ON s.day = d::date
     ORDER BY date ASC`
  );

  const [rev] = await query(
    `SELECT
       COALESCE(SUM(amount) FILTER (WHERE status='paid'),0)::numeric AS revenue_total,
       COALESCE(SUM(amount) FILTER (WHERE status='paid' AND created_at > date_trunc('month', now())),0)::numeric AS revenue_month,
       COUNT(*) FILTER (WHERE status='paid')::int AS paid_count
     FROM transactions`
  );

  const [subs] = await query(
    `SELECT
       COUNT(*) FILTER (WHERE status='active' AND (expires_at IS NULL OR expires_at > now()))::int AS active,
       COUNT(*) FILTER (WHERE status='active' AND expires_at BETWEEN now() AND now() + interval '7 days')::int AS expiring_7d
     FROM subscriptions`
  );

  return {
    users: totals,
    plans: byPlan,
    signups,
    revenue: { total: Number(rev.revenue_total), month: Number(rev.revenue_month), paidCount: rev.paid_count },
    subscriptions: subs,
  };
}

// Searchable, paginated user list with their current plan + expiry.
export async function adminListUsers({ q = '', limit = 50, offset = 0 } = {}) {
  const like = `%${q.toLowerCase()}%`;
  const rows = await query(
    `SELECT u.id, u.email, u.display_name, u.role, u.email_verified, u.daily_message_limit,
            u.daily_messages_used, u.created_at,
            s.expires_at, s.status AS sub_status
     FROM users u
     LEFT JOIN LATERAL (
       SELECT expires_at, status FROM subscriptions
       WHERE user_id = u.id AND status='active' ORDER BY started_at DESC LIMIT 1
     ) s ON true
     WHERE ($1 = '' OR lower(u.email) LIKE $2 OR lower(u.display_name) LIKE $2)
     ORDER BY u.created_at DESC
     LIMIT $3 OFFSET $4`,
    [q, like, Math.min(limit, 200), offset]
  );
  const [{ count }] = await query(
    `SELECT COUNT(*)::int AS count FROM users
     WHERE ($1='' OR lower(email) LIKE $2 OR lower(display_name) LIKE $2)`,
    [q, like]
  );
  return { users: rows, total: count };
}

export async function adminGetUser(id) {
  const [user] = await query(
    `SELECT id, email, display_name, role, email_verified, daily_message_limit,
            daily_messages_used, created_at FROM users WHERE id = $1`,
    [id]
  );
  if (!user) return null;
  const subscriptions = await query(
    `SELECT plan_code, status, started_at, expires_at FROM subscriptions
     WHERE user_id = $1 ORDER BY started_at DESC LIMIT 10`,
    [id]
  );
  const transactions = await query(
    `SELECT id, plan_code, amount, status, cf_order_id, cf_payment_id, created_at
     FROM transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
    [id]
  );
  return { user, subscriptions, transactions };
}

export async function adminListTransactions({ status = '', limit = 100 } = {}) {
  return query(
    `SELECT t.id, t.amount, t.status, t.plan_code, t.cf_order_id, t.cf_payment_id, t.created_at,
            u.email
     FROM transactions t JOIN users u ON u.id = t.user_id
     WHERE ($1 = '' OR t.status = $1)
     ORDER BY t.created_at DESC LIMIT $2`,
    [status, Math.min(limit, 500)]
  );
}
