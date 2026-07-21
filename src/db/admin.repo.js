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
       COALESCE(SUM(amount) FILTER (WHERE status='completed'),0)::numeric AS revenue_total,
       COALESCE(SUM(amount) FILTER (WHERE status='completed' AND created_at > date_trunc('month', now())),0)::numeric AS revenue_month,
       COUNT(*) FILTER (WHERE status='completed')::int AS paid_count
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

// Searchable, paginated user list with their current plan + expiry. Optional plan (role) filter.
export async function adminListUsers({ q = '', plan = '', limit = 50, offset = 0 } = {}) {
  const like = `%${q.toLowerCase()}%`;
  const rows = await query(
    `SELECT u.id, u.email, u.display_name, u.role, u.email_verified, u.daily_message_limit,
            u.daily_messages_used, u.created_at, u.role_category, u.referral_source,
            s.expires_at, s.status AS sub_status
     FROM users u
     LEFT JOIN LATERAL (
       SELECT expires_at, status FROM subscriptions
       WHERE user_id = u.id AND status='active' ORDER BY started_at DESC LIMIT 1
     ) s ON true
     WHERE ($1 = '' OR lower(u.email) LIKE $2 OR lower(u.display_name) LIKE $2)
       AND ($5 = '' OR u.role = $5)
     ORDER BY u.created_at DESC
     LIMIT $3 OFFSET $4`,
    [q, like, Math.min(limit, 200), offset, plan]
  );
  const [{ count }] = await query(
    `SELECT COUNT(*)::int AS count FROM users
     WHERE ($1='' OR lower(email) LIKE $2 OR lower(display_name) LIKE $2) AND ($3='' OR role=$3)`,
    [q, like, plan]
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

// Rich analytics for the dashboard over a [from, to] date range (defaults last 30 days).
export async function adminAnalytics({ from, to } = {}) {
  const toD = to ? new Date(to) : new Date();
  const fromD = from ? new Date(from) : new Date(Date.now() - 29 * 86400000);
  const fromS = fromD.toISOString().slice(0, 10);
  const toS = toD.toISOString().slice(0, 10);

  const [u] = await query(`SELECT
      COUNT(*)::int AS total,
      COUNT(*) FILTER (WHERE email_verified)::int AS verified,
      COUNT(*) FILTER (WHERE created_at::date = current_date)::int AS today,
      COUNT(*) FILTER (WHERE created_at >= date_trunc('month', now()))::int AS this_month,
      COUNT(*) FILTER (WHERE created_at BETWEEN date_trunc('month', now()) - interval '1 month' AND date_trunc('month', now()))::int AS last_month,
      COUNT(*) FILTER (WHERE created_at >= date_trunc('month', now()) - interval '3 months')::int AS last_3mo,
      COUNT(*) FILTER (WHERE created_at >= date_trunc('year', now()))::int AS this_year,
      COUNT(*) FILTER (WHERE created_at > now() - interval '30 days')::int AS new_30d,
      COUNT(*) FILTER (WHERE created_at BETWEEN now() - interval '60 days' AND now() - interval '30 days')::int AS prev_30d,
      COUNT(*) FILTER (WHERE created_at > now() - interval '180 days')::int AS new_6mo
    FROM users`);

  const signups = await query(
    `SELECT to_char(d::date,'YYYY-MM-DD') AS date, COALESCE(c,0)::int AS count
     FROM generate_series($1::date, $2::date, interval '1 day') d
     LEFT JOIN (SELECT created_at::date AS day, COUNT(*) c FROM users GROUP BY day) s ON s.day = d::date
     ORDER BY date ASC`,
    [fromS, toS]
  );

  const byCategory = await query(
    `SELECT COALESCE(NULLIF(role_category,''),'unknown') AS category, COUNT(*)::int AS count
     FROM users GROUP BY 1 ORDER BY count DESC LIMIT 8`
  );
  const bySource = await query(
    `SELECT COALESCE(NULLIF(referral_source,''),'unknown') AS source, COUNT(*)::int AS count
     FROM users GROUP BY 1 ORDER BY count DESC LIMIT 8`
  );

  const [rev] = await query(`SELECT
      COALESCE(SUM(amount) FILTER (WHERE status='completed'),0)::numeric AS total,
      COALESCE(SUM(amount) FILTER (WHERE status='completed' AND created_at >= date_trunc('month', now())),0)::numeric AS this_month,
      COALESCE(SUM(amount) FILTER (WHERE status='completed' AND created_at BETWEEN date_trunc('month', now()) - interval '1 month' AND date_trunc('month', now())),0)::numeric AS prev_month,
      COUNT(*) FILTER (WHERE status='completed')::int AS paid_count,
      COUNT(*) FILTER (WHERE status='pending')::int AS pending_count,
      COUNT(*) FILTER (WHERE status='cancelled')::int AS cancelled_count
    FROM transactions`);

  const revenueSeries = await query(
    `SELECT to_char(d::date,'YYYY-MM-DD') AS date, COALESCE(a,0)::numeric AS amount
     FROM generate_series($1::date, $2::date, interval '1 day') d
     LEFT JOIN (SELECT created_at::date AS day, SUM(amount) a FROM transactions WHERE status='completed' GROUP BY day) t ON t.day = d::date
     ORDER BY date ASC`,
    [fromS, toS]
  );
  const revenueByPlan = await query(
    `SELECT plan_code AS plan, COALESCE(SUM(amount),0)::numeric AS amount, COUNT(*)::int AS count
     FROM transactions WHERE status='completed' GROUP BY plan_code ORDER BY amount DESC`
  );

  const planMix = await query(
    `SELECT role AS plan, COUNT(*)::int AS count FROM users GROUP BY role ORDER BY count DESC`
  );
  const [subs] = await query(`SELECT
      COUNT(*) FILTER (WHERE status='active' AND (expires_at IS NULL OR expires_at > now()))::int AS active,
      COUNT(*) FILTER (WHERE status='active' AND expires_at BETWEEN now() AND now() + interval '7 days')::int AS expiring_7d
    FROM subscriptions`);

  const pct = (cur, prev) => (prev > 0 ? Math.round(((cur - prev) / prev) * 1000) / 10 : cur > 0 ? 100 : 0);
  return {
    range: { from: fromS, to: toS },
    users: {
      ...u,
      growth_30d_pct: pct(u.new_30d, u.prev_30d),
    },
    signups,
    byCategory,
    bySource,
    planMix,
    revenue: {
      total: Number(rev.total),
      this_month: Number(rev.this_month),
      prev_month: Number(rev.prev_month),
      month_growth_pct: pct(Number(rev.this_month), Number(rev.prev_month)),
      paid_count: rev.paid_count,
      pending_count: rev.pending_count,
      cancelled_count: rev.cancelled_count,
    },
    revenueSeries: revenueSeries.map((r) => ({ date: r.date, amount: Number(r.amount) })),
    revenueByPlan: revenueByPlan.map((r) => ({ plan: r.plan, amount: Number(r.amount), count: r.count })),
    subscriptions: subs,
  };
}

export async function adminListTransactions({ status = '', q = '', from = '', to = '', limit = 50, offset = 0 } = {}) {
  const like = `%${q.toLowerCase()}%`;
  const rows = await query(
    `SELECT t.id, t.amount, t.status, t.plan_code, t.cf_order_id, t.cf_payment_id, t.voucher_no,
            t.created_at, u.email, u.display_name
     FROM transactions t JOIN users u ON u.id = t.user_id
     WHERE ($1 = '' OR t.status = $1)
       AND ($2 = '' OR lower(u.email) LIKE $3 OR lower(u.display_name) LIKE $3 OR t.cf_order_id LIKE $3 OR CAST(t.amount AS TEXT) LIKE $3)
       AND ($4 = '' OR t.created_at::date >= $4::date)
       AND ($5 = '' OR t.created_at::date <= $5::date)
     ORDER BY t.created_at DESC LIMIT $6 OFFSET $7`,
    [status, q, like, from, to, Math.min(limit, 200), offset]
  );
  const [{ count }] = await query(
    `SELECT COUNT(*)::int AS count FROM transactions t JOIN users u ON u.id = t.user_id
     WHERE ($1='' OR t.status=$1)
       AND ($2='' OR lower(u.email) LIKE $3 OR lower(u.display_name) LIKE $3 OR t.cf_order_id LIKE $3 OR CAST(t.amount AS TEXT) LIKE $3)
       AND ($4='' OR t.created_at::date >= $4::date) AND ($5='' OR t.created_at::date <= $5::date)`,
    [status, q, like, from, to]
  );
  return { transactions: rows, total: count };
}
