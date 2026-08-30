import http from 'node:http';
import { createApp } from './app.js';
import { env, describeLlmConfig } from './config/env.js';
import { initDb } from './db/index.js';
import { expireDueSubscriptions, takeExpiringForReminder } from './db/billing.repo.js';
import { sendMail, expiryReminderEmail } from './services/email/mailer.js';
import { purgeOldSessions } from './db/sessions.repo.js';
import { initSupportSocket } from './services/support/socket.js';

async function main() {
  // Open DB, run migrations, seed default user before accepting traffic.
  await initDb();
  console.log('Database ready (Postgres/Neon)');
  const { seedAdmin } = await import('./services/auth/auth.js');
  await seedAdmin().catch((e) => console.warn('seedAdmin:', e.message));

  // Phase 13/16: expire due subscriptions + send expiry reminders on boot, then hourly.
  const sweep = async () => {
    try {
      const reminders = await takeExpiringForReminder(3);
      for (const r of reminders) {
        const days = Math.max(1, Math.ceil((new Date(r.expires_at) - Date.now()) / 86400000));
        sendMail({ to: r.email, ...expiryReminderEmail(r.plan_code, days) }).catch(() => {});
      }
      await expireDueSubscriptions(env.auth.freeDailyLimit);
      // Retention: drop chats with no activity in 30 days (memory survives).
      const purged = await purgeOldSessions(30);
      if (purged) console.log(`retention: purged ${purged} sessions older than 30 days`);
    } catch (e) {
      console.error('billing/retention sweep:', e.message);
    }
  };
  await sweep();
  setInterval(sweep, 60 * 60 * 1000).unref();

  // Cyber Skills self-heal: if the 817-playbook index is empty on a fresh DB (esp. a desktop install
  // pointing at its own database), auto-ingest once in the background — so web + desktop stay aligned
  // with zero manual steps. No-op when already indexed; never blocks boot.
  import('./services/skills/index.js')
    .then(({ ensureSkillsIndexed }) => ensureSkillsIndexed())
    .then((r) => { if (r?.indexing) console.log('[skills] index empty — auto-ingesting in background…'); })
    .catch((e) => console.warn('[skills] ensureSkillsIndexed:', e.message));

  const app = createApp();
  const server = http.createServer(app);
  initSupportSocket(server, env.corsOrigins); // real-time support chat
  server.listen(env.port, () => {
    console.log('========================================');
    console.log(' CypherMind AI — backend');
    console.log(`  http://localhost:${env.port}  (+ socket.io support)`);
    console.log(`  ${describeLlmConfig()}`);
    console.log('========================================');
  });
}

main().catch((err) => {
  console.error('Fatal startup error:', err.message);
  process.exit(1);
});
