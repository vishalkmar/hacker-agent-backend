import { createApp } from './app.js';
import { env, describeLlmConfig } from './config/env.js';
import { initDb } from './db/index.js';
import { expireDueSubscriptions, takeExpiringForReminder } from './db/billing.repo.js';
import { sendMail, expiryReminderEmail } from './services/email/mailer.js';

async function main() {
  // Open DB, run migrations, seed default user before accepting traffic.
  await initDb();
  console.log('Database ready (Postgres/Neon)');

  // Phase 13/16: expire due subscriptions + send expiry reminders on boot, then hourly.
  const sweep = async () => {
    try {
      const reminders = await takeExpiringForReminder(3);
      for (const r of reminders) {
        const days = Math.max(1, Math.ceil((new Date(r.expires_at) - Date.now()) / 86400000));
        sendMail({ to: r.email, ...expiryReminderEmail(r.plan_code, days) }).catch(() => {});
      }
      await expireDueSubscriptions(env.auth.freeDailyLimit);
    } catch (e) {
      console.error('billing sweep:', e.message);
    }
  };
  await sweep();
  setInterval(sweep, 60 * 60 * 1000).unref();

  const app = createApp();
  app.listen(env.port, () => {
    console.log('========================================');
    console.log(' CypherMind AI — backend');
    console.log(`  http://localhost:${env.port}`);
    console.log(`  ${describeLlmConfig()}`);
    console.log('========================================');
  });
}

main().catch((err) => {
  console.error('Fatal startup error:', err.message);
  process.exit(1);
});
