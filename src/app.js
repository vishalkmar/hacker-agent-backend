import express from 'express';
import cors from 'cors';
import { env, describeLlmConfig } from './config/env.js';
import { currentUser } from './middleware/currentUser.js';
import { authRouter } from './routes/auth.js';
import { sessionsRouter } from './routes/sessions.js';
import { chatRouter } from './routes/chat.js';
import { terminalRouter } from './routes/terminal.js';
import { webRouter } from './routes/web.js';
import { filesRouter } from './routes/files.js';
import { memoryRouter } from './routes/memory.js';
import { sandboxRouter } from './routes/sandbox.js';
import { findingsRouter, findingItemRouter } from './routes/findings.js';
import { payloadsRouter } from './routes/payloads.js';
import { reportsRouter, reportItemRouter } from './routes/reports.js';
import { publicPlansRouter, billingRouter, cashfreeWebhook } from './routes/billing.js';
import { adminRouter } from './routes/admin.js';
import { toolsRouter } from './routes/tools.js';

export function createApp() {
  const app = express();

  app.use(cors({ origin: env.corsOrigins, credentials: true }));

  // Cashfree webhook needs the RAW body for signature verification — mount before json parser.
  app.post('/api/billing/webhook', express.raw({ type: '*/*' }), cashfreeWebhook);

  app.use(express.json({ limit: '2mb' }));

  // Lightweight request log.
  app.use((req, _res, next) => {
    if (req.path !== '/api/health') {
      console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
    }
    next();
  });

  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      llm: describeLlmConfig(),
      env: env.nodeEnv,
      exec: {
        enabled: env.exec.enabled,
        shell: env.exec.shell,
        guardHost: env.exec.guardHost,
        backend: env.exec.backend,
        image: env.exec.image,
      },
    });
  });

  // Public auth routes (register/login) — no user required.
  app.use('/api/auth', authRouter);
  // Public pricing (plans) — visible pre-login.
  app.use('/api/plans', publicPlansRouter);

  // Everything below has a current user attached.
  app.use('/api', currentUser);
  app.use('/api/billing', billingRouter);
  app.use('/api/admin', adminRouter);
  app.use('/api/tools', toolsRouter);
  app.use('/api/sessions', sessionsRouter);
  app.use('/api/sessions', findingsRouter);
  app.use('/api/sessions', reportsRouter);
  app.use('/api/findings', findingItemRouter);
  app.use('/api/payloads', payloadsRouter);
  app.use('/api/reports', reportItemRouter);
  app.use('/api/chat', chatRouter);
  app.use('/api/terminal', terminalRouter);
  app.use('/api/web', webRouter);
  app.use('/api/files', filesRouter);
  app.use('/api/memory', memoryRouter);
  app.use('/api/sandbox', sandboxRouter);

  // 404 + error handlers.
  app.use((_req, res) => res.status(404).json({ error: 'Not found' }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    const status = err.status || 500;
    if (status >= 500) console.error('Unhandled error:', err);
    res.status(status).json({ error: err.message || 'Internal error' });
  });

  return app;
}
