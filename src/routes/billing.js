import { Router } from 'express';
import { env } from '../config/env.js';
import { newId } from '../db/index.js';
import { getUserById } from '../services/auth/auth.js';
import {
  listPlans, getPlan, getActiveSubscription, activateSubscription,
  createTransaction, getTransactionByOrder, markTransaction, listTransactions,
} from '../db/billing.repo.js';
import {
  createOrder, getOrder, verifyWebhookSignature, cashfreeConfigured, cashfreeMode,
} from '../services/billing/cashfree.js';
import { sendMail, receiptEmail } from '../services/email/mailer.js';

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

async function sendReceipt(userId, plan) {
  const u = await getUserById(userId);
  if (u?.email) sendMail({ to: u.email, ...receiptEmail(plan.name, plan.price_inr) }).catch(() => {});
}

// Public: list active plans (for the pricing page, pre-login).
export const publicPlansRouter = Router();
publicPlansRouter.get('/', wrap(async (_req, res) => {
  res.json({ plans: await listPlans({ activeOnly: true }), cashfree: cashfreeConfigured() });
}));

// Authed billing endpoints.
export const billingRouter = Router();

// Current plan + active subscription for the logged-in user.
billingRouter.get('/me', wrap(async (req, res) => {
  const sub = await getActiveSubscription(req.userId);
  const user = await getUserById(req.userId);
  const planCode = sub?.plan_code || 'free';
  res.json({ plan: await getPlan(planCode), subscription: sub, usage: {
    used: user?.daily_messages_used || 0, limit: user?.daily_message_limit || 0,
  } });
}));

billingRouter.get('/transactions', wrap(async (req, res) => {
  res.json({ transactions: await listTransactions(req.userId) });
}));

// Start a checkout: create a Cashfree order + a pending transaction.
billingRouter.post('/checkout', wrap(async (req, res) => {
  const plan = await getPlan((req.body?.planCode || '').toLowerCase());
  if (!plan || !plan.is_active) return res.status(404).json({ error: 'Plan not found' });
  if (plan.code === 'free' || Number(plan.price_inr) <= 0)
    return res.status(400).json({ error: 'This plan is free — nothing to pay' });

  const user = await getUserById(req.userId);
  const orderId = 'cm_' + newId();
  const { paymentSessionId } = await createOrder({
    orderId,
    amount: plan.price_inr,
    customer: { id: req.userId, email: user?.email, phone: req.body?.phone },
    returnUrl: `${env.email.appBaseUrl}/billing/return`,
  });
  await createTransaction({ userId: req.userId, planCode: plan.code, amount: plan.price_inr, cfOrderId: orderId });
  res.json({ orderId, paymentSessionId, mode: cashfreeMode() });
}));

// Verify an order (fallback when the webhook can't reach localhost): poll Cashfree, activate if paid.
billingRouter.get('/verify/:orderId', wrap(async (req, res) => {
  const txn = await getTransactionByOrder(req.params.orderId);
  if (!txn || txn.user_id !== req.userId) return res.status(404).json({ error: 'Order not found' });
  if (txn.status === 'paid') return res.json({ status: 'paid', alreadyActivated: true });

  const order = await getOrder(req.params.orderId);
  const paid = order?.order_status === 'PAID';
  if (paid) {
    const plan = await getPlan(txn.plan_code);
    await markTransaction(txn.cf_order_id, { status: 'paid', raw: order });
    await activateSubscription(req.userId, plan);
    sendReceipt(req.userId, plan);
    return res.json({ status: 'paid', plan: plan.code });
  }
  res.json({ status: order?.order_status || 'pending' });
}));

// Cashfree webhook (mounted with a raw body parser in app.js — req.body is a Buffer).
export async function cashfreeWebhook(req, res) {
  try {
    const raw = req.body instanceof Buffer ? req.body.toString('utf8') : JSON.stringify(req.body || {});
    const signature = req.headers['x-webhook-signature'];
    const timestamp = req.headers['x-webhook-timestamp'];
    if (env.cashfree.secret && !verifyWebhookSignature(raw, signature, timestamp)) {
      return res.status(401).json({ error: 'bad signature' });
    }
    const payload = JSON.parse(raw);
    const orderId = payload?.data?.order?.order_id;
    const payStatus = payload?.data?.payment?.payment_status || payload?.data?.order?.order_status;
    if (orderId && /SUCCESS|PAID/i.test(payStatus || '')) {
      const txn = await getTransactionByOrder(orderId);
      if (txn && txn.status !== 'paid') {
        const plan = await getPlan(txn.plan_code);
        await markTransaction(orderId, {
          status: 'paid',
          cfPaymentId: payload?.data?.payment?.cf_payment_id,
          method: payload?.data?.payment?.payment_group,
          raw: payload,
        });
        await activateSubscription(txn.user_id, plan);
        sendReceipt(txn.user_id, plan);
      }
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(200).json({ ok: false, error: e.message }); // 200 so Cashfree doesn't spam retries
  }
}
