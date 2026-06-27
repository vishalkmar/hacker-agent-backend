import crypto from 'node:crypto';
import { env } from '../../config/env.js';

const BASE = () =>
  env.cashfree.env === 'production' ? 'https://api.cashfree.com/pg' : 'https://sandbox.cashfree.com/pg';

export function cashfreeConfigured() {
  return !!(env.cashfree.appId && env.cashfree.secret);
}
export function cashfreeMode() {
  return env.cashfree.env === 'production' ? 'production' : 'sandbox';
}

function headers() {
  return {
    'Content-Type': 'application/json',
    'x-api-version': env.cashfree.apiVersion,
    'x-client-id': env.cashfree.appId,
    'x-client-secret': env.cashfree.secret,
  };
}

// Create a Cashfree order. Returns { paymentSessionId, orderId } or throws.
export async function createOrder({ orderId, amount, customer, returnUrl }) {
  if (!cashfreeConfigured()) {
    const e = new Error('Cashfree is not configured (set CASHFREE_APP_ID / CASHFREE_SECRET)');
    e.status = 503;
    throw e;
  }
  const res = await fetch(`${BASE()}/orders`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({
      order_id: orderId,
      order_amount: Number(amount),
      order_currency: 'INR',
      customer_details: {
        customer_id: customer.id,
        customer_email: customer.email,
        customer_phone: customer.phone || '9999999999',
      },
      order_meta: { return_url: `${returnUrl}?order_id={order_id}` },
    }),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const e = new Error('Cashfree order failed: ' + (json.message || res.status));
    e.status = 502;
    throw e;
  }
  return { paymentSessionId: json.payment_session_id, orderId: json.order_id };
}

// Fetch order status from Cashfree (used by the verify endpoint as a webhook fallback).
export async function getOrder(orderId) {
  const res = await fetch(`${BASE()}/orders/${orderId}`, { headers: headers() });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) return null;
  return json; // includes order_status: PAID | ACTIVE | EXPIRED ...
}

// Verify a webhook signature (Cashfree: base64 HMAC-SHA256 of `${timestamp}${rawBody}`).
export function verifyWebhookSignature(rawBody, signature, timestamp) {
  if (!env.cashfree.secret || !signature) return false;
  const payload = `${timestamp}${rawBody}`;
  const expected = crypto.createHmac('sha256', env.cashfree.secret).update(payload).digest('base64');
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
  } catch {
    return false;
  }
}
