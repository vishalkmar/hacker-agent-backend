import 'dotenv/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const backendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function hasBash() {
  try {
    execSync('bash -c "exit 0"', { stdio: 'ignore', timeout: 4000 });
    return true;
  } catch {
    return false;
  }
}

function num(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function bool(value, fallback) {
  if (value === undefined) return fallback;
  return /^(1|true|yes|on)$/i.test(String(value).trim());
}

// Default shell if EXEC_SHELL is not set.
// Prefer bash everywhere — the agent thinks in Unix/Kali commands (curl, grep, sed, awk).
// On Windows, Git Bash provides the full Unix toolset; fall back to PowerShell if absent.
function defaultShell() {
  if (process.env.EXEC_SHELL) return process.env.EXEC_SHELL.toLowerCase();
  if (process.platform !== 'win32') return 'bash';
  return hasBash() ? 'bash' : 'powershell';
}

export const env = {
  port: num(process.env.PORT, 8787),
  nodeEnv: process.env.NODE_ENV || 'development',
  corsOrigins: (process.env.CORS_ORIGIN || 'http://localhost:5173')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),

  // Postgres connection string (Neon or any Postgres).
  databaseUrl: process.env.DATABASE_URL || '',

  // ----- Auth (Phase 9) -----
  auth: {
    jwtSecret: process.env.JWT_SECRET || 'dev-insecure-secret-change-me',
    required: bool(process.env.AUTH_REQUIRED, false),
    tokenTtl: process.env.TOKEN_TTL || '7d',
    freeDailyLimit: num(process.env.FREE_DAILY_LIMIT, 50),
    // Phase 15: emails that get the admin panel (comma-separated).
    adminEmails: (process.env.ADMIN_EMAILS || '')
      .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean),
  },

  // ----- Billing / Cashfree (Phase 13) -----
  cashfree: {
    env: (process.env.CASHFREE_ENV || 'sandbox').toLowerCase(), // sandbox | production
    appId: process.env.CASHFREE_APP_ID || '',
    secret: process.env.CASHFREE_SECRET || '',
    webhookSecret: process.env.CASHFREE_WEBHOOK_SECRET || '',
    apiVersion: process.env.CASHFREE_API_VERSION || '2023-08-01',
  },

  // ----- Email + OTP (Phase 12) -----
  email: {
    host: process.env.SMTP_HOST || '',
    port: num(process.env.SMTP_PORT, 587),
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    from: process.env.EMAIL_FROM || 'CypherMind <no-reply@cyphermind.local>',
    appBaseUrl: process.env.APP_BASE_URL || 'http://localhost:5173',
  },
  otp: {
    ttlMin: num(process.env.OTP_TTL_MIN, 10),
    maxAttempts: num(process.env.OTP_MAX_ATTEMPTS, 5),
    resendCooldownSec: num(process.env.OTP_RESEND_COOLDOWN_SEC, 60),
  },

  llm: {
    provider: (process.env.LLM_PROVIDER || 'mock').toLowerCase(),
    baseUrl: process.env.LLM_BASE_URL || '',
    apiKey: process.env.LLM_API_KEY || '',
    model: process.env.LLM_MODEL || '',
    temperature: num(process.env.LLM_TEMPERATURE, 0.4),
    maxTokens: num(process.env.LLM_MAX_TOKENS, 2048),
    // Vision (Phase 11): a multimodal model for understanding uploaded images.
    // Defaults to the chat baseUrl/apiKey; only the model id differs.
    visionModel: process.env.VISION_MODEL || '',
    visionBaseUrl: process.env.VISION_BASE_URL || process.env.LLM_BASE_URL || '',
    visionApiKey: process.env.VISION_API_KEY || process.env.LLM_API_KEY || '',
  },

  // ----- Execution engine (Phase 1.5): lets the AI run real shell commands -----
  exec: {
    enabled: bool(process.env.EXEC_ENABLED, true),
    shell: defaultShell(), // powershell | cmd | bash | sh
    // Working directory the AI's commands run in (its sandbox/workspace).
    workspace: path.resolve(backendRoot, process.env.EXEC_WORKSPACE || './workspace'),
    timeoutMs: num(process.env.EXEC_TIMEOUT_MS, 120_000),
    maxOutputBytes: num(process.env.EXEC_MAX_OUTPUT_BYTES, 200_000),
    // Max execute->observe iterations per chat turn (stops runaway loops).
    maxSteps: num(process.env.EXEC_MAX_STEPS, 8),
    // Larger budget for autonomous Autopilot runs (Phase 8).
    maxStepsAutopilot: num(process.env.EXEC_MAX_STEPS_AUTOPILOT, 25),
    // Block commands that would destroy the host machine (protects YOUR box).
    guardHost: bool(process.env.EXEC_GUARD_HOST, true),

    // ----- Phase 4: Docker sandbox -----
    backend: (process.env.EXEC_BACKEND || 'auto').toLowerCase(), // auto | host | docker
    image: process.env.EXEC_IMAGE || 'cyphermind/kali:latest',
    net: process.env.EXEC_NET || 'bridge', // bridge | none | host
    mem: process.env.EXEC_MEM || '2g',
    cpus: process.env.EXEC_CPUS || '2',

    // ----- Phase 8: SSH "full OS" backend -----
    ssh: {
      host: process.env.SSH_HOST || '',
      user: process.env.SSH_USER || 'root',
      port: process.env.SSH_PORT || '22',
      key: process.env.SSH_KEY || '',
    },
  },

  // ----- Memory engine (Phase 3): cross-session semantic recall -----
  embed: {
    enabled: bool(process.env.EMBED_ENABLED, true),
    provider: (process.env.EMBED_PROVIDER || process.env.LLM_PROVIDER || 'local').toLowerCase(),
    baseUrl: process.env.EMBED_BASE_URL || process.env.LLM_BASE_URL || '',
    apiKey: process.env.EMBED_API_KEY || process.env.LLM_API_KEY || '',
    model: process.env.EMBED_MODEL || 'nvidia/nv-embedqa-e5-v5',
    dim: num(process.env.EMBED_DIM, 1024),
    topK: num(process.env.MEMORY_TOPK, 6),
  },
};

export function describeLlmConfig() {
  const { provider, model, baseUrl, apiKey } = env.llm;
  const keyState = apiKey ? 'set' : 'MISSING';
  if (provider === 'mock') return `LLM provider=mock (no key needed)`;
  return `LLM provider=${provider} model=${model || '(none)'} baseUrl=${baseUrl || '(none)'} apiKey=${keyState}`;
}
