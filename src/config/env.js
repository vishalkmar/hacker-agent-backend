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

// Build the LLM failover chain (highest priority first). Numbered LLM_<n>_MODEL entries win
// (each may carry its own BASE_URL/API_KEY for a different provider); otherwise fall back to
// the comma-separated LLM_MODELS (or single LLM_MODEL) on the default endpoint.
function buildLlmChain() {
  const defBase = (process.env.LLM_BASE_URL || '').trim();
  const defKey = (process.env.LLM_API_KEY || '').trim();
  const numbered = [];
  for (let i = 1; i <= 20; i++) {
    const model = process.env[`LLM_${i}_MODEL`];
    if (!model || !model.trim()) continue;
    numbered.push({
      model: model.trim(),
      baseUrl: (process.env[`LLM_${i}_BASE_URL`] || defBase).trim(),
      apiKey: (process.env[`LLM_${i}_API_KEY`] || defKey).trim(),
    });
  }
  if (numbered.length) return numbered;
  const models = (process.env.LLM_MODELS || process.env.LLM_MODEL || '')
    .split(',').map((s) => s.trim()).filter(Boolean);
  return models.map((model) => ({ model, baseUrl: defBase, apiKey: defKey }));
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
  // Phase D2: true when embedded in the Electron desktop app (spawned with CYPHERMIND_DESKTOP=true).
  // The backend is then bound to 127.0.0.1 and only the local renderer talks to it → CORS can be permissive.
  desktop: bool(process.env.CYPHERMIND_DESKTOP, false),
  // Phase D3: the deployed web API the desktop trusts for login/entitlement. When the embedded backend can't
  // verify a JWT locally (no shared JWT_SECRET), it validates the token against `${webApiUrl}/api/auth/me`.
  webApiUrl: (process.env.WEB_API_URL || '').replace(/\/+$/, ''),
  // Phase D6: per-launch shared secret between the Electron renderer and this embedded backend. When set
  // (desktop only), every /api call must carry it in the X-CypherMind-Local header — so no OTHER local
  // process on 127.0.0.1 can drive the exec engine, only our own renderer that was handed the secret.
  localApiSecret: process.env.LOCAL_API_SECRET || '',
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
    // Direct admin login (username/password from .env).
    adminUsername: process.env.ADMIN_USERNAME || '',
    adminPassword: process.env.ADMIN_PASSWORD || '',
  },

  // ----- Billing / Cashfree (Phase 13) -----
  cashfree: {
    env: (process.env.CASHFREE_ENV || 'sandbox').toLowerCase(), // sandbox | production
    appId: process.env.CASHFREE_APP_ID || '',
    secret: process.env.CASHFREE_SECRET || '',
    webhookSecret: process.env.CASHFREE_WEBHOOK_SECRET || '',
    apiVersion: process.env.CASHFREE_API_VERSION || '2023-08-01',
  },

  // ----- AI Browser tool (Playwright) -----
  browser: {
    enabled: bool(process.env.BROWSER_ENABLED, true),
    headless: bool(process.env.BROWSER_HEADLESS, true),
    timeoutMs: num(process.env.BROWSER_TIMEOUT_MS, 30_000),
  },

  // ----- Email + OTP (Phase 12) -----
  email: {
    // Brevo transactional API (preferred when set).
    brevoApiKey: process.env.BREVO_API_KEY || '',
    // SMTP fallback (Brevo SMTP relay or any SMTP).
    host: process.env.SMTP_HOST || process.env.BREVO_SMTP_HOST || '',
    port: num(process.env.SMTP_PORT || process.env.BREVO_SMTP_PORT, 587),
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
    // Multi-provider failover CHAIN, highest priority first. Two ways to configure:
    //  1) Numbered entries — each can point at a DIFFERENT company/endpoint:
    //       LLM_1_MODEL / LLM_1_BASE_URL / LLM_1_API_KEY, LLM_2_MODEL / ... (url+key optional,
    //       default to LLM_BASE_URL / LLM_API_KEY). Use this to mix NVIDIA + OpenRouter + others.
    //  2) LLM_MODELS (comma-separated) OR single LLM_MODEL — all on the default endpoint.
    // A model that hangs (no first token in firstTokenTimeoutMs) or errors falls over to the next.
    chain: buildLlmChain(),
    models: buildLlmChain().map((c) => c.model),
    model: buildLlmChain()[0]?.model || '',
    // How long to wait for the FIRST streamed token before failing over to the next model.
    firstTokenTimeoutMs: num(process.env.LLM_FIRST_TOKEN_TIMEOUT_MS, 25_000),
    // Nemotron reasoning models stream their thinking in `reasoning_content` (not `content`),
    // which caused "empty response"/false-"hang" failovers. Disabling thinking makes them stream
    // the answer directly (faster, reliable). Our agent loop provides the reasoning structure.
    disableThinking: bool(process.env.LLM_DISABLE_THINKING, true),
    temperature: num(process.env.LLM_TEMPERATURE, 0.4),
    maxTokens: num(process.env.LLM_MAX_TOKENS, 2048),
    // Vision (Phase 11): a multimodal model for understanding uploaded images.
    // Defaults to the chat baseUrl/apiKey; only the model id differs.
    visionModel: process.env.VISION_MODEL || '',
    visionBaseUrl: process.env.VISION_BASE_URL || process.env.LLM_BASE_URL || '',
    visionApiKey: process.env.VISION_API_KEY || process.env.LLM_API_KEY || '',
    // Optional server-side speech-to-text (mic). Any OpenAI-compatible /audio/transcriptions endpoint
    // (e.g. Groq's free Whisper) — auto-detects the spoken language. The chat mic uses the browser Web
    // Speech API by default; this is the fallback for browsers without it.
    sttModel: process.env.STT_MODEL || 'whisper-large-v3',
    sttBaseUrl: process.env.STT_BASE_URL || '',
    sttApiKey: process.env.STT_API_KEY || '',
  },

  // ----- Execution engine (Phase 1.5): lets the AI run real shell commands -----
  exec: {
    enabled: bool(process.env.EXEC_ENABLED, true),
    shell: defaultShell(), // powershell | cmd | bash | sh
    // Working directory the AI's commands run in (its sandbox/workspace).
    workspace: path.resolve(backendRoot, process.env.EXEC_WORKSPACE || './workspace'),
    timeoutMs: num(process.env.EXEC_TIMEOUT_MS, 120_000),
    maxOutputBytes: num(process.env.EXEC_MAX_OUTPUT_BYTES, 200_000),
    // Max execute->observe iterations per chat turn (stops runaway loops). Big assessments
    // ("test all vulns on this site") need room; on hitting the cap the agent now still writes a
    // findings summary instead of stopping abruptly.
    maxSteps: num(process.env.EXEC_MAX_STEPS, 20),
    // Larger budget for autonomous Autopilot runs (Phase 8).
    maxStepsAutopilot: num(process.env.EXEC_MAX_STEPS_AUTOPILOT, 25),
    // Block commands that would destroy the host machine (protects YOUR box).
    guardHost: bool(process.env.EXEC_GUARD_HOST, true),

    // ----- Phase 4: Docker sandbox -----
    backend: (process.env.EXEC_BACKEND || 'auto').toLowerCase(), // auto | host | docker
    image: process.env.EXEC_IMAGE || 'cyphermind/kali:latest',
    net: process.env.EXEC_NET || 'bridge', // bridge | none | host
    // Grant NET_RAW/NET_ADMIN + seccomp=unconfined so scanners (nmap SYN, masscan, hping,
    // aircrack) actually work in the sandbox. Off = locked-down (SYN scans fail).
    netCaps: bool(process.env.EXEC_NET_CAPS, true),
    mem: process.env.EXEC_MEM || '2g',
    cpus: process.env.EXEC_CPUS || '2',
    // Wi-Fi passthrough: to run REAL wireless attacks (airodump/aireplay/reaver) the container must see the
    // host's monitor-capable radio. Set EXEC_WIFI=true to launch the sandbox with --privileged --net=host so a
    // USB adapter attached to the exec host is usable. Only meaningful on a Linux exec host with such an
    // adapter (a cloud VM / Windows-WSL host has no radio, so leave it off). Off by default (safer isolation).
    wifi: bool(process.env.EXEC_WIFI, false),
    // Wordlist (rockyou) bind-mounted read-only into the sandbox at the standard Kali path, so every crack
    // command (hashcat/john/hydra) that references /usr/share/wordlists/rockyou.txt just works — uncompressed
    // and guaranteed present. Defaults to backend/rockyou.txt if the user dropped it there.
    wordlist: path.resolve(backendRoot, process.env.EXEC_WORDLIST || './rockyou.txt'),
    wordlistMount: process.env.EXEC_WORDLIST_MOUNT || '/usr/share/wordlists/rockyou.txt',

    // ----- Phase 8: SSH "full OS" backend -----
    ssh: {
      host: process.env.SSH_HOST || '',
      user: process.env.SSH_USER || 'root',
      port: process.env.SSH_PORT || '22',
      key: process.env.SSH_KEY || '',
    },
  },

  // ----- Shodan (OSINT/recon): internet-wide device/service intelligence via api.shodan.io -----
  shodan: {
    apiKey: process.env.SHODAN_API_KEY || '',
    baseUrl: process.env.SHODAN_BASE_URL || 'https://api.shodan.io',
    timeoutMs: num(process.env.SHODAN_TIMEOUT_MS, 15_000),
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
  const { provider, model, baseUrl, apiKey, chain } = env.llm;
  if (provider === 'mock') return `LLM provider=mock (no key needed)`;
  if (provider === 'openai' || provider === 'nvidia') {
    const entries = chain.map((entry, index) =>
      `priority=#${index + 1} model=${entry.model} baseUrl=${entry.baseUrl || '(none)'} apiKey=${entry.apiKey ? 'set' : 'MISSING'}`);
    return `LLM adapter=openai-compatible ${entries.join(' | ') || '(no models configured)'}`;
  }
  return `LLM provider=${provider} model=${model || '(none)'} baseUrl=${baseUrl || '(none)'} apiKey=${apiKey ? 'set' : 'MISSING'}`;
}
