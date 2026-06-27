-- CypherMind AI — Phase 1 schema (PostgreSQL / Neon)
-- Only users / sessions / messages exist in Phase 1.
-- Later phases add: tool_executions, findings, targets, payloads, reports, etc.
-- IDs are app-generated short strings (nanoid) kept as text for simplicity.

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT UNIQUE,
  display_name  TEXT NOT NULL DEFAULT 'Operator',
  role          TEXT NOT NULL DEFAULT 'free',   -- free | student | pro | enterprise | admin
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Phase 9: auth + plan/usage columns (additive).
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash       TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS daily_message_limit INTEGER NOT NULL DEFAULT 50;
ALTER TABLE users ADD COLUMN IF NOT EXISTS daily_messages_used INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_daily_reset    DATE NOT NULL DEFAULT CURRENT_DATE;

-- Phase 12: email-OTP auth (existing rows stay verified; new OTP signups start unverified).
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url     TEXT;

CREATE TABLE IF NOT EXISTS email_otps (
  id          TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  code_hash   TEXT NOT NULL,
  purpose     TEXT NOT NULL DEFAULT 'auth',   -- auth (register/login)
  attempts    INTEGER NOT NULL DEFAULT 0,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_email_otps_email ON email_otps(email, created_at DESC);

-- Phase 21: autonomous tool self-test runs + distilled capability registry.
CREATE TABLE IF NOT EXISTS tool_runs (
  id          TEXT PRIMARY KEY,
  tool        TEXT NOT NULL,
  attempt     INTEGER NOT NULL DEFAULT 1,
  command     TEXT NOT NULL,
  stdout      TEXT,
  stderr      TEXT,
  exit_code   INTEGER,
  verdict     TEXT,                          -- works | partial | broken
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_toolruns_tool ON tool_runs(tool, created_at DESC);

CREATE TABLE IF NOT EXISTS tool_capabilities (
  tool        TEXT PRIMARY KEY,
  category    TEXT,
  status      TEXT NOT NULL DEFAULT 'untested', -- untested | works | partial | broken
  capability  TEXT,                              -- 1-line what it does / verified
  example     TEXT,                              -- a known-good command
  tested_at   TIMESTAMPTZ
);

-- Phase 13: plans, subscriptions & transactions (billing).
CREATE TABLE IF NOT EXISTS plans (
  code        TEXT PRIMARY KEY,                 -- free | pro | enterprise | ...
  name        TEXT NOT NULL,
  price_inr   NUMERIC(10,2) NOT NULL DEFAULT 0,
  period      TEXT NOT NULL DEFAULT 'monthly',  -- monthly | lifetime | free
  daily_limit INTEGER NOT NULL DEFAULT 50,
  features    TEXT,                              -- JSON array of feature strings
  is_active   BOOLEAN NOT NULL DEFAULT true,
  sort        INTEGER NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed default plans (idempotent; admin can edit later).
INSERT INTO plans (code, name, price_inr, period, daily_limit, features, sort) VALUES
  ('free','Free',0,'free',50,'["50 messages/day","Multimodal chat","Community support"]',0),
  ('pro','Pro',499,'monthly',500,'["500 messages/day","Autopilot & all tools","Priority support"]',1),
  ('enterprise','Enterprise',4999,'monthly',100000,'["Unlimited messages","Dedicated support","Custom integrations"]',2)
ON CONFLICT (code) DO NOTHING;

CREATE TABLE IF NOT EXISTS subscriptions (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plan_code   TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'active',    -- active | expired | cancelled
  started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ,
  auto_renew  BOOLEAN NOT NULL DEFAULT false,
  reminded    BOOLEAN NOT NULL DEFAULT false,   -- Phase 16: expiry reminder sent
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_subs_user ON subscriptions(user_id, status);
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS reminded BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS transactions (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plan_code     TEXT NOT NULL,
  amount        NUMERIC(10,2) NOT NULL,
  currency      TEXT NOT NULL DEFAULT 'INR',
  status        TEXT NOT NULL DEFAULT 'created',  -- created | paid | failed
  cf_order_id   TEXT,
  cf_payment_id TEXT,
  method        TEXT,
  raw           TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_txn_user ON transactions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_txn_order ON transactions(cf_order_id);

CREATE TABLE IF NOT EXISTS sessions (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title         TEXT NOT NULL DEFAULT 'New chat',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS messages (
  id            TEXT PRIMARY KEY,
  session_id    TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role          TEXT NOT NULL,                  -- user | assistant | system
  content       TEXT NOT NULL DEFAULT '',
  model         TEXT,                            -- which LLM produced an assistant msg
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, created_at ASC);

-- Phase 1.5: audit log of every shell command the AI (or user) executed.
CREATE TABLE IF NOT EXISTS command_executions (
  id            TEXT PRIMARY KEY,
  session_id    TEXT REFERENCES sessions(id) ON DELETE CASCADE,
  user_id       TEXT REFERENCES users(id) ON DELETE CASCADE,
  source        TEXT NOT NULL DEFAULT 'ai',   -- ai | user
  shell         TEXT,
  command       TEXT NOT NULL,
  stdout        TEXT,
  stderr        TEXT,
  exit_code     INTEGER,
  blocked       BOOLEAN NOT NULL DEFAULT FALSE,
  duration_ms   INTEGER,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cmdexec_session ON command_executions(session_id, created_at ASC);

-- Phase 2: uploaded files + their extracted analysis.
CREATE TABLE IF NOT EXISTS files (
  id            TEXT PRIMARY KEY,
  user_id       TEXT REFERENCES users(id) ON DELETE CASCADE,
  session_id    TEXT REFERENCES sessions(id) ON DELETE SET NULL,
  name          TEXT NOT NULL,
  kind          TEXT NOT NULL,                -- image | pdf | code | text | other
  mime          TEXT,
  size_bytes    INTEGER,
  path          TEXT NOT NULL,
  extracted     TEXT,                          -- extracted text / analysis for the LLM
  meta          TEXT,                          -- JSON string of extra findings
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id, created_at DESC);

-- Phase 5: structured findings parsed from scanners (and manual entries).
CREATE TABLE IF NOT EXISTS findings (
  id            TEXT PRIMARY KEY,
  session_id    TEXT REFERENCES sessions(id) ON DELETE CASCADE,
  user_id       TEXT REFERENCES users(id) ON DELETE CASCADE,
  title         TEXT NOT NULL,
  finding_type  TEXT NOT NULL DEFAULT 'info',   -- open_port | service | subdomain | live_host | vuln | secret | info
  severity      TEXT NOT NULL DEFAULT 'info',   -- info | low | medium | high | critical
  host          TEXT,
  port          INTEGER,
  protocol      TEXT,
  service       TEXT,
  version       TEXT,
  evidence      TEXT,
  source        TEXT,                            -- nmap | subfinder | httpx | manual | ai
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Phase 6: vuln-management columns (additive; safe to re-run).
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status      TEXT NOT NULL DEFAULT 'open';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_score  NUMERIC(3,1);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_vector TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cve         TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id, created_at DESC);
-- Avoid duplicate identical findings within a session.
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup
  ON findings(session_id, finding_type, COALESCE(host,''), COALESCE(port,0), COALESCE(service,''), title);

-- Phase 7: saved payload library.
CREATE TABLE IF NOT EXISTS payloads (
  id           TEXT PRIMARY KEY,
  user_id      TEXT REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  payload_type TEXT,
  language     TEXT,
  code         TEXT NOT NULL,
  params       TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_payloads_user ON payloads(user_id, created_at DESC);

-- Phase 7: generated pentest reports.
CREATE TABLE IF NOT EXISTS reports (
  id           TEXT PRIMARY KEY,
  session_id   TEXT REFERENCES sessions(id) ON DELETE CASCADE,
  user_id      TEXT REFERENCES users(id) ON DELETE CASCADE,
  title        TEXT NOT NULL,
  report_type  TEXT DEFAULT 'pentest',
  markdown     TEXT,
  html         TEXT,
  stats        TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_reports_session ON reports(session_id, created_at DESC);
