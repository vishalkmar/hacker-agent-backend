import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { nanoid } from 'nanoid';
import { env } from '../config/env.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

if (!env.databaseUrl) {
  throw new Error('DATABASE_URL is not set in backend/.env (Postgres connection string required)');
}

// Neon requires SSL. We control SSL via the explicit `ssl` option below and accept its
// managed cert (rejectUnauthorized:false) — the standard setup for serverless Postgres.
// Strip any `sslmode=` from the URL so pg doesn't warn about it conflicting with `ssl`.
const connectionString = env.databaseUrl.replace(/([?&])sslmode=[^&]*(&|$)/, (_m, p1, p2) =>
  p2 === '&' ? p1 : ''
);

export const pool = new pg.Pool({
  connectionString,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30_000,
});

pool.on('error', (err) => console.error('Postgres pool error:', err.message));

// Simple query helper: returns rows.
export async function query(text, params) {
  const res = await pool.query(text, params);
  return res.rows;
}

export function newId() {
  return nanoid();
}

// The default local user for Phase 1 (real auth arrives in Phase 9).
export const DEFAULT_USER_ID = 'local-user';

// Run schema migrations (idempotent) + seed the default user. Called once on boot.
export async function initDb() {
  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(schema);
  await pool.query(
    `INSERT INTO users (id, email, display_name, role)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (id) DO NOTHING`,
    [DEFAULT_USER_ID, 'operator@local', 'Operator', 'admin']
  );
  await initMemory();
}

// Phase 3: pgvector + memory_chunks table. Dimension comes from EMBED_DIM, so the vector
// column is created dynamically. Best-effort: if pgvector is unavailable, memory is skipped.
export async function initMemory() {
  const { env } = await import('../config/env.js');
  const dim = env.embed.dim;
  try {
    await pool.query('CREATE EXTENSION IF NOT EXISTS vector');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS memory_chunks (
        id          TEXT PRIMARY KEY,
        user_id     TEXT REFERENCES users(id) ON DELETE CASCADE,
        session_id  TEXT REFERENCES sessions(id) ON DELETE SET NULL,
        source      TEXT NOT NULL DEFAULT 'message',
        role        TEXT,
        content     TEXT NOT NULL,
        embedding   vector(${dim}),
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);
    await pool.query('CREATE INDEX IF NOT EXISTS idx_memory_user ON memory_chunks(user_id, created_at DESC)');
    // ANN index for fast cosine search (hnsw available in pgvector >= 0.5 / Neon).
    await pool
      .query(
        'CREATE INDEX IF NOT EXISTS idx_memory_vec ON memory_chunks USING hnsw (embedding vector_cosine_ops)'
      )
      .catch((e) => console.warn('hnsw index skipped:', e.message));

    // Phase 19: RAG index of Kali tool docs (embedding dim matches EMBED_DIM).
    await pool.query(`
      CREATE TABLE IF NOT EXISTS tool_docs (
        name         TEXT PRIMARY KEY,
        package      TEXT,
        category     TEXT,
        summary      TEXT,
        help_text    TEXT,
        man_excerpt  TEXT,
        example      TEXT,
        source       TEXT NOT NULL DEFAULT 'extract',
        content_hash TEXT,
        embedding    vector(${dim}),
        updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);
    await pool
      .query('CREATE INDEX IF NOT EXISTS idx_tooldocs_vec ON tool_docs USING hnsw (embedding vector_cosine_ops)')
      .catch((e) => console.warn('tool_docs hnsw index skipped:', e.message));

    memoryReady = true;
    console.log(`Memory engine ready (pgvector, dim=${dim})`);
  } catch (e) {
    memoryReady = false;
    console.warn('Memory engine disabled (pgvector unavailable):', e.message);
  }
}

export let memoryReady = false;
export function isMemoryReady() {
  return memoryReady;
}
