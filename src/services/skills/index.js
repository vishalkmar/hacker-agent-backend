// Cyber Skills RAG service — Phase 1.
//
// Ingests the 817 vendored Anthropic Cybersecurity Skills playbooks (backend/data/cyber-skills) into
// the `skill_docs` pgvector table and retrieves the most relevant playbook(s) for a given goal. Mirrors
// the Kali tool-doc RAG (services/tools/index.js): embed a compact "retrieval text" per skill, cosine
// search, keyword fallback when embeddings are in local-hash mode. The full SKILL.md body is stored so
// the agent can inject the expert Workflow + Output Format on a hit (Phase 2).
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { query, isMemoryReady } from '../../db/index.js';
import { embed, embedOne, toVectorLiteral } from '../memory/embed.js';

const backendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
export const SKILLS_DIR = path.join(backendRoot, 'data', 'cyber-skills');

const hash = (s) => crypto.createHash('sha1').update(s || '').digest('hex');
const arr = (v) => (Array.isArray(v) ? v : v ? [v] : []);
const pgArray = (a) => arr(a).map((x) => String(x)); // node-postgres maps JS arrays -> text[]

// The compact text we embed for retrieval — name + subdomain + description + tags. NOT the full body
// (which is long and would dilute the semantic signal); the body is stored separately for injection.
function embedText(s) {
  return [s.name?.replace(/-/g, ' '), s.subdomain, s.description, arr(s.tags).join(' ')]
    .filter(Boolean).join('\n').slice(0, 2000);
}

// Read the vendored catalog + each SKILL.md body from disk.
export function loadCatalog() {
  const catPath = path.join(SKILLS_DIR, 'catalog.json');
  if (!fs.existsSync(catPath)) throw new Error(`catalog.json not found at ${catPath} — run scripts/sync-cyber-skills.mjs first`);
  const cat = JSON.parse(fs.readFileSync(catPath, 'utf8'));
  return cat.skills.map((s) => {
    const p = path.join(SKILLS_DIR, s.path);
    const md = fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '';
    // Strip the YAML frontmatter — keep just the playbook body for injection.
    const body = md.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '').trim();
    return { ...s, body };
  });
}

// Upsert a batch of skills (embeds their retrieval text in one call).
export async function upsertSkillDocs(items) {
  if (!isMemoryReady() || !items?.length) return 0;
  const clean = items.filter((s) => s && s.name);
  let vectors;
  try {
    vectors = await embed(clean.map(embedText), 'passage');
  } catch (e) {
    console.warn('skill embed batch failed:', e.message);
    return 0;
  }
  let n = 0;
  for (let i = 0; i < clean.length; i++) {
    const s = clean[i];
    const ch = hash(`${s.description}|${s.body}`);
    try {
      await query(
        `INSERT INTO skill_docs (name, subdomain, description, tags, mitre, nist, body, content_hash, embedding, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::vector, now())
         ON CONFLICT (name) DO UPDATE SET
           subdomain=$2, description=$3, tags=$4, mitre=$5, nist=$6, body=$7,
           content_hash=$8, embedding=$9::vector, updated_at=now()`,
        [s.name, s.subdomain || '', s.description || '', pgArray(s.tags), pgArray(s.mitre),
         pgArray(s.nist), s.body || '', ch, toVectorLiteral(vectors[i])]
      );
      n++;
    } catch (e) {
      console.warn('upsertSkillDoc failed for', s.name, e.message);
    }
  }
  return n;
}

// Ingest the whole vendored catalog in batches. Returns the number of skills indexed.
export async function ingestSkills({ batch = 32, onProgress } = {}) {
  const skills = loadCatalog();
  let total = 0;
  for (let i = 0; i < skills.length; i += batch) {
    total += await upsertSkillDocs(skills.slice(i, i + batch));
    onProgress?.(Math.min(i + batch, skills.length), skills.length);
  }
  return total;
}

// Boot-time self-healing: if the vendored catalog is present but the index is empty (a fresh DB —
// e.g. a desktop install pointing at its own database, or first web deploy), ingest it ONCE in the
// background so the Skills feature works everywhere without a manual step. Cheap + idempotent: it only
// embeds when skill_docs is (nearly) empty, and never blocks boot. Returns a small status object.
export async function ensureSkillsIndexed({ background = true, minExpected = 800 } = {}) {
  if (!isMemoryReady()) return { skipped: 'memory-not-ready' };
  let have = 0;
  try { const r = await query('SELECT COUNT(*)::int AS n FROM skill_docs'); have = r[0]?.n || 0; } catch { return { skipped: 'no-table' }; }
  if (have >= minExpected) return { alreadyIndexed: have };
  if (!fs.existsSync(path.join(SKILLS_DIR, 'catalog.json'))) return { skipped: 'no-catalog', have };
  const run = () => ingestSkills({ batch: 32 })
    .then((c) => console.log(`[skills] auto-indexed ${c} cyber-skill playbooks (was ${have})`))
    .catch((e) => console.warn('[skills] auto-index failed:', e.message));
  if (background) { run(); return { indexing: true, had: have }; }
  return { indexed: await ingestSkills({ batch: 32 }) };
}

// Retrieve top-K skills relevant to a goal. Embedding search + keyword fallback.
export async function retrieveSkills(queryText, k = 4) {
  if (!isMemoryReady() || !queryText?.trim()) return [];
  try {
    const qvec = await embedOne(queryText, 'query');
    const rows = await query(
      `SELECT name, subdomain, description, tags, mitre, nist,
              1 - (embedding <=> $1::vector) AS score
       FROM skill_docs
       ORDER BY embedding <=> $1::vector ASC LIMIT $2`,
      [toVectorLiteral(qvec), k]
    );
    if (rows.length) return rows;
  } catch (e) {
    console.warn('retrieveSkills vector path failed:', e.message);
  }
  const like = `%${queryText.toLowerCase().slice(0, 60)}%`;
  return query(
    `SELECT name, subdomain, description, tags, mitre, nist, 0 AS score
     FROM skill_docs
     WHERE lower(name) LIKE $1 OR lower(description) LIKE $1 OR lower(array_to_string(tags,' ')) LIKE $1
     LIMIT $2`,
    [like, k]
  );
}

// Full playbook (including body) by exact name.
export async function getSkill(name) {
  return (await query(
    `SELECT name, subdomain, description, tags, mitre, nist, body, updated_at
     FROM skill_docs WHERE name = $1`, [name]
  ))[0] || null;
}

// Pull the named `## Section` blocks out of a SKILL.md body, in the requested order.
export function extractSkillSections(body, wanted) {
  const parts = String(body || '').split(/\n(?=##\s)/);
  const picked = [];
  for (const w of wanted) {
    const sec = parts.find((p) => new RegExp(`^##\\s+${w}\\b`, 'i').test(p.trim()));
    if (sec) picked.push(sec.trim());
  }
  return picked.join('\n\n');
}

// Build the system-prompt injection for a goal: the #1 matched playbook's Workflow + Output Format
// (trimmed to a budget), plus the other matches listed as pull-able. Returns { text, names } or null.
export async function buildSkillInjection(goal, { k = 4, bodyBudget = 3500 } = {}) {
  const hits = await retrieveSkills(goal, k);
  if (!hits.length) return null;
  const top = hits[0];
  const full = await getSkill(top.name);
  let sections = extractSkillSections(full?.body || '', ['Workflow', 'Output Format']);
  if (sections.length > bodyBudget) {
    sections = sections.slice(0, bodyBudget) + '\n…[playbook truncated — pull the full one with ```skill ' + top.name + ']';
  }
  const mitre = top.mitre?.length ? ` (MITRE ${top.mitre.join(', ')})` : '';
  let text = `== MATCHED EXPERT PLAYBOOK: ${top.name} [${top.subdomain || 'cybersecurity'}]${mitre} ==\n`;
  text += `${top.description}\n\n`;
  text += 'FOLLOW this playbook — run each Workflow step for real, and present results in its Output Format:\n\n';
  text += sections || '(this playbook has no structured Workflow section — pull it with ```skill ' + top.name + ')';
  const others = hits.slice(1);
  if (others.length) {
    text += `\n\nOther matched playbooks (pull with \`\`\`skill <name>): ${others.map((s) => s.name).join(', ')}`;
  }
  return {
    text,
    names: hits.map((h) => h.name),
    top: { name: top.name, mitre: top.mitre || [], nist: top.nist || [] },
  };
}

// Which expert playbook is currently guiding a session (set when its injection fires). Used to tag the
// findings produced that turn with the skill's MITRE/NIST mapping → framework-aligned reports.
const activeSkill = new Map(); // sessionId -> { skill, mitre, nist }
export function setActiveSkill(sessionId, ctx) { if (sessionId && ctx?.skill) activeSkill.set(sessionId, ctx); }
export function getActiveSkill(sessionId) { return activeSkill.get(sessionId) || null; }

// Browse/filter the catalog (deterministic, paginated) — for the Skills UI. NOT semantic; use
// retrieveSkills for natural-language relevance. Filters: q (name/desc/tags text), subdomain, mitre,
// nist. Returns { total, limit, offset, skills } (bodies excluded — pull one via getSkill).
export async function browseSkills({ q = '', subdomain = '', mitre = '', nist = '', limit = 60, offset = 0 } = {}) {
  if (!isMemoryReady()) return { total: 0, limit, offset, skills: [] };
  const like = q ? `%${String(q).toLowerCase().slice(0, 80)}%` : '';
  const where = `
      ($1 = '' OR lower(name) LIKE $1 OR lower(description) LIKE $1 OR lower(array_to_string(tags,' ')) LIKE $1)
      AND ($2 = '' OR subdomain = $2)
      AND ($3 = '' OR $3 = ANY(mitre))
      AND ($4 = '' OR $4 = ANY(nist))`;
  const params = [like, subdomain || '', mitre || '', nist || ''];
  const [{ total }] = await query(`SELECT COUNT(*)::int AS total FROM skill_docs WHERE ${where}`, params);
  const skills = await query(
    `SELECT name, subdomain, description, tags, mitre, nist
     FROM skill_docs WHERE ${where}
     ORDER BY name LIMIT $5 OFFSET $6`,
    [...params, Math.min(Number(limit) || 60, 200), Math.max(Number(offset) || 0, 0)]
  );
  return { total, limit: Number(limit) || 60, offset: Number(offset) || 0, skills };
}

export async function skillStats() {
  const [s] = await query(`SELECT COUNT(*)::int AS skills FROM skill_docs`);
  const subs = await query(
    `SELECT COALESCE(NULLIF(subdomain,''),'other') AS subdomain, COUNT(*)::int AS count
     FROM skill_docs GROUP BY 1 ORDER BY count DESC`
  );
  return { ...s, subdomains: subs };
}
