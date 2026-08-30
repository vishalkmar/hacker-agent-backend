#!/usr/bin/env node
// Phase 1 — ingest all 817 vendored cyber-skills into the skill_docs pgvector table.
// Usage: node scripts/ingest-cyber-skills.mjs
import { initDb, isMemoryReady } from '../src/db/index.js';
import { ingestSkills, skillStats } from '../src/services/skills/index.js';

const t0 = Date.now();
await initDb(); // ensures the skill_docs table + pgvector exist
if (!isMemoryReady()) {
  console.error('❌ memory engine (pgvector) not ready — cannot ingest. Check DATABASE_URL / EMBED_*.');
  process.exit(1);
}

process.stdout.write('Ingesting cyber-skills');
const n = await ingestSkills({
  batch: 32,
  onProgress: (done, total) => process.stdout.write(`\rIngesting cyber-skills… ${done}/${total}`),
});
const stats = await skillStats();
console.log(`\n✅ ingested ${n} skills in ${((Date.now() - t0) / 1000).toFixed(1)}s — skill_docs now holds ${stats.skills}`);
console.log('   top subdomains:', stats.subdomains.slice(0, 6).map((s) => `${s.subdomain}(${s.count})`).join(' '));
process.exit(0);
