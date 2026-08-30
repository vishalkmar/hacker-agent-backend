#!/usr/bin/env node
// Phase 5 TEST — desktop alignment: the Skills feature ships + self-heals in the packaged desktop app
// exactly like the web app (shared backend data, shared frontend, idempotent boot ingest). No installer
// build needed — we assert the packaging config + the self-heal behaviour directly.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { initDb, isMemoryReady } from '../src/db/index.js';
import { ensureSkillsIndexed } from '../src/services/skills/index.js';

const backendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = path.resolve(backendRoot, '..');
let failed = 0;
const fail = (m) => { console.error('  ❌ ' + m); failed++; };
const ok = (m) => console.log('  ✅ ' + m);

// 1) The skills DATA lives under backend/ (so electron-builder's backend extraResource bundles it).
const catPath = path.join(backendRoot, 'data', 'cyber-skills', 'catalog.json');
if (fs.existsSync(catPath) && JSON.parse(fs.readFileSync(catPath, 'utf8')).total === 817)
  ok('skills data is under backend/data/cyber-skills (ships via backend extraResource)');
else fail('backend/data/cyber-skills/catalog.json missing or not 817');

// 2) electron-builder config bundles the backend (with data) + the built frontend, and does NOT
//    exclude the skills data.
const build = JSON.parse(fs.readFileSync(path.join(repoRoot, 'desktop', 'package.json'), 'utf8')).build;
const res = build?.extraResources || [];
const backendRes = res.find((r) => r.from === '../backend' && r.to === 'backend');
const frontendRes = res.find((r) => (r.from || '').includes('frontend/dist'));
backendRes ? ok('electron-builder ships ../backend → backend (data/cyber-skills included)') : fail('no backend extraResource');
frontendRes ? ok('electron-builder ships ../frontend/dist → frontend (Skills panel included)') : fail('no frontend extraResource');
const filters = backendRes?.filter || [];
const excludesData = filters.some((f) => /^!.*data|cyber-skills/i.test(f));
!excludesData ? ok('backend filter does NOT exclude the skills data') : fail('backend filter excludes skills data!');

// 3) The frontend Skills UI is shared (in frontend/src) and wired into App.jsx → desktop renderer gets it.
const hasPanel = fs.existsSync(path.join(repoRoot, 'frontend', 'src', 'components', 'SkillsPanel.jsx'));
const appWired = fs.readFileSync(path.join(repoRoot, 'frontend', 'src', 'App.jsx'), 'utf8').includes('SkillsPanel');
hasPanel && appWired ? ok('SkillsPanel.jsx is in shared frontend/src and wired in App.jsx') : fail('SkillsPanel not shared/wired');

// 4) Boot self-heal is idempotent: with the shared Neon DB already indexed, it must NOT re-ingest.
await initDb();
if (!isMemoryReady()) { fail('pgvector not ready'); }
else {
  const r = await ensureSkillsIndexed();
  r.alreadyIndexed >= 800
    ? ok(`ensureSkillsIndexed idempotent → alreadyIndexed=${r.alreadyIndexed} (no re-embed)`)
    : fail(`ensureSkillsIndexed not idempotent: ${JSON.stringify(r)}`);
}

console.log(failed === 0 ? '\n🎉 Phase 5 PASS — desktop ships + self-heals the Skills feature, aligned with web.' : `\n💥 Phase 5 FAIL — ${failed} check(s) failed.`);
process.exit(failed === 0 ? 0 : 1);
