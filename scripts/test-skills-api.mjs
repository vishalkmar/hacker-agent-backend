#!/usr/bin/env node
// Phase 3 TEST — the /api/skills HTTP endpoints (browse + filter + semantic search + get + stats).
// Mounts the real router on a throwaway express app (no auth middleware — the router is read-only) and
// hits it over HTTP. Exits non-zero on any failure.
import express from 'express';
import { initDb, isMemoryReady } from '../src/db/index.js';
import { skillsRouter } from '../src/routes/skills.js';

await initDb();
if (!isMemoryReady()) { console.error('❌ pgvector not ready'); process.exit(1); }

const app = express();
app.use('/api/skills', skillsRouter);
const server = app.listen(0);
await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${server.address().port}/api/skills`;
const get = async (p) => { const r = await fetch(base + p); return { status: r.status, body: await r.json().catch(() => ({})) }; };

let failed = 0;
const fail = (m) => { console.error('  ❌ ' + m); failed++; };
const ok = (m) => console.log('  ✅ ' + m);

// 1) browse + pagination
const b = await get('?limit=5');
b.body.total === 817 && b.body.skills.length === 5
  ? ok(`browse: total=${b.body.total}, page=5`)
  : fail(`browse wrong: total=${b.body.total} page=${b.body.skills?.length}`);

// 2) subdomain filter
const sub = await get('?subdomain=web-application-security&limit=100');
sub.body.total === 42 && sub.body.skills.every((s) => s.subdomain === 'web-application-security')
  ? ok(`subdomain filter: web-application-security = ${sub.body.total}`)
  : fail(`subdomain filter wrong: total=${sub.body.total}`);

// 3) MITRE filter
const mit = await get('?mitre=T1055&limit=200');
mit.body.total > 0 && mit.body.skills.every((s) => s.mitre.includes('T1055'))
  ? ok(`MITRE filter: T1055 = ${mit.body.total} skills, all tagged`)
  : fail(`MITRE filter wrong: total=${mit.body.total}`);

// 4) text query
const q = await get('?q=kerberoast&limit=20');
q.body.total >= 1 && q.body.skills.some((s) => /kerbero/i.test(s.name))
  ? ok(`text query "kerberoast" = ${q.body.total}`)
  : fail(`text query wrong: total=${q.body.total}`);

// 5) semantic search
const se = await get('/search?q=' + encodeURIComponent('dump a database via sql injection') + '&k=4');
se.body.skills?.length && /sql|inject/i.test(se.body.skills[0].name)
  ? ok(`semantic search → ${se.body.skills[0].name}`)
  : fail(`semantic search wrong: ${JSON.stringify(se.body.skills?.[0])}`);

// 6) stats
const st = await get('/stats');
st.body.skills === 817 && Array.isArray(st.body.subdomains) && st.body.subdomains.length > 10
  ? ok(`stats: ${st.body.skills} skills, ${st.body.subdomains.length} subdomains`)
  : fail(`stats wrong: ${JSON.stringify(st.body).slice(0, 100)}`);

// 7) get full playbook by name
const one = await get('/analyzing-memory-dumps-with-volatility');
one.status === 200 && one.body.skill?.body?.length > 1000 && one.body.skill.mitre?.length
  ? ok(`get by name: body ${one.body.skill.body.length} chars, MITRE ${one.body.skill.mitre.join(',')}`)
  : fail(`get by name wrong: status=${one.status}`);

// 8) 404
const nf = await get('/does-not-exist-xyz');
nf.status === 404 ? ok('unknown skill → 404') : fail(`unknown skill status=${nf.status}`);

server.close();
console.log(failed === 0 ? '\n🎉 Phase 3 PASS — /api/skills endpoints work.' : `\n💥 Phase 3 FAIL — ${failed} check(s) failed.`);
process.exit(failed === 0 ? 0 : 1);
