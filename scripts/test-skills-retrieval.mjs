#!/usr/bin/env node
// Phase 1 TEST — assert the skill index is complete and retrieval returns the RIGHT playbooks.
// Exits non-zero if any check fails, so it gates progress to Phase 2.
import { initDb, isMemoryReady, query } from '../src/db/index.js';
import { retrieveSkills, getSkill } from '../src/services/skills/index.js';

await initDb();
if (!isMemoryReady()) { console.error('❌ pgvector not ready'); process.exit(1); }

let failed = 0;
const fail = (m) => { console.error('  ❌ ' + m); failed++; };
const ok = (m) => console.log('  ✅ ' + m);

// 1) count == 817
const [{ n }] = await query('SELECT COUNT(*)::int AS n FROM skill_docs');
n === 817 ? ok(`skill_docs count = ${n}`) : fail(`skill_docs count = ${n}, expected 817`);

// 2) retrieval returns a sensible top hit for representative goals.
// Each case: a natural-language goal + a regex the top few skill names should satisfy.
const cases = [
  ['dump a database via sql injection', /sql|inject|database/i],
  ['analyze a RAM memory dump for malware', /memory|volatility|ram|forensic/i],
  ['find and exploit exposed S3 buckets', /s3|bucket|cloud|storage/i],
  ['kerberoast active directory service accounts', /kerbero|active-directory|\bad\b|ticket/i],
  ['bypass login authentication on a web app', /auth|login|bypass|access/i],
  ['crack password hashes', /hash|crack|password/i],
];
for (const [goal, re] of cases) {
  const hits = await retrieveSkills(goal, 4);
  const names = hits.map((h) => h.name);
  const match = names.some((nm) => re.test(nm)) || hits.some((h) => re.test(h.description));
  match ? ok(`"${goal}" → ${names[0]}`) : fail(`"${goal}" → no relevant skill in top 4: ${names.join(', ')}`);
}

// 3) getSkill returns a full body for a known skill.
const one = await getSkill('analyzing-memory-dumps-with-volatility');
one && one.body && one.body.length > 500
  ? ok(`getSkill body loaded (${one.body.length} chars, mitre=${one.mitre?.join(',')})`)
  : fail('getSkill did not return a substantive body');

console.log(failed === 0 ? '\n🎉 Phase 1 PASS — skill index + retrieval work.' : `\n💥 Phase 1 FAIL — ${failed} check(s) failed.`);
process.exit(failed === 0 ? 0 : 1);
