#!/usr/bin/env node
// Phase 6 TEST — findings inherit the guiding skill's MITRE/NIST mapping, and the report renders a
// framework-aligned "MITRE ATT&CK Coverage" section. Uses a throwaway session, cleans up after.
import { initDb, isMemoryReady, query, DEFAULT_USER_ID } from '../src/db/index.js';
import { addFindings, listFindings, findingStats } from '../src/db/findings.repo.js';
import { generateReport } from '../src/services/report/generate.js';
import { setActiveSkill, getActiveSkill } from '../src/services/skills/index.js';

await initDb();
if (!isMemoryReady()) console.warn('(memory not ready — report/tagging still testable)');

let failed = 0;
const fail = (m) => { console.error('  ❌ ' + m); failed++; };
const ok = (m) => console.log('  ✅ ' + m);

// 1) migration added the framework columns
const cols = await query(
  `SELECT column_name FROM information_schema.columns WHERE table_name='findings' AND column_name = ANY($1)`,
  [['mitre', 'nist', 'skill']]
);
cols.length === 3 ? ok('findings has mitre/nist/skill columns') : fail(`missing columns: got ${cols.map((c) => c.column_name).join(',')}`);

const sid = 'test-skill-report-' + Date.now();
await query(`INSERT INTO sessions (id, user_id, title) VALUES ($1,$2,$3)`, [sid, DEFAULT_USER_ID, 'Skill Report Test']);

try {
  // 2) active-skill tracker
  setActiveSkill(sid, { skill: 'performing-kerberoasting-attack', mitre: ['T1558.003'], nist: ['DE.CM-01'] });
  const sk = getActiveSkill(sid);
  sk?.skill === 'performing-kerberoasting-attack' ? ok('setActiveSkill/getActiveSkill round-trips') : fail('active-skill tracker broken');

  // 3) findings tagged (emulates runAndCapture's enrichment) persist + read back
  const items = [{ title: 'Kerberoastable SPN found on dc01', severity: 'high', host: 'dc01', finding_type: 'vuln' }];
  const enriched = items.map((f) => ({ ...f, mitre: sk.mitre, nist: sk.nist, skill: sk.skill }));
  const n = await addFindings(sid, DEFAULT_USER_ID, enriched);
  const list = await listFindings(sid);
  const f = list.find((x) => x.title.includes('Kerberoastable'));
  n === 1 && f?.mitre?.includes('T1558.003') && f.nist?.includes('DE.CM-01') && f.skill === 'performing-kerberoasting-attack'
    ? ok(`finding persisted with MITRE ${f.mitre.join(',')} · skill ${f.skill}`)
    : fail(`finding not tagged correctly: ${JSON.stringify(f && { mitre: f.mitre, nist: f.nist, skill: f.skill })}`);

  // 4) report renders the MITRE ATT&CK Coverage section (markdown + html)
  const stats = await findingStats(sid);
  const { markdown, html } = await generateReport({ id: sid, title: 'Skill Report Test' }, list, stats);
  const mdOk = /MITRE ATT&CK Coverage/.test(markdown) && markdown.includes('T1558.003') && markdown.includes('performing-kerberoasting-attack');
  const htmlOk = /MITRE ATT&amp;CK Coverage/.test(html) && html.includes('T1558.003');
  mdOk ? ok('report markdown has MITRE ATT&CK Coverage (techniques + playbook)') : fail('report markdown missing coverage');
  htmlOk ? ok('report HTML has MITRE ATT&CK Coverage section') : fail('report HTML missing coverage');
} finally {
  await query('DELETE FROM sessions WHERE id = $1', [sid]); // cascade removes the test findings
}

console.log(failed === 0 ? '\n🎉 Phase 6 PASS — findings are framework-tagged and the report is ATT&CK-aligned.' : `\n💥 Phase 6 FAIL — ${failed} check(s) failed.`);
process.exit(failed === 0 ? 0 : 1);
