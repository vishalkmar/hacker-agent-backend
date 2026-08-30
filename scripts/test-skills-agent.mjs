#!/usr/bin/env node
// Phase 2 TEST — the agent can USE the skills: ```skill tool-block works, blocks are parsed, and the
// matching expert playbook auto-injects (Workflow + Output Format) for a goal. Exits non-zero on fail.
import { initDb, isMemoryReady } from '../src/db/index.js';
import { buildSkillInjection } from '../src/services/skills/index.js';
import { parseToolBlocks, runTool } from '../src/services/llm/agent.js';

await initDb();
if (!isMemoryReady()) { console.error('❌ pgvector not ready'); process.exit(1); }

let failed = 0;
const fail = (m) => { console.error('  ❌ ' + m); failed++; };
const ok = (m) => console.log('  ✅ ' + m);

// 1) ```skill blocks are recognized by the tool-block parser.
const blocks = parseToolBlocks('sure, let me check.\n```skill kerberoasting active directory\n```\ndone');
blocks.length === 1 && blocks[0].type === 'skill'
  ? ok('```skill block is parsed (type=skill)')
  : fail('```skill not parsed correctly: ' + JSON.stringify(blocks));

// 2) the ```skill tool-block returns a real playbook (natural-language query path).
const r1 = await runTool({ type: 'skill', body: 'dump a database with sql injection' }, { sessionId: 'test-sess', userId: 'local-user' });
r1.exitCode === 0 && /Workflow/i.test(r1.output) && /sql/i.test(r1.label)
  ? ok(`\`\`\`skill "sql injection" → ${r1.label} (playbook w/ Workflow)`)
  : fail(`\`\`\`skill query path weak: label=${r1.label} exit=${r1.exitCode}`);

// 3) exact-name path.
const r2 = await runTool({ type: 'skill', body: 'analyzing-memory-dumps-with-volatility' }, { sessionId: 'test-sess', userId: 'local-user' });
r2.exitCode === 0 && /volatility/i.test(r2.output) && r2.output.length > 1000
  ? ok(`\`\`\`skill exact-name → full playbook (${r2.output.length} chars)`)
  : fail(`\`\`\`skill exact-name path failed: exit=${r2.exitCode} len=${r2.output.length}`);

// 4) auto-injection: a goal yields a MATCHED EXPERT PLAYBOOK with Workflow + real commands + Output Format.
const inj = await buildSkillInjection('kerberoast service accounts in active directory', { k: 4 });
if (!inj) { fail('buildSkillInjection returned null'); }
else {
  const hasHeader = /MATCHED EXPERT PLAYBOOK/.test(inj.text);
  const hasWorkflow = /##\s*Workflow/i.test(inj.text) || /```/.test(inj.text);
  const hasFormat = /Output Format/i.test(inj.text);
  const hasNames = Array.isArray(inj.names) && inj.names.length >= 1;
  hasHeader ? ok('injection has MATCHED EXPERT PLAYBOOK header') : fail('injection missing header');
  hasWorkflow ? ok('injection includes the Workflow / real commands') : fail('injection has no Workflow/commands');
  hasFormat ? ok('injection includes the Output Format template') : fail('injection missing Output Format');
  hasNames ? ok(`injection lists matched skills: ${inj.names.slice(0, 3).join(', ')}…`) : fail('injection has no skill names');
  console.log(`  ℹ️  injection size: ${inj.text.length} chars (top: ${inj.names[0]})`);
}

console.log(failed === 0 ? '\n🎉 Phase 2 PASS — the agent can pull + auto-follow skill playbooks.' : `\n💥 Phase 2 FAIL — ${failed} check(s) failed.`);
process.exit(failed === 0 ? 0 : 1);
