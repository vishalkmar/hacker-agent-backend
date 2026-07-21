// Probe: feed the REAL agent system prompt to the live LLM chain and print exactly what the model emits
// (which ```tool blocks it chooses). Isolates model behaviour — no DB/Docker/exec. Usage:
//   node scripts/llm-probe.mjs "user prompt here"
import { streamChat, activeModel } from '../src/services/llm/index.js';
import { SYSTEM_PROMPT, EXEC_PROTOCOL_PROMPT, EXEC_FORCE_PROMPT, THINKING_PROMPT, CONVERSATION_GUARD } from '../src/services/llm/prompt.js';

const system = SYSTEM_PROMPT + EXEC_PROTOCOL_PROMPT + EXEC_FORCE_PROMPT + THINKING_PROMPT + CONVERSATION_GUARD;
const prompt = process.argv[2] || 'Test for SQL injection login bypass on https://iamalive.app/login';

let out = '';
const t0 = Date.now();
try {
  await streamChat({ history: [{ role: 'user', content: prompt }], system, onDelta: (t) => { out += t; } });
} catch (e) {
  console.error('LLM error:', e.message);
  process.exit(2);
}
const secs = ((Date.now() - t0) / 1000).toFixed(1);

// Which tool blocks did the model emit?
const tags = [...out.matchAll(/```([a-z]+)/g)].map((m) => m[1]).filter((t) => t !== 'bash' || true);
console.log(`\n──────── MODEL: ${activeModel()} · ${secs}s · ${out.length} chars ────────`);
console.log(out.slice(0, 2500));
console.log('\n──────── TOOL BLOCKS EMITTED ────────');
console.log(tags.length ? [...new Set(tags)].join(', ') : '(NONE — model only wrote prose, did not invoke a tool)');
