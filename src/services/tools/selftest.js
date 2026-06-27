import { query, newId } from '../../db/index.js';
import { runCommand } from '../exec/runner.js';
import { checkDenylist } from '../exec/denylist.js';

const LAB = process.env.TOOLS_LAB_TARGET || '127.0.0.1';
const RETRIES = Number(process.env.TOOLS_SELFTEST_RETRIES) || 3;
const TIMEOUT = Number(process.env.TOOLS_SELFTEST_TIMEOUT_MS) || 20_000;

// Only allow self-test commands that are safe: a known-good example that targets the lab host,
// or pure introspection (--help/--version/-h). Everything else is rejected.
function safeCommands(tool, example) {
  const cmds = [];
  if (example && /\b(127\.0\.0\.1|localhost|0\.0\.0\.0)\b/.test(example) && !/\b(\d{1,3}\.){3}\d{1,3}\b/.test(example.replace(/127\.0\.0\.1|0\.0\.0\.0/g, ''))) {
    cmds.push(example);
  }
  cmds.push(`${tool} --version`, `${tool} --help`, `${tool} -h`);
  // De-dupe + drop anything the host-guard would block.
  return [...new Set(cmds)].filter((c) => !checkDenylist(c).blocked).slice(0, RETRIES);
}

async function runOne(sessionId, command) {
  // runCommand handles Docker→host fallback + the host-protection denylist for us.
  const r = await runCommand(command, { sessionId, timeoutMs: TIMEOUT });
  return { stdout: r.stdout, stderr: r.stderr, exitCode: r.exitCode, backend: r.backend };
}

function judge({ stdout, stderr, exitCode }) {
  const out = `${stdout || ''}\n${stderr || ''}`;
  if (/command not found|not installed|No such file/i.test(out)) return 'broken';
  if (exitCode === 0) return 'works';
  if ((out.trim().length > 20) && /usage:|options?:|version|-h,|--help/i.test(out)) return 'partial';
  return 'broken';
}

// Test a single tool: try safe commands until one "works"; record runs + capability.
export async function selfTestTool({ tool, category, example, sessionId }) {
  const cmds = safeCommands(tool, example);
  let best = { verdict: 'broken', command: cmds[0] || `${tool} --version`, out: '' };
  for (let i = 0; i < cmds.length; i++) {
    const res = await runOne(sessionId, cmds[i]);
    const verdict = judge(res);
    await query(
      `INSERT INTO tool_runs (id, tool, attempt, command, stdout, stderr, exit_code, verdict)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [newId(), tool, i + 1, cmds[i], (res.stdout || '').slice(0, 2000), (res.stderr || '').slice(0, 2000), res.exitCode ?? null, verdict]
    ).catch(() => {});
    if (verdict === 'works') { best = { verdict, command: cmds[i], out: res.stdout || res.stderr || '' }; break; }
    if (verdict === 'partial' && best.verdict !== 'works') best = { verdict, command: cmds[i], out: res.stdout || res.stderr || '' };
  }
  const capability = (best.out || '').split('\n').find((l) => l.trim())?.slice(0, 160) || '';
  await query(
    `INSERT INTO tool_capabilities (tool, category, status, capability, example, tested_at)
     VALUES ($1,$2,$3,$4,$5, now())
     ON CONFLICT (tool) DO UPDATE SET category=$2, status=$3, capability=$4, example=$5, tested_at=now()`,
    [tool, category || null, best.verdict, capability, best.command]
  ).catch(() => {});
  return { tool, verdict: best.verdict, command: best.command };
}

// Run a sweep. scope: 'all' | 'category:web' | 'tool:nmap'.
export async function runSelfTest({ scope = 'all', sessionId = 'tools', limit = 25 } = {}) {
  let rows;
  if (scope.startsWith('tool:')) {
    rows = await query('SELECT name AS tool, category, example FROM tool_docs WHERE name = $1', [scope.slice(5)]);
  } else if (scope.startsWith('category:')) {
    rows = await query('SELECT name AS tool, category, example FROM tool_docs WHERE category = $1 LIMIT $2', [scope.slice(9), limit]);
  } else {
    rows = await query('SELECT name AS tool, category, example FROM tool_docs ORDER BY updated_at DESC LIMIT $1', [limit]);
  }
  const results = [];
  for (const r of rows) {
    results.push(await selfTestTool({ ...r, sessionId }));
  }
  const summary = results.reduce((a, r) => ((a[r.verdict] = (a[r.verdict] || 0) + 1), a), {});
  return { tested: results.length, summary, results, labTarget: LAB };
}

export async function listToolCapabilities(status = '') {
  if (status) return query('SELECT * FROM tool_capabilities WHERE status = $1 ORDER BY tool', [status]);
  return query('SELECT * FROM tool_capabilities ORDER BY tested_at DESC NULLS LAST, tool LIMIT 500');
}
