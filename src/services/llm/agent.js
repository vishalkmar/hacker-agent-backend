import { env } from '../../config/env.js';
import { streamChat, activeModel } from './index.js';
import { SYSTEM_PROMPT, EXEC_PROTOCOL_PROMPT, AUTOPILOT_PROMPT } from './prompt.js';
import { runCommand } from '../exec/runner.js';
import { webSearch, renderSearchResults } from '../web/search.js';
import { fetchUrl, renderPage } from '../web/fetch.js';
import { reconUrl, renderRecon } from '../web/recon.js';
import { extractFindings, detectScanner } from '../scan/parsers.js';
import { extractWebFindings, detectWebScanner } from '../scan/webparsers.js';
import { extractWirelessFindings, buildWirelessCommand } from '../scan/wireless.js';
import { retrieveTools } from '../tools/index.js';
import { runBrowser, fmtBrowser } from '../browser/browser.js';
import { enrichCvss } from '../scan/cvss.js';
import { generatePayload, renderPayload, parsePayloadSpec } from '../payloads/templates.js';
import { generateReport } from '../report/generate.js';
import { logCommand } from '../../db/commands.repo.js';
import { addFindings, listFindings, findingStats } from '../../db/findings.repo.js';
import { saveReport } from '../../db/reports.repo.js';
import { getSession } from '../../db/sessions.repo.js';

function shellNote(shell) {
  if (shell === 'powershell' || shell === 'pwsh') {
    return `\n\nYour execute shell is PowerShell. IMPORTANT: \`curl\` and \`wget\` are aliases
for Invoke-WebRequest — call \`curl.exe\` for real curl. Use \`Select-String\` instead of
\`grep\`. Prefer PowerShell cmdlets (Invoke-WebRequest, Test-NetConnection, Get-Content).`;
  }
  if (shell === 'cmd') {
    return `\n\nYour execute shell is Windows cmd.exe. Use Windows commands; for HTTP use curl.exe.`;
  }
  return `\n\nYour execute shell is bash (Git Bash on Windows / Linux) with the full Unix
toolset (curl, wget, grep, sed, awk, jq, openssl, nc if present). Write standard Unix/Kali
commands. If a tool like nmap/sqlmap is missing, say so and adapt or install it.`;
}

const EXEC_SYSTEM = SYSTEM_PROMPT + EXEC_PROTOCOL_PROMPT + shellNote(env.exec.shell);

const TOOL_TYPES = ['execute', 'search', 'fetch', 'recon', 'scan', 'vulnscan', 'wireless', 'tool', 'browser', 'payload', 'report'];
// Models often write a shell command in a plain ```bash/```sh/```shell block instead of
// ```execute. Treat those as execute so the agent actually RUNS commands (not just prints them).
const EXEC_ALIASES = new Set(['bash', 'sh', 'shell', 'console', 'terminal']);
const ALL_FENCES = [...TOOL_TYPES, ...EXEC_ALIASES];

// Parse all tool blocks in document order. Handles BOTH forms the model uses:
//   ```fetch https://x```            (body on the same line as the info string)
//   ```execute\nwhoami\n```          (body on following lines)
function parseToolBlocks(text) {
  const re = new RegExp('```(' + ALL_FENCES.join('|') + ')[ \\t]*([\\s\\S]*?)```', 'g');
  const out = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    const body = m[2].trim();
    if (body) out.push({ type: EXEC_ALIASES.has(m[1]) ? 'execute' : m[1], body });
  }
  return out;
}

function stripToolBlocks(text) {
  const re = new RegExp('```(' + ALL_FENCES.join('|') + ')[ \\t]*[\\s\\S]*?```', 'g');
  return text.replace(re, '').replace(/\n{3,}/g, '\n\n').trim();
}

function fmtCmdOutput(result) {
  const parts = [];
  if (result.stdout?.trim()) parts.push(result.stdout.trim());
  if (result.stderr?.trim()) parts.push(result.stderr.trim());
  return parts.join('\n').trim();
}

// Run a command, log it, and auto-extract findings if it was a scanner.
async function runAndCapture(command, { sessionId, userId }) {
  const result = await runCommand(command, { sessionId });
  await logCommand({
    sessionId,
    userId,
    source: 'ai',
    shell: result.shell,
    command,
    stdout: result.stdout,
    stderr: result.stderr,
    exitCode: result.exitCode,
    blocked: result.blocked,
    durationMs: result.durationMs,
  });
  let findingsAdded = 0;
  try {
    const out = `${result.stdout || ''}\n${result.stderr || ''}`;
    const items = [
      ...extractFindings(command, out),
      ...extractWebFindings(command, out),
      ...extractWirelessFindings(command, out),
    ];
    if (items.length) findingsAdded = await addFindings(sessionId, userId, items.map(enrichCvss));
  } catch (e) {
    console.warn('finding extraction failed:', e.message);
  }
  return { result, findingsAdded };
}

// Run a single tool block; returns { label, output, exitCode, findingsAdded }.
async function runTool({ type, body }, { sessionId, userId }) {
  if (type === 'execute') {
    const { result, findingsAdded } = await runAndCapture(body, { sessionId, userId });
    return {
      label: '$ ' + body,
      output: fmtCmdOutput(result) || '(no output)',
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  if (type === 'scan') {
    // Bare target -> sensible nmap; otherwise run the given scanner command as-is.
    const command = detectScanner(body) ? body : `nmap -sV -Pn -T4 ${body}`;
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: 'scan: ' + command,
      output: fmtCmdOutput(result) || '(no output)',
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  if (type === 'vulnscan') {
    // Bare target -> nuclei; otherwise run the given web scanner command as-is.
    const command = detectWebScanner(body) ? body : `nuclei -u ${body}`;
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: 'vulnscan: ' + command,
      output: fmtCmdOutput(result) || '(no output)',
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  if (type === 'search') {
    try {
      const r = await webSearch(body);
      return { label: 'web.search ' + body, output: renderSearchResults(r), exitCode: 0 };
    } catch (e) {
      return { label: 'web.search ' + body, output: 'Search error: ' + e.message, exitCode: 1 };
    }
  }

  if (type === 'fetch') {
    try {
      const p = await fetchUrl(body);
      return { label: 'web.fetch ' + body, output: renderPage(p), exitCode: 0 };
    } catch (e) {
      return { label: 'web.fetch ' + body, output: 'Fetch error: ' + e.message, exitCode: 1 };
    }
  }

  if (type === 'recon') {
    try {
      const r = await reconUrl(body);
      return { label: 'web.recon ' + body, output: renderRecon(r), exitCode: 0 };
    } catch (e) {
      return { label: 'web.recon ' + body, output: 'Recon error: ' + e.message, exitCode: 1 };
    }
  }

  if (type === 'tool') {
    // Look up the right Kali tool(s) for a need from the RAG index.
    const tools = await retrieveTools(body, 6);
    const output = tools.length
      ? tools.map((t) => `${t.name}${t.category ? ` [${t.category}]` : ''}: ${(t.summary || '').slice(0, 140)}${t.example ? `\n  e.g. ${t.example}` : ''}`).join('\n')
      : '(no matching tools indexed — run the tool index build first)';
    return { label: 'tool lookup: ' + body, output, exitCode: 0 };
  }

  if (type === 'browser') {
    // The AI's own headless browser — navigate & inspect live web apps.
    const r = await runBrowser(sessionId, body);
    return {
      label: 'browser: ' + body.split('\n')[0].slice(0, 80),
      output: fmtBrowser(r),
      exitCode: r.error && !r.url ? 1 : 0,
      screenshot: r.screenshot || null,
      pageUrl: r.url || null,
    };
  }

  if (type === 'wireless') {
    // body: either a raw aircrack-suite command, or "<action> [iface] [bssid] [channel]".
    let command = body;
    const known = /airmon|airodump|aireplay|aircrack|reaver|wifite|iw /i.test(body);
    if (!known) {
      const [action, iface, bssid, channel] = body.split(/\s+/);
      command = buildWirelessCommand({ action, iface, bssid, channel });
    }
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: 'wireless: ' + command,
      output: fmtCmdOutput(result) || '(no output)',
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  if (type === 'payload') {
    const spec = parsePayloadSpec(body);
    const p = generatePayload(spec);
    return { label: `payload: ${spec.type}${spec.language ? '/' + spec.language : ''}`, output: renderPayload(p), exitCode: p.error ? 1 : 0 };
  }

  if (type === 'report') {
    try {
      const session = await getSession(userId, sessionId);
      const findings = await listFindings(sessionId);
      const stats = await findingStats(sessionId);
      const { markdown, html, title } = await generateReport(session, findings, stats);
      const id = await saveReport(sessionId, userId, { title, markdown, html, stats });
      return {
        label: 'report: generated',
        output: `Report generated (${stats.total} findings). Download: /api/reports/${id}/download?format=html (or format=md)\n\n${markdown.slice(0, 1500)}`,
        exitCode: 0,
      };
    } catch (e) {
      return { label: 'report', output: 'Report error: ' + e.message, exitCode: 1 };
    }
  }

  return { label: type, output: 'Unknown tool', exitCode: 1 };
}

// Agent loop: model thinks -> emits tool blocks -> we run them -> feed output back ->
// repeat until the model stops requesting tools (or maxSteps reached).
// emit(event, data) streams SSE. Returns the canonical transcript to persist.
export async function runAgent({ history, sessionId, userId, emit, signal, memoryContext, autopilot }) {
  const working = [...history];
  let system = autopilot ? EXEC_SYSTEM + AUTOPILOT_PROMPT : EXEC_SYSTEM;
  if (memoryContext) system += '\n\n== RELEVANT MEMORY FROM EARLIER SESSIONS ==\n' + memoryContext;

  // Phase 20: ground the agent with the right Kali tools (RAG over the tool index).
  try {
    const goal = [...history].reverse().find((m) => m.role === 'user')?.content;
    if (goal) {
      const tools = await retrieveTools(goal, 6);
      if (tools.length) {
        const block = tools
          .map((t) => `- ${t.name}${t.category ? ` [${t.category}]` : ''}: ${(t.summary || '').slice(0, 120)}${t.example ? `\n  e.g. ${t.example}` : ''}`)
          .join('\n');
        system +=
          '\n\n== AVAILABLE KALI TOOLS (retrieved for this task) ==\n' +
          'Prefer these installed tools with their real flags. Verify with --help if unsure; never invent flags.\n' +
          block;
        emit?.('tools', { count: tools.length, names: tools.map((t) => t.name) });
      }
    }
  } catch {
    /* retrieval is best-effort */
  }
  const maxSteps = autopilot ? env.exec.maxStepsAutopilot : env.exec.maxSteps;
  let canonical = '';
  const append = (s) => {
    canonical += (canonical ? '\n\n' : '') + s;
  };

  for (let step = 0; step < maxSteps; step++) {
    const stepText = await streamChat({
      history: working,
      system,
      signal,
      onDelta: (text) => emit('delta', { text }),
    });

    working.push({ role: 'assistant', content: stepText });

    const cleaned = stripToolBlocks(stepText);
    if (cleaned) append(cleaned);

    const tools = parseToolBlocks(stepText);
    if (tools.length === 0) break;

    let observation = '';
    for (const tool of tools) {
      const firstLine = tool.body.split('\n')[0].slice(0, 100);
      const intent =
        tool.type === 'execute' ? '$ ' + firstLine : `${tool.type}: ${firstLine}`;
      emit('command', { command: intent });

      const r = await runTool(tool, { sessionId, userId });

      emit('command_result', {
        command: r.label,
        stdout: r.output,
        stderr: '',
        exitCode: r.exitCode,
        blocked: r.blocked || false,
      });

      if (r.findingsAdded > 0) emit('findings', { count: r.findingsAdded });
      // Live browser view for the UI panel.
      if (r.screenshot) emit('browser', { url: r.pageUrl, screenshot: r.screenshot });

      append(
        '```bash\n' + r.label + '\n```\n```text\n' + (r.output || '(no output)') + '\n```\n' +
          `_exit ${r.exitCode}${r.blocked ? ' · blocked by host guard' : ''}_` +
          (r.findingsAdded > 0 ? ` · 🎯 ${r.findingsAdded} finding(s)` : '')
      );

      observation += `${r.label}\n${r.output}\n[exit ${r.exitCode}]\n\n`;
      if (signal?.aborted) break;
    }

    if (signal?.aborted) break;

    working.push({ role: 'user', content: `Tool output:\n${observation.trim()}` });

    if (step === maxSteps - 1) {
      append(`_(reached max steps = ${maxSteps}; stopping.)_`);
    }
  }

  return canonical || '(no response)';
}

export { activeModel };
