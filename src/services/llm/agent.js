import { env } from '../../config/env.js';
import { streamChat, activeModel } from './index.js';
import { SYSTEM_PROMPT, EXEC_PROTOCOL_PROMPT, AUTOPILOT_PROMPT, EXEC_FORCE_PROMPT, THINKING_PROMPT, CONVERSATION_GUARD, VULN_FORCE_PROMPT } from './prompt.js';
import { renderCatalog } from '../exploit/knowledge.js';
import { runCommand } from '../exec/runner.js';
import { webSearch, renderSearchResults } from '../web/search.js';
import { fetchUrl, renderPage } from '../web/fetch.js';
import { reconUrl, renderRecon } from '../web/recon.js';
import { extractFindings, detectScanner } from '../scan/parsers.js';
import { extractWebFindings, detectWebScanner } from '../scan/webparsers.js';
import { extractWirelessFindings, buildWirelessCommand, isNoAdapter } from '../scan/wireless.js';
import { extractBluetoothFindings, buildBluetoothCommand, isNoBtAdapter } from '../scan/bluetooth.js';
import { buildGhostCommand, extractGhostFindings, isNoDevice, ghostLabel } from '../ghost/index.js';
import { buildAdCommand, extractAdFindings, isNoAd, adLabel } from '../ad/index.js';
import { cyclic, cyclicFind, renderTemplate, buildExploitDevCommand, xdevLabel } from '../exploitdev/index.js';
import { parsePasswords, checkMany, renderPwnedReport, pwnedLabel } from '../pwnedpass/index.js';
import { extractMitmFindings, buildMitmCommand } from '../scan/mitm.js';
import { gateAction } from '../authz/authz.js';
import { extractOsintFindings, buildOsintCommand, buildOsintSweep, renderOsint, sniffKind } from '../osint/osint.js';
import { parseArtifactSpec, generateArtifactFile, humanSize } from '../artifacts/generate.js';
import { saveArtifact } from '../../db/artifacts.repo.js';
import { buildVulnCommand, buildOwaspScan, extractExploitFindings, renderVulnLookup } from '../exploit/exploit.js';
import { bestMatch } from '../exploit/knowledge.js';
import { buildAppsecCommand, extractAppsecFindings, summarizeSbom, remediationFor, generateCicdPipeline, SCANNER_AREAS, ALL_AREAS, AREAS } from '../appsec/index.js';
import { buildCloudCommand, extractCloudFindings, renderCloud } from '../cloud/index.js';
import { buildWebSecretsCommand, extractWebSecretsFindings, renderWebSecrets } from '../websecrets/index.js';
import { buildBucketCommand, extractBucketFindings, renderBuckets } from '../buckets/index.js';
import { buildIamCommand, extractIamFindings, renderIam } from '../iam/index.js';
import { buildDefaultCredsCommand, extractDefaultCredsFindings, renderDefaultCreds } from '../defaultcreds/index.js';
import { buildExposedCommand, extractExposedFindings, renderExposed } from '../exposed/index.js';
import { buildFirewallCommand, extractFirewallFindings, renderFirewall } from '../firewall/index.js';
import { buildSvcAuditCommand, extractSvcAuditFindings, renderSvcAudit } from '../svcaudit/index.js';
import { buildWebInputCommand, extractWebInputFindings, renderWebInput } from '../webinput/index.js';
import { buildApiDiscoverCommand, extractApiDiscoverFindings, renderApiDiscover } from '../apidiscover/index.js';
import { buildAuthSessionCommand, extractAuthSessionFindings, renderAuthSession } from '../authsession/index.js';
import { buildReconScanCommand, extractReconScanFindings, renderReconScan } from '../recon/index.js';
import { buildLoginBypassCommand, extractLoginBypassFindings, renderLoginBypass } from '../loginbypass/index.js';
import { parseNetexec } from '../netexec/index.js';
import { parseZap } from '../zap/index.js';
import { parseContentDisc } from '../scan/contentdisc.js';
import { parseDnsenum } from '../scan/dnsenum.js';
import { parseJohn } from '../scan/john.js';
import { buildSniffCommand, parseTshark } from '../scan/tshark.js';
import { renderMenu, pickAttack, parseMsfArgs, buildAttack, msfconsoleCmd, detectIpCommand, parseMsf, ENSURE_MSF } from '../metasploit/index.js';
import { startJob, readJob, writeJob, stopJob, listJobs, updateJobMeta } from '../exec/jobs.js';
import { detectLiveCommand, liveLabel } from '../exec/livetools.js';
import { renderSetMenu, pickSetVector, buildSetCommand, parseSet } from '../set/index.js';
import { buildHoundCommand, extractHoundLink, parseHound } from '../hound/index.js';
import { buildCamphishCommand, extractCamphishLink, parseCamphish, pickTemplate, CAMPHISH_TEMPLATES } from '../camphish/index.js';
import { runDorkSweep, renderDork } from '../dork/index.js';
import { renderHashid } from '../hashid/index.js';
import { runShodan, renderShodan, shodanFindings } from '../shodan/index.js';
import { retrieveTools } from '../tools/index.js';
import { runBrowser, fmtBrowser } from '../browser/browser.js';
import { enrichCvss } from '../scan/cvss.js';
import { generatePayload, renderPayload, parsePayloadSpec } from '../payloads/templates.js';
import { generateReport } from '../report/generate.js';
import { logCommand } from '../../db/commands.repo.js';
import { addFindings, listFindings, findingStats, updateFinding } from '../../db/findings.repo.js';
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

// EXEC_FORCE_PROMPT forces the model to actually RUN commands (via ```execute blocks) and never
// simulate; THINKING_PROMPT makes it narrate a plan + per-step analysis so the user sees progress.
const EXEC_SYSTEM = SYSTEM_PROMPT + EXEC_PROTOCOL_PROMPT + shellNote(env.exec.shell) + EXEC_FORCE_PROMPT + THINKING_PROMPT + CONVERSATION_GUARD;

// ---- Anti-simulation guard ----
// Fires when a step emits NO tool block but looks like it simulated output or merely listed
// commands. We then re-prompt the model to run for real (bounded retries).
const SIM_RE = /\bsimulat(?:e|ed|es|ion|ing)\b|\bhypothetical\b|assume the (?:out|res|scan)|simulated output|for demonstration|for educational purposes only/i;
// Only treat it as "listed a command but didn't run it" when the model actually put a command in a
// fenced shell block. A bare tool name in a PROSE explanation (e.g. answering "what is nmap?") must
// NOT force execution — that would break normal Q&A / the conversation guard.
const CMD_HINT_RE = /```(?:bash|sh|shell|console|terminal)\b/im;
const ANTI_SIM_NUDGE =
  'STOP — you did NOT run anything, you only described or simulated it. This is a REAL Kali ' +
  'Docker container with real tools and network access. Do NOT simulate, do NOT print bullet-list ' +
  'steps, do NOT fabricate output. Emit exactly ONE real ```execute (or ```scan / ```vulnscan / ' +
  '```recon) block NOW and run the actual command. Then wait for the real output.';

// Tool output fed BACK to the model must be bounded or the context explodes — a single
// `curl` of a web page can be 100k+ tokens → 400 "maximum context length is 131072 tokens".
// The UI and DB keep the FULL output; the model only needs a head+tail slice to reason from.
const MODEL_OBS_MAX = 6000; // chars per tool output sent to the model
const OBS_TOTAL_MAX = 14000; // chars for a whole step's combined observation
function clampForModel(text) {
  const s = String(text || '');
  if (s.length <= MODEL_OBS_MAX) return s;
  const head = s.slice(0, 4200);
  const tail = s.slice(-1500);
  return `${head}\n\n…[${s.length - head.length - tail.length} chars truncated to fit model context]…\n\n${tail}`;
}

// Keep the working history within the context window: preserve the first user message (the
// goal) and drop the OLDEST middle exchanges when the total gets large (~90k tokens of chars).
const HISTORY_MAX_CHARS = 360_000;
function trimHistory(msgs) {
  let total = msgs.reduce((n, m) => n + (m.content?.length || 0), 0);
  if (total <= HISTORY_MAX_CHARS) return;
  // msgs[0] is the original user goal — always keep it; trim from index 1 forward.
  while (total > HISTORY_MAX_CHARS && msgs.length > 3) {
    const removed = msgs.splice(1, 1)[0];
    total -= removed.content?.length || 0;
  }
}

// Engages VULN_FORCE_PROMPT + the CVE/CWE catalogue when the user's goal is about vulns/exploits.
const VULN_ENGAGE_RE =
  /\b(vuln\w*|exploit\w*|cve[-\s]?\d+|cwe[-\s]?\d+|owasp|metasploit|payload|reverse[-\s]?shell|rce|lfi|rfi|sql[\s-]?inj\w*|sqli|xss|csrf|ssrf|idor|deserial\w*|priv(?:ilege)?[-\s]?esc\w*|shellshock|log4shell|eternalblue|bluekeep|proxylogon|zerologon|spring4shell|heartbleed|dirty[-\s]?(?:cow|pipe)|drupalgeddon|meltdown|spectre|follina|printnightmare|citrix[-\s]?bleed|baron[-\s]?samedit|regresshion)\b/i;

const TOOL_TYPES = ['execute', 'search', 'fetch', 'recon', 'scan', 'vulnscan', 'wireless', 'bluetooth', 'ghost', 'ad', 'exploitdev', 'pwnedpass', 'mitm', 'sniff', 'osint', 'exploit', 'msf', 'set', 'hound', 'camphish', 'owasp', 'artifact', 'file', 'tool', 'browser', 'payload', 'report', 'dork', 'hashid', 'shodan',
  // AppSec / DevSecOps code-security suite (each its own tag):
  ...ALL_AREAS,
  // Cloud & infrastructure security posture (Phase 1+):
  'cloud', 'websecrets', 'buckets', 'iam', 'defaultcreds', 'exposed', 'firewall', 'svcaudit', 'webinput', 'apidiscover', 'authsession', 'loginbypass'];
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
      ...extractBluetoothFindings(command, out),
      ...extractGhostFindings(command, out),
      ...extractAdFindings(command, out),
      ...extractMitmFindings(command, out),
      ...extractOsintFindings(command, out),
      ...extractExploitFindings(command, out),
      ...extractAppsecFindings(command, out),
      ...extractCloudFindings(command, out),
      ...extractWebSecretsFindings(command, out),
      ...extractBucketFindings(command, out),
      ...extractIamFindings(command, out),
      ...extractDefaultCredsFindings(command, out),
      ...extractExposedFindings(command, out),
      ...extractFirewallFindings(command, out),
      ...extractSvcAuditFindings(command, out),
      ...extractWebInputFindings(command, out),
      ...extractApiDiscoverFindings(command, out),
      ...extractAuthSessionFindings(command, out),
      ...extractReconScanFindings(command, out),
      ...extractLoginBypassFindings(command, out),
      ...parseNetexec(command, out),
      ...parseZap(command, out),
      ...parseContentDisc(command, out),
      ...parseDnsenum(command, out),
      ...parseJohn(command, out),
      ...parseTshark(command, out),
      ...parseMsf(command, out),
      ...parseSet(command, out),
      ...parseHound(command, out),
      ...parseCamphish(command, out),
    ];
    if (items.length) findingsAdded = await addFindings(sessionId, userId, items.map(enrichCvss));
  } catch (e) {
    console.warn('finding extraction failed:', e.message);
  }
  return { result, findingsAdded };
}

// Run a single tool block; returns { label, output, exitCode, findingsAdded }.
async function runTool({ type, body }, { sessionId, userId }) {
  // Authorization gate: offensive actions only run against a target the operator has attested to
  // (own asset / written scope) for this session. Unauthorized → blocked here, audit-logged, and
  // NOTHING runs. The AI cannot self-authorize; only an operator `/authorize` message grants it.
  const gate = await gateAction({ type, body, sessionId, userId });
  if (gate.blocked) {
    return { label: `⛔ authorization required: ${gate.target}`, output: gate.message, exitCode: 126, blocked: true };
  }

  if (type === 'execute') {
    // STRONGLY-BOUND live sessions: if this is a listener / capture / tunnel / interactive console (any Kali
    // tool that must stay alive for a callback), run it as a PERSISTENT job = a Live Hack Environment, not a
    // one-shot (which would block/time out). Auto-opens the panel + AI management box. Gating already ran above.
    const live = detectLiveCommand(body);
    if (live.live) {
      const label = liveLabel(body, live.kind);
      const job = await startJob({ command: body, sessionId, userId, label, kind: live.kind, live: true, interactive: live.interactive });
      return {
        label: '$ ' + body,
        output: `▶️ **Live session started** — ${live.why} (job \`${job.id}\`).\n\nA Live Hack Environment opened below. Just tell the management box in plain language what to show or do (e.g. ${live.interactive ? '"run whoami in the shell", "show me the session"' : '"any callbacks yet?", "show me the captured data"'}) and I'll operate it for you — or use raw stdin.`,
        exitCode: 0, jobId: job.id, live: true, kind: live.kind, envLabel: label,
      };
    }
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
    // Bare target -> a clean, parseable nuclei run. -silent gives the compact "[id] [proto] [severity] url"
    // format (parseNuclei handles it AND JSON) — far more readable than -j, which embeds the full HTTP
    // response per line. Rate-limited, no update-check spam, per-host timeout. nuclei v3 auto-downloads its
    // ~13k templates on first run if missing. If the model passes a full scanner command, run it as-is.
    const command = detectWebScanner(body) ? body : `nuclei -u ${body} -silent -duc -rl 150 -timeout 8`;
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
    // Strengthened recon: run the network-level FOOTPRINT in the sandbox (DNS records, AXFR, SPF/DMARC,
    // crt.sh + wordlist subdomains resolved to live assets, ASN/CDN, tech fingerprint, ports) AND merge the
    // JS page/endpoint recon. The footprint flows through runAndCapture so its findings are auto-extracted.
    const parts = [];
    let findingsAdded = 0;
    const command = buildReconScanCommand(body);
    if (command) {
      try {
        const { result, findingsAdded: fa } = await runAndCapture(command, { sessionId, userId });
        findingsAdded += fa || 0;
        const fp = renderReconScan(fmtCmdOutput(result));
        if (fp) parts.push('### Network footprint\n' + fp);
      } catch (e) {
        parts.push('_footprint error: ' + e.message + '_');
      }
    }
    // JS page + JS-endpoint recon (tech, routes, emails, IPs from the live page).
    const first = String(body || '').split(/\s+/)[0] || body;
    const jsTarget = /^https?:\/\//i.test(first) ? first : 'https://' + first;
    try {
      const r = await reconUrl(jsTarget);
      parts.push('### Page & JS recon\n' + renderRecon(r));
    } catch (e) {
      parts.push('_page-recon note: ' + e.message + '_');
    }
    return { label: 'recon ' + body, output: parts.join('\n\n') || 'Recon produced no output.', exitCode: 0, findingsAdded };
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
    const known = /airmon|airodump|aireplay|aircrack|reaver|wash|wifite|iw /i.test(body);
    if (!known) {
      const [action, iface, bssid, channel] = body.split(/\s+/);
      command = buildWirelessCommand({ action, iface, bssid, channel });
    }
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    const rawOut = fmtCmdOutput(result) || '(no output)';
    // If there's no real radio, return the HONEST hardware message — never let the model present a fake AP list.
    const noAdapter = isNoAdapter(`${result.stdout || ''}\n${result.stderr || ''}\n${rawOut}`);
    const output = noAdapter
      ? '⚠️ NO WIRELESS ADAPTER on the exec backend — this is REAL output, not a scan.\n' + rawOut +
        '\n\n[Do NOT invent access points. Real Wi-Fi scan/deauth/capture needs a monitor-mode USB adapter physically attached to the machine running the exec backend, within range of the target. Attach one (e.g. Alfa AWUS036ACH) and run the exec backend on that local machine (EXEC_BACKEND=host or ssh to a local Kali box), then retry.]'
      : rawOut;
    return {
      label: 'wireless: ' + command.split('\n')[0].slice(0, 60),
      output,
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
      noAdapter,
    };
  }

  // ```sniff <action> [pcap|iface] [filter] -> tshark packet capture & analysis. action = capture|creds|
  // http|dns|hosts|protocols|read|info. Extracts cleartext creds from traffic. Offline pcap analysis works
  // anywhere; live capture needs a network interface + NET_RAW (the sandbox has it; desktop = real machine).
  if (type === 'sniff') {
    let command = body.trim();
    const known = /tshark|dumpcap|tcpdump|capinfos|editcap|mergecap/i.test(command);
    if (!known) {
      const parts = command.split(/\s+/);
      const action = (parts[0] || 'info').toLowerCase();
      // 2nd token: an iface for capture, else a pcap path; rest = display filter (for read)
      const isCapture = action === 'capture';
      const arg = parts[1];
      const rest = parts.slice(2).join(' ');
      command = buildSniffCommand({
        action,
        iface: isCapture ? arg : undefined,
        pcap: !isCapture && arg && arg !== '-' ? arg : undefined,
        count: isCapture ? parts[2] : undefined,
        filter: action === 'read' ? rest : undefined,
      });
    }
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    const rawOut = fmtCmdOutput(result) || '(no output)';
    const noCap = /SNIFF-NOCAPTURE/.test(`${result.stdout || ''}${result.stderr || ''}${rawOut}`);
    const output = noCap
      ? '⚠️ NO CAPTURE INTERFACE on the exec backend — REAL output, not a capture.\n' + rawOut +
        '\n\n[Live packet capture needs a network interface + NET_RAW (or run the exec backend on the local/desktop machine). Offline analysis of an existing .pcap (```sniff read/http/creds <file>) works anywhere.]'
      : rawOut;
    return {
      label: 'sniff: ' + command.split('\n')[0].slice(0, 60),
      output,
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  if (type === 'bluetooth') {
    // body: a raw hcitool/bluesnarfer/l2ping/sdptool command, OR "<action> [mac] [chan] [arg...]" where action =
    // check|scan|lescan|info|services|ping|info-snarf|contacts|calls|search|delete|list-storage|custom|flood.
    // The adapter is AUTO-DETECTED (hci0/hci1/USB dongle); no radio -> honest BT-NOADAPTER (never fabricated).
    let command = body.trim();
    const known = /hcitool|bluesnarfer|l2ping|sdptool|bluetoothctl|hciconfig/i.test(command);
    if (!known) {
      const parts = command.split(/\s+/);
      const [action, mac, chan] = parts;
      const rest = parts.slice(3).join(' ');
      // arg after chan means different things per action
      const opts = { action, mac, chan: chan || undefined };
      if (action === 'search') opts.name = rest || undefined;
      else if (action === 'custom') opts.atcmd = rest || undefined;
      else if (action === 'calls' || action === 'contacts' || action === 'snarf') {
        // "<range> [TYPE]" e.g. "1-50 DC"
        const [range, t] = rest.split(/\s+/);
        if (range) opts.range = range;
        if (t) opts.type = t;
      } else if (rest) opts.range = rest;
      command = buildBluetoothCommand(opts);
    }
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    const rawOut = fmtCmdOutput(result) || '(no output)';
    const noAdapter = isNoBtAdapter(`${result.stdout || ''}\n${result.stderr || ''}\n${rawOut}`);
    const output = noAdapter
      ? '⚠️ NO BLUETOOTH ADAPTER on the exec backend — this is REAL output, not a scan.\n' + rawOut +
        '\n\n[Do NOT invent Bluetooth devices, MACs, contacts or call logs. Real BT recon/snarf needs a Bluetooth radio physically attached to the machine running the exec backend, near the target. Run the exec backend on that local/desktop machine (or EXEC_BACKEND=ssh to a Kali box with an adapter), then retry.]'
      : rawOut;
    return {
      label: 'bluetooth: ' + body.split('\n')[0].slice(0, 80),
      output,
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
      noAdapter,
    };
  }

  if (type === 'ghost') {
    // Ghost — Android remote access over ADB (modeled on Ghost Framework). body: a raw adb command, OR
    // "<action> [target] [arg] [arg2]" where action = check|scan|connect|disconnect|devices|shell|sysinfo|
    // screenshot|screenrecord|pull|apps|install|uninstall|run|logcat|battery|network|wifi|macinet|wpa|
    // extract-apk|current|input|forward|reboot|shutdown|unlock. Target = device IP[:5555] (or CIDR for scan).
    let command = body.trim();
    const known = /^\s*(adb|nmap)\b/i.test(command);
    if (!known) {
      const parts = command.split(/\s+/);
      const [action, target, arg, ...restArr] = parts;
      const rest = restArr.join(' ');
      // `shell` takes a free-form command as its arg; others take discrete tokens.
      const opts = action === 'shell'
        ? { action, target, arg: [arg, rest].filter(Boolean).join(' ') }
        : { action, target, arg, arg2: rest || undefined };
      command = buildGhostCommand(opts);
    }
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    const rawOut = fmtCmdOutput(result) || '(no output)';
    const noDevice = isNoDevice(`${result.stdout || ''}\n${result.stderr || ''}\n${rawOut}`);
    const output = noDevice
      ? '⚠️ NO REACHABLE ANDROID DEVICE over ADB — this is REAL output, not a scan.\n' + rawOut +
        '\n\n[Do NOT invent device data (model, files, screenshots, apps). Ghost needs the target to have ADB-over-network enabled with tcp:5555 reachable from the exec backend (or a USB device on the backend machine). Run the exec backend on the desktop app / same LAN as the target, then retry.]'
      : rawOut;
    return {
      label: ghostLabel(body),
      output,
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
      noDevice,
    };
  }

  if (type === 'ad') {
    // Active Directory attack-path (BloodHound/impacket). body: a raw command, OR
    // "<action> [domain] [k=v ...]" where action = check|collect|analyze|kerberoast|asreproast|dcsync and
    // k=v ∈ u=<user> p=<pass> dc=<dc-ip> ns=<dc-ip> file=<path>.
    let command = body.trim();
    const known = /^\s*(bloodhound-python|impacket-|GetUserSPNs|GetNPUsers|secretsdump|python3?\s)/i.test(command);
    if (!known) {
      const tokens = command.split(/\s+/);
      const action = tokens.shift();
      const opts = { action };
      for (const tok of tokens) {
        const kv = /^([a-z]+)=(.+)$/i.exec(tok);
        if (kv) {
          const k = kv[1].toLowerCase();
          if (k === 'u' || k === 'user') opts.user = kv[2];
          else if (k === 'p' || k === 'pass') opts.pass = kv[2];
          else if (k === 'dc' || k === 'ns' || k === 'dcip') { opts.dc = opts.dc || kv[2]; opts.dcip = kv[2]; }
          else if (k === 'file') opts.file = kv[2];
          else if (k === 'domain' || k === 'd') opts.domain = kv[2];
        } else if (!opts.domain) opts.domain = tok; // first positional = domain
      }
      command = buildAdCommand(opts);
    }
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    const rawOut = fmtCmdOutput(result) || '(no output)';
    const noAd = isNoAd(`${result.stdout || ''}\n${result.stderr || ''}\n${rawOut}`);
    const output = noAd
      ? '⚠️ NO AD DATA / DC UNREACHABLE — this is REAL output, not analysis.\n' + rawOut +
        '\n\n[Do NOT invent users, groups, hashes or attack paths. AD enumeration needs valid domain creds + network line-of-sight to a DC (LDAP/389, SMB/445, Kerberos/88). Run the exec backend on a host that can reach the DC, then retry.]'
      : rawOut;
    return {
      label: adLabel(body),
      output,
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
      noAd,
    };
  }

  if (type === 'exploitdev') {
    // Custom exploit dev. body: "<action> [args]" where action = pattern|offset|template|checksec|compile|
    // gadgets|shellcode. pattern/offset/template are pure computation (instant, no shell, no target).
    const raw = body.trim();
    const tokens = raw.split(/\s+/);
    const action = (tokens[0] || '').toLowerCase();

    if (action === 'pattern') {
      const len = parseInt(tokens[1], 10) || 200;
      const patt = cyclic(len);
      return { label: xdevLabel(body), output: `cyclic pattern (length ${patt.length}, pwntools-compatible):\n${patt}`, exitCode: 0, findingsAdded: 0 };
    }
    if (action === 'offset') {
      const off = cyclicFind(tokens[1] || '');
      const out = off < 0
        ? `offset: value "${tokens[1]}" not found in the cyclic pattern (is it the exact EIP/RIP crash value?).`
        : `offset: ${off}   (the ${off}-byte prefix before you control EIP/RIP — set OFFSET=${off})`;
      return { label: xdevLabel(body), output: out, exitCode: 0, findingsAdded: 0 };
    }
    if (action === 'template') {
      const lang = tokens[1] || 'python';
      const vuln = tokens[2] || 'bof';
      return { label: xdevLabel(body), output: renderTemplate(lang, vuln, {}), exitCode: 0, findingsAdded: 0 };
    }

    // Shell helpers (checksec/compile/gadgets/shellcode).
    let command = raw;
    if (!/^\s*(gcc|go\s+build|checksec|ROPgadget|msfvenom|file\s|python3?\s)/i.test(raw)) {
      command = buildExploitDevCommand({
        action,
        file: tokens[1],
        out: action === 'compile' ? tokens[2] : undefined,
        arch: action === 'shellcode' ? tokens[1] : undefined,
        lhost: action === 'shellcode' ? tokens[2] : undefined,
        lport: action === 'shellcode' ? tokens[3] : undefined,
      });
    }
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return { label: xdevLabel(body), output: fmtCmdOutput(result) || '(no output)', exitCode: result.exitCode, blocked: result.blocked, findingsAdded };
  }

  if (type === 'mitm') {
    // body: "<action> [target] [gateway] [iface] [site] [port] [dns] [duration]"
    //   action = scan|arp|dns|phish|full|auto|cleanup|setup
    //   target = victim IP
    //   gateway = network gateway IP
    //   iface = network interface (wlan0, eth0)
    //   site = google|facebook|instagram|linkedin (for phish/full/auto)
    //   port = phishing server port
    //   dns = all or comma-separated domains
    //   duration = attack duration in seconds (0 = run until stopped)
    // Also accepts a raw python command path (passed through).
    let raw = body.trim();
    const known = /mitm_agent|phish_with_mitm|arpspoof|dnsmasq/i.test(raw);
    let command;
    if (known) {
      command = raw;
    } else {
      const [action, target, gateway, iface, site, port, dns, duration] = raw.split(/\s+/);
      command = buildMitmCommand({
        action: action || 'full',
        target, gateway, iface, site,
        port: port ? parseInt(port) : undefined,
        dns, duration: duration ? parseInt(duration) : 0,
      });
    }
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: 'mitm: ' + command,
      output: fmtCmdOutput(result) || '(no output)',
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  if (type === 'osint') {
    // body: a raw OSINT tool command, OR "<target>" / "<type> <target> [tool]" where type =
    // email|username|phone|domain|auto. Default = a deterministic multi-tool SWEEP that ALWAYS returns
    // actionable dork/lookup leads (never "just a country code"), plus runs the right CLI tools.
    let command = body.trim();
    const known = /theharvester|holehe|sherlock|maigret|h8mail|phoneinfoga|recon-ng|dnsrecon|sublist3r|whois|amass|curl|nslookup|dig/i.test(command);
    if (!known) {
      const parts = command.split(/\s+/);
      let kind = 'auto';
      let target = parts[0];
      let toolName;
      if (['email', 'username', 'phone', 'domain', 'auto'].includes((parts[0] || '').toLowerCase())) {
        kind = parts[0].toLowerCase();
        target = parts[1];
        toolName = parts[2];
      }
      // A forced single tool -> that tool; otherwise the full sweep.
      command = toolName ? buildOsintCommand({ target, type: kind, tool: toolName }) : buildOsintSweep({ target, type: kind });
    }
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: 'osint: ' + body.split('\n')[0].slice(0, 80),
      output: renderOsint(fmtCmdOutput(result)) || '(no output)',
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  if (type === 'artifact' || type === 'file') {
    // Generate a REAL downloadable file (txt/csv/json/xlsx/docx/pdf/…) from the AI's content,
    // or pull one the agent already made in the sandbox. Returns a working download link.
    try {
      const spec = parseArtifactSpec(body);
      const gen = await generateArtifactFile(spec, { sessionId });
      const id = await saveArtifact({
        sessionId, userId, name: gen.name, format: gen.ext, mime: gen.mime, sizeBytes: gen.sizeBytes, path: gen.storedPath,
      });
      const sizeHuman = humanSize(gen.sizeBytes);
      return {
        label: `artifact: ${gen.name}`,
        output: `File "${gen.name}" (${gen.ext.toUpperCase()}, ${sizeHuman}) is ready and its download link was delivered to the user. Do NOT paste the file contents again.`,
        exitCode: 0,
        artifact: { id, name: gen.name, url: `/api/artifacts/${id}/download`, format: gen.ext, mime: gen.mime, sizeBytes: gen.sizeBytes, sizeHuman },
      };
    } catch (e) {
      return { label: 'artifact', output: 'Artifact error: ' + e.message, exitCode: 1 };
    }
  }

  if (type === 'exploit') {
    // body: "<mode> <vuln-or-cve> <target> [lhost] [lport]" where mode = info|detect|exploit.
    //   info  -> just return the KB entry (detect + exploit + remediation), runs nothing.
    //   detect/exploit -> build + run the real command (msf/nuclei/searchsploit/PoC).
    // Also accepts a raw msfconsole/nuclei/searchsploit command (passed through).
    const raw = body.trim();
    const known = /^(msfconsole|nuclei|searchsploit|sqlmap|nikto|commix|dalfox|hydra)\b/i.test(raw);
    if (known) {
      const { result, findingsAdded } = await runAndCapture(raw, { sessionId, userId });
      return { label: 'exploit: ' + raw.split('\n')[0].slice(0, 80), output: fmtCmdOutput(result) || '(no output)', exitCode: result.exitCode, blocked: result.blocked, findingsAdded };
    }
    const parts = raw.split(/\s+/);
    let mode = 'detect';
    if (['info', 'detect', 'exploit'].includes((parts[0] || '').toLowerCase())) mode = parts.shift().toLowerCase();
    // vuln query may be a CVE id or a multi-word name; target is the last token that looks like a host/URL.
    let target;
    let lhost;
    let lport;
    // Pull trailing tokens: [target] [lhost] [lport] — target is the first token containing a . or ://
    const idx = parts.findIndex((p) => /(:\/\/|\.\d|\.[a-z]{2,}|^\d+\.\d+\.\d+\.\d+$)/i.test(p));
    let vuln = raw;
    if (idx >= 0) {
      vuln = parts.slice(0, idx).join(' ') || parts[idx];
      target = parts[idx];
      lhost = parts[idx + 1];
      lport = parts[idx + 2];
    } else {
      vuln = parts.join(' ');
    }

    if (mode === 'info') {
      return { label: 'exploit info: ' + vuln, output: renderVulnLookup(vuln), exitCode: 0 };
    }
    if (!target) {
      const hit = bestMatch(vuln);
      return { label: 'exploit: ' + vuln, output: `No target given. Usage: \`${mode} ${vuln} <target> [lhost] [lport]\`.\n\n` + renderVulnLookup(vuln) + (hit ? '' : ''), exitCode: 1 };
    }
    const built = buildVulnCommand(vuln, { target, lhost, lport, mode });
    const { result, findingsAdded } = await runAndCapture(built.command, { sessionId, userId });
    const head = `${mode.toUpperCase()} ${built.entry ? (built.entry.cve || built.entry.cwe) + ' ' + built.entry.name : vuln} → ${target}`;
    return {
      label: 'exploit: ' + head,
      output: (built.note ? `[${built.note}]\n\n` : '') + (fmtCmdOutput(result) || '(no output)'),
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  // ```msf — Metasploit made simple: the user picks an attack by number (or describes it) and the AI performs
  // it. Generates the msfvenom payload with the OPERATOR'S OWN IP (to test on their own device), and starts
  // the multi/handler as a PERSISTENT background job so the session stays alive. Sub-commands: menu | ip |
  // sessions | read <job> | send <job> <cmd> | stop <job> | <number|desc> [lhost=..] [lport=..] [rhost=..].
  if (type === 'msf') {
    const raw = body.trim();
    const parts = raw.split(/\s+/);
    const first = (parts[0] || '').toLowerCase();

    if (!raw || first === 'menu' || first === 'help' || first === 'list-attacks')
      return { label: 'msf: menu', output: renderMenu(), exitCode: 0 };

    if (['ip', 'detect-ip', 'myip', 'lhost'].includes(first)) {
      const { result } = await runAndCapture(detectIpCommand(), { sessionId, userId });
      return { label: 'msf: detect-ip', output: 'Your reachable IPs — pick one as LHOST (LAN IP to test on a device on the same network):\n\n' + (fmtCmdOutput(result) || ''), exitCode: 0 };
    }

    if (['sessions', 'jobs', 'listeners'].includes(first)) {
      const jl = listJobs({ sessionId });
      const out = jl.length ? jl.map((j) => `• [${j.status}] \`${j.id}\` — ${j.label} (${j.backend})`).join('\n') : '(no listeners / background jobs running)';
      return { label: 'msf: sessions', output: '**Live background jobs / listeners:**\n' + out + '\n\nUse ```msf read <id> to view live output, ```msf send <id> <cmd> to type into it, ```msf stop <id> to kill it.', exitCode: 0 };
    }
    if (first === 'read' && parts[1]) {
      const r = readJob(parts[1], 0);
      if (r.error) return { label: 'msf: read', output: r.error, exitCode: 1 };
      return { label: 'msf: read ' + parts[1], output: `**[${r.status}] ${r.label}** (${r.backend})\n\`\`\`\n${(r.text || '(no output yet)').slice(-4000)}\n\`\`\``, exitCode: 0 };
    }
    if (first === 'send' && parts[1]) {
      const r = writeJob(parts[1], parts.slice(2).join(' '));
      return { label: 'msf: send', output: r.ok ? `sent to job ${parts[1]}` : (r.error || 'error'), exitCode: r.ok ? 0 : 1 };
    }
    if (first === 'stop' && parts[1]) {
      const r = stopJob(parts[1]);
      return { label: 'msf: stop', output: r.ok ? `🛑 stopped job ${parts[1]}` : (r.error || 'error'), exitCode: r.ok ? 0 : 1 };
    }

    // Raw passthrough: msfconsole -> persistent job; msfvenom -> generate the payload.
    if (/^msfconsole\b/i.test(raw)) {
      const job = await startJob({ command: ENSURE_MSF + raw, sessionId, userId, label: 'msfconsole', kind: 'msf' });
      return { label: 'msf: msfconsole', output: `▶️ Started msfconsole as a live session \`${job.id}\` (stays alive). A live session opened below — type Metasploit commands there or just tell it what to do.`, exitCode: 0, jobId: job.id, live: true, kind: 'msf', envLabel: 'msfconsole' };
    }
    if (/^msfvenom\b/i.test(raw)) {
      const { result, findingsAdded } = await runAndCapture(raw, { sessionId, userId });
      return { label: 'msf: msfvenom', output: fmtCmdOutput(result) || '(no output)', exitCode: result.exitCode, findingsAdded };
    }

    // Attack selection: a number or a description, + lhost/lport/rhost.
    const item = pickAttack(first === 'payload' || first === 'exploit' || first === 'attack' ? parts.slice(1).join(' ') : raw);
    if (!item) return { label: 'msf', output: `Couldn't match that to an attack. Here's the menu:\n\n${renderMenu()}`, exitCode: 1 };
    const args = parseMsfArgs(parts);
    const plan = buildAttack(item, args);

    // Exploit path targets a remote RHOST -> gate it (authorization required).
    if (plan.kind === 'exploit') {
      if (!args.rhost) return { label: 'msf: ' + item.name, output: `**${item.name}**\n${plan.note}\n\nUsage: \`\`\`msf ${item.id} rhost=<target> lhost=<your-ip> lport=4444`, exitCode: 1 };
      const g = await gateAction({ type: 'exploit', body: args.rhost, sessionId, userId });
      if (g.blocked) return { label: `⛔ authorization required: ${args.rhost}`, output: g.message, exitCode: 126, blocked: true };
      const job = await startJob({ command: msfconsoleCmd(plan.resource), sessionId, userId, label: `exploit ${item.name} -> ${args.rhost}`, kind: 'msf' });
      return { label: 'msf: ' + item.name, output: `▶️ Launched **${item.name}** against \`${args.rhost}\` as a live session \`${job.id}\` (handler stays alive).\n\n${plan.note}\n\nA live session opened below — tell it "list sessions / interact with session 1".`, exitCode: 0, jobId: job.id, live: true, kind: 'msf', envLabel: `exploit ${item.name}` };
    }

    // Handler-only path: start the persistent listener.
    if (plan.kind === 'handler') {
      const job = await startJob({ command: msfconsoleCmd(plan.handler), sessionId, userId, label: `handler :${plan.lport}`, kind: 'msf' });
      return { label: 'msf: handler', output: `🎧 Started a persistent handler on \`0.0.0.0:${plan.lport}\` as a live session \`${job.id}\`.\n${plan.note}\n\nA live session opened below — it'll show incoming sessions; tell it "interact with session 1" when one lands.`, exitCode: 0, jobId: job.id, live: true, kind: 'msf', envLabel: `handler :${plan.lport}` };
    }

    // Payload path: (1) generate the payload with the user's IP, (2) start the matching handler as a job.
    const { result: venomRes } = await runAndCapture(ENSURE_MSF + plan.venom, { sessionId, userId });
    const job = await startJob({ command: msfconsoleCmd(plan.handler), sessionId, userId, label: `handler :${plan.lport} (${item.name})`, kind: 'msf' });
    const lines = [
      `**${item.name}** — payload built with LHOST \`${plan.lhost}\` LPORT \`${plan.lport}\``,
      '```', plan.venom, '```',
      fmtCmdOutput(venomRes)?.trim() ? `→ ${fmtCmdOutput(venomRes).trim().split('\n').slice(-3).join('\n')}` : '',
      `\n🎧 Handler running as a live session \`${job.id}\` (stays alive). A live session opened below — when the payload runs on the target, tell it "interact with session 1".`,
      `\n${plan.note}`,
    ].filter(Boolean);
    return { label: 'msf: ' + item.name, output: lines.join('\n'), exitCode: 0, jobId: job.id, live: true, kind: 'msf', envLabel: `${item.name} handler` };
  }

  // ```set — the Social-Engineer Toolkit, made simple. The user picks a social-engineering attack (number or
  // description) and the AI performs it: QR codes, payloads, credential-harvester phishing sites, powershell
  // shells, etc. SET is driven non-interactively (menu answers piped in). Cloned-site/harvester listeners run
  // as PERSISTENT background jobs so the phishing page stays alive to capture victims. Sub: menu | ip | <sel>.
  if (type === 'set') {
    const raw = body.trim();
    const parts = raw.split(/\s+/);
    const first = (parts[0] || '').toLowerCase();
    if (!raw || first === 'menu' || first === 'help') return { label: 'set: menu', output: renderSetMenu(), exitCode: 0 };
    if (['ip', 'detect-ip', 'myip'].includes(first)) {
      const { result } = await runAndCapture(detectIpCommand(), { sessionId, userId });
      return { label: 'set: detect-ip', output: 'Your reachable IPs — pick one as LHOST / the harvester post-back:\n\n' + (fmtCmdOutput(result) || ''), exitCode: 0 };
    }
    const item = pickSetVector(first === 'attack' || first === 'vector' ? parts.slice(1).join(' ') : raw);
    if (!item) return { label: 'set', output: `Couldn't match that to a SET attack. Menu:\n\n${renderSetMenu()}`, exitCode: 1 };
    // parse opts (key=value + positional): url (contains :// or a dot), lhost (ip), lport (number), ptype
    const opts = {};
    for (const t of parts.slice(1)) {
      const kv = /^(url|lhost|lport|ptype|payloadtype|template)=(.+)$/i.exec(t);
      if (kv) { const k = kv[1].toLowerCase().replace('payloadtype', 'ptype'); opts[k === 'ptype' ? 'payloadType' : k] = kv[2]; continue; }
      if (/:\/\//.test(t)) opts.url = t;
      else if (/^(\d{1,3}\.){3}\d{1,3}$/.test(t)) opts.lhost = t;
      else if (/^\d{2,5}$/.test(t)) opts.lport = t;
    }
    // required-field check
    const missing = (item.needs || []).filter((n) => !opts[n]);
    if (missing.length) return { label: 'set: ' + item.name, output: `**${item.name}** needs: ${missing.join(', ')}.\nUsage: \`\`\`set ${item.id} ${(item.needs || []).map((n) => n + '=<' + n + '>').join(' ')}\n(I can detect your IP with \`\`\`set ip.)`, exitCode: 1 };

    const built = buildSetCommand(item.vector, opts);
    if (built.infoOnly || !built.command) return { label: 'set: ' + item.name, output: `**${item.name}**\n${built.note}`, exitCode: 0 };

    if (built.listener) {
      // credential harvester / web-jacking / tabnabbing: keep SET's phishing web server ALIVE as a job.
      const job = await startJob({ command: built.command, sessionId, userId, label: `SET ${item.vector} (${opts.url || ''})`, kind: 'set', meta: { link: opts.url || null } });
      return { label: 'set: ' + item.name, output: `🎣 **${item.name}** — LIVE as a live session \`${job.id}\`.\n${built.note}\n\nA live session opened below — tell it "show me captured credentials / any victims yet" and I'll operate it.`, exitCode: 0, jobId: job.id, live: true, kind: 'set', link: opts.url || null, envLabel: `SET ${item.vector}` };
    }
    // one-shot generator (QR / payload / powershell / infectious): run + collect the artifact.
    const { result, findingsAdded } = await runAndCapture(built.command, { sessionId, userId });
    const out = fmtCmdOutput(result) || '';
    const arts = [...out.matchAll(/SET-ARTIFACT:\s*\d+ bytes\s+(\S+)/gi)].map((m) => m[1]);
    return {
      label: 'set: ' + item.name,
      output: `**${item.name}**\n${built.note}\n\n${arts.length ? '✅ Generated: ' + arts.join(', ') : out.split('\n').slice(-6).join('\n')}`,
      exitCode: result.exitCode, findingsAdded,
    };
  }

  // ```hound — geolocation + device-recon tracker. Starts Hound (php + cloudflared tunnel) as a PERSISTENT
  // background job, waits for the public link, and hands it back to deliver to the target. When the target
  // opens it and allows location, exact GPS + device intel stream into the job (captured -> findings).
  if (type === 'hound') {
    const raw = body.trim().toLowerCase();
    // `hound read <job>` / `hound link <job>` -> show a running tracker's output/link
    const rd = /^(read|link|data)\s+(\S+)/.exec(raw);
    if (rd) {
      const r = readJob(rd[2], 0);
      if (r.error) return { label: 'hound', output: r.error, exitCode: 1 };
      const link = extractHoundLink(r.text);
      return { label: 'hound: ' + rd[2], output: (link ? `Link: ${link}\n\n` : '') + '```\n' + (r.text || '(no output yet)').slice(-3000) + '\n```', exitCode: 0 };
    }
    const job = await startJob({ command: buildHoundCommand(), sessionId, userId, label: 'hound GPS tracker', kind: 'hound' });
    // cloudflared usually publishes the link in ~15-30s — poll for it (this action legitimately takes that long).
    let link = null;
    for (let i = 0; i < 13 && !link; i++) { await new Promise((r) => setTimeout(r, 3000)); link = extractHoundLink(readJob(job.id, 0).text); }
    if (link) updateJobMeta(job.id, { link });
    // A LIVE HACK ENVIRONMENT: auto-open the Sessions panel + AI management box (live/kind/link surfaced via emit).
    const envFields = { jobId: job.id, live: true, kind: 'hound', link, envLabel: 'Hound GPS tracker' };
    if (link) {
      return { label: 'hound', output: `🐕 **Hound tracking link is LIVE** (job \`${job.id}\`):\n\n**${link}**\n\nSend this to the target. The moment they open it and allow location in their browser, I capture their EXACT GPS coordinates + device intel (OS, model, public IP, ISP, browser). A live session opened below — just tell it "show me the location / any new hits" and I'll operate it for you. (Authorized tracking / OSINT engagements only.)`, exitCode: 0, ...envFields };
    }
    return { label: 'hound', output: `🐕 Hound is starting as job \`${job.id}\` — the cloudflared tunnel is still coming up. A live session opened below; in a few seconds ask it for the public trycloudflare.com link to deliver to the target.`, exitCode: 0, ...envFields };
  }

  // ```camphish — webcam-grab + geolocation via a phishing page (Festival/YouTube/Meeting template). Starts
  // CamPhish (php + cloudflared) as a PERSISTENT job, returns the public link; when the target opens it and
  // allows CAMERA, front-camera shots (cam*.png) + GPS + device intel stream in (captures -> findings).
  if (type === 'camphish') {
    const raw = body.trim();
    const rd = /^(read|link|data)\s+(\S+)/i.exec(raw);
    if (rd) {
      const r = readJob(rd[2], 0);
      if (r.error) return { label: 'camphish', output: r.error, exitCode: 1 };
      const link = extractCamphishLink(r.text);
      return { label: 'camphish: ' + rd[2], output: (link ? `Link: ${link}\n\n` : '') + '```\n' + (r.text || '(no output yet)').slice(-3000) + '\n```', exitCode: 0 };
    }
    const tmpl = pickTemplate(raw.replace(/^(start|template)\s+/i, ''));
    const job = await startJob({ command: buildCamphishCommand(tmpl), sessionId, userId, label: `camphish (${CAMPHISH_TEMPLATES[tmpl]})`, kind: 'camphish' });
    let link = null;
    for (let i = 0; i < 14 && !link; i++) { await new Promise((r) => setTimeout(r, 3000)); link = extractCamphishLink(readJob(job.id, 0).text); }
    if (link) updateJobMeta(job.id, { link });
    const envFields = { jobId: job.id, live: true, kind: 'camphish', link, envLabel: `CamPhish (${CAMPHISH_TEMPLATES[tmpl]})` };
    if (link) {
      return { label: 'camphish', output: `📸 **CamPhish is LIVE** (job \`${job.id}\`, template: ${CAMPHISH_TEMPLATES[tmpl]}):\n\n**${link}**\n\nDeliver this link to the target. When they open it and allow CAMERA, I capture their front-camera shots + GPS + device intel. A live session opened below — tell it "show me the captured images / any GPS" and I'll operate it. (Authorized social-engineering only.)`, exitCode: 0, ...envFields };
    }
    return { label: 'camphish', output: `📸 CamPhish is starting as job \`${job.id}\` (${CAMPHISH_TEMPLATES[tmpl]}) — the cloudflared tunnel is coming up. A live session opened below; ask it for the public link in a few seconds.`, exitCode: 0, ...envFields };
  }

  if (type === 'owasp') {
    // body: a target host/URL -> run a broad OWASP Top-10 sweep (fingerprint + nikto + nuclei).
    const target = body.trim().split(/\s+/)[0];
    if (!target) return { label: 'owasp', output: 'Usage: ```owasp <target-url>```', exitCode: 1 };
    const built = buildOwaspScan(target);
    const { result, findingsAdded } = await runAndCapture(built.command, { sessionId, userId });
    return {
      label: 'owasp sweep: ' + target,
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

  // ---- AppSec / DevSecOps suite -------------------------------------------------------------
  // SCA / SBOM: syft inventory shown as a summary (not persisted as hundreds of info findings).
  if (type === 'sca') {
    const command = buildAppsecCommand('sca', body);
    const { result } = await runAndCapture(command, { sessionId, userId });
    const sum = summarizeSbom(fmtCmdOutput(result));
    return { label: `SCA/SBOM: ${(body || '.').split('\n')[0].slice(0, 60)}`, output: sum.text, exitCode: result.exitCode, blocked: result.blocked };
  }

  // Straight scanner areas (sast/secrets/gitsecrets/depcve/iac/container/config/license/supplychain):
  // build the self-installing command, run it, and the finding pipeline parses the JSON.
  if (SCANNER_AREAS.includes(type)) {
    const command = buildAppsecCommand(type, body);
    if (!command) return { label: type, output: 'Unknown AppSec area', exitCode: 1 };
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: `${AREAS[type].label}: ${(body || (type === 'container' ? '(image)' : '.')).split('\n')[0].slice(0, 70)}`,
      output: fmtCmdOutput(result) || '(no findings / empty scan)',
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  // Secure code review: run SAST to gather signals, then hand the agent a directive to write the review.
  if (type === 'codereview') {
    const command = buildAppsecCommand('sast', body);
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    const out = fmtCmdOutput(result) || '(no scanner output — the code may be clean or unsupported)';
    return {
      label: `code review: ${(body || '.').split('\n')[0].slice(0, 60)}`,
      output:
        out +
        '\n\n[WRITE THE SECURE CODE REVIEW NOW: group the SAST findings above by severity, explain the risk/impact of each with file:line, and give a concrete fix per issue. Read the flagged files (```execute cat …) if you need context. End with an overall risk verdict and top-3 priorities.]',
      exitCode: result.exitCode,
      findingsAdded,
    };
  }

  // Remediation generation: match the finding/description to the fix KB and tell the agent to patch.
  if (type === 'remediation') {
    return { label: 'remediation: ' + (body || '').split('\n')[0].slice(0, 60), output: remediationFor(body), exitCode: 0 };
  }

  // Fix verification: re-run the relevant scanner and diff vs this session's prior findings.
  if (type === 'fixverify') {
    const parts = (body || '').trim().split(/\s+/);
    let area = (parts[0] || '').toLowerCase();
    let target = parts.slice(1).join(' ');
    if (!SCANNER_AREAS.includes(area)) { area = 'sast'; target = (body || '').trim(); }
    const command = buildAppsecCommand(area, target);
    const { result } = await runAndCapture(command, { sessionId, userId });
    const current = extractAppsecFindings(command, fmtCmdOutput(result));
    const currentTitles = new Set(current.map((f) => f.title));
    const TYPE_BY_AREA = {
      sast: ['sast'], secrets: ['secret'], gitsecrets: ['secret'], depcve: ['dependency'],
      supplychain: ['supplychain', 'dependency'], iac: ['iac'], container: ['dependency', 'config', 'secret'],
      config: ['config'], license: ['license'],
    };
    const wanted = new Set(TYPE_BY_AREA[area] || ['sast']);
    const before = (await listFindings(sessionId)).filter((f) => wanted.has(f.finding_type) && f.status !== 'closed');
    const resolved = before.filter((f) => !currentTitles.has(f.title));
    const still = before.filter((f) => currentTitles.has(f.title));
    for (const r of resolved) { try { await updateFinding(userId, r.id, { status: 'closed' }); } catch { /* best-effort */ } }
    const lines = [
      `Re-ran **${AREAS[area]?.label || area}** on \`${target || '.'}\`.`,
      `✅ Resolved (now closed): **${resolved.length}**`,
      `⚠️ Still open: **${still.length}**`,
      `🆕 Currently detected: **${current.length}**`,
    ];
    if (resolved.length) lines.push('\nFixed:\n' + resolved.slice(0, 15).map((f) => `- ${f.title}`).join('\n'));
    if (still.length) lines.push('\nStill present:\n' + still.slice(0, 15).map((f) => `- ${f.title}`).join('\n'));
    return { label: `fixverify: ${area} ${target || '.'}`, output: lines.join('\n'), exitCode: still.length ? 1 : 0 };
  }

  // CI/CD integration: emit a ready-to-commit security-gate pipeline for the chosen platform.
  if (type === 'cicd') {
    const platform = ((body || '').trim().split(/\s+/)[0] || 'github').toLowerCase();
    const { filename, content } = generateCicdPipeline(platform);
    return {
      label: `cicd: ${platform}`,
      output: `Commit this as \`${filename}\` to run the full security suite (secrets, SAST, dependency CVEs, IaC, vulns) as a CI gate:\n\n\`\`\`yaml\n${content}\`\`\``,
      exitCode: 0,
    };
  }

  // ---- Cloud & infrastructure security (Phase 1) --------------------------------------------
  // ```cloud <domain>  -> external cloud-posture assessment (provider/CDN, public buckets,
  //                        exposed secret/env files, nuclei cloud/exposure/takeover).
  // ```cloud aws|azure|gcp -> credentialed CSPM via Prowler (ambient creds).
  if (type === 'cloud') {
    const command = buildCloudCommand(body);
    if (!command) return { label: 'cloud', output: 'Usage: ```cloud <domain>``` (external) or ```cloud aws|azure|gcp``` (credentialed CSPM).', exitCode: 1 };
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    const raw = fmtCmdOutput(result);
    const credentialed = /^(aws|azure|gcp|kubernetes|prowler|scout)/i.test((body || '').trim());
    return {
      label: `cloud: ${(body || '').split('\n')[0].slice(0, 60)}`,
      output: credentialed ? (raw || '(no CSPM output — are cloud credentials configured?)') : renderCloud(raw),
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  // ```websecrets <domain> -> hunt secrets a live web app leaks to the browser (JS bundles, env
  // vars, source maps, web-served dotfiles). `deep` scans more assets.
  if (type === 'websecrets') {
    const command = buildWebSecretsCommand(body);
    if (!command) return { label: 'websecrets', output: 'Usage: ```websecrets <domain>``` (add "deep" for more assets).', exitCode: 1 };
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: `websecrets: ${(body || '').split('\n')[0].slice(0, 60)}`,
      output: renderWebSecrets(fmtCmdOutput(result)),
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  // ```buckets <domain> -> deep public storage-bucket enumeration (S3/GCS/Azure/DO) via keyword
  // permutations; classifies public-listable (HIGH) vs exists-but-private (LOW). `deep` = more.
  if (type === 'buckets') {
    const command = buildBucketCommand(body);
    if (!command) return { label: 'buckets', output: 'Usage: ```buckets <domain>``` (add "deep" for 220 permutations + Azure/DO, or "seed:<word>").', exitCode: 1 };
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: `buckets: ${(body || '').split('\n')[0].slice(0, 60)}`,
      output: renderBuckets(fmtCmdOutput(result)),
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  // ```iam <policy.json>  -> analyze an IAM policy/authorization-details dump for over-permissive
  // grants (offline). ```iam aws|azure|gcp -> Prowler IAM-category CSPM (credentialed).
  if (type === 'iam') {
    const command = buildIamCommand(body);
    if (!command) return { label: 'iam', output: 'Usage: ```iam <path-to-policy.json>``` (offline analysis) or ```iam aws|azure|gcp``` (credentialed CSPM).', exitCode: 1 };
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    const credentialed = /^(aws|azure|gcp|prowler)/i.test((body || '').trim());
    return {
      label: `iam: ${(body || '').split('\n')[0].slice(0, 60)}`,
      output: credentialed ? (fmtCmdOutput(result) || '(no CSPM output — are cloud credentials configured?)') : renderIam(fmtCmdOutput(result)),
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  // ```defaultcreds <target> -> find exposed admin panels/services and test default credentials
  // (HTTP Basic-Auth + known consoles; `deep` adds nmap NSE anon/empty-password checks).
  if (type === 'defaultcreds') {
    const command = buildDefaultCredsCommand(body);
    if (!command) return { label: 'defaultcreds', output: 'Usage: ```defaultcreds <target-host-or-url>``` (add "deep" for nmap NSE service checks).', exitCode: 1 };
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: `defaultcreds: ${(body || '').split('\n')[0].slice(0, 60)}`,
      output: renderDefaultCreds(fmtCmdOutput(result)),
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  // ```exposed <target> -> find unauthenticated databases, dashboards & control-plane APIs
  // (Elasticsearch/CouchDB/Grafana/Kibana/Docker/K8s/etcd/actuator…). `deep` adds an nmap DB-port scan.
  if (type === 'exposed') {
    const command = buildExposedCommand(body);
    if (!command) return { label: 'exposed', output: 'Usage: ```exposed <target-host-or-url>``` (add "deep" for an nmap DB/dashboard port scan).', exitCode: 1 };
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: `exposed: ${(body || '').split('\n')[0].slice(0, 60)}`,
      output: renderExposed(fmtCmdOutput(result)),
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  // ```firewall <target> -> map externally-reachable ports and review network segmentation / firewalling
  // (flags SSH/RDP/SMB/DB/control-plane ports exposed to the internet; detects firewall + WAF). `deep` = all ports.
  if (type === 'firewall') {
    const command = buildFirewallCommand(body);
    if (!command) return { label: 'firewall', output: 'Usage: ```firewall <target-host-or-ip>``` (add "deep" for an all-ports + UDP scan).', exitCode: 1 };
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: `firewall: ${(body || '').split('\n')[0].slice(0, 60)}`,
      output: renderFirewall(fmtCmdOutput(result)),
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  // ```svcaudit <target> -> audit SMB/FTP/SSH/RDP service HARDENING (SMBv1/signing/null-session, FTP anon/
  // cleartext, SSH weak kex/cipher/MAC/host-key, RDP NLA/encryption). `deep` adds BlueKeep/MS17-010 vuln NSE.
  if (type === 'svcaudit') {
    const command = buildSvcAuditCommand(body);
    if (!command) return { label: 'svcaudit', output: 'Usage: ```svcaudit <target-host-or-ip>``` (add "deep" for MS12-020/MS17-010 vuln checks).', exitCode: 1 };
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: `svcaudit: ${(body || '').split('\n')[0].slice(0, 60)}`,
      output: renderSvcAudit(fmtCmdOutput(result)),
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  // ```webinput <target> -> NON-DESTRUCTIVE file-upload / rate-limit / input-validation testing
  // (burst rate check, reflected-XSS/SQL-error/LFI canary probes, input-length, upload-form discovery).
  if (type === 'webinput') {
    const command = buildWebInputCommand(body);
    if (!command) return { label: 'webinput', output: 'Usage: ```webinput <target-url>``` (optionally a burst count, e.g. `webinput https://site 25`).', exitCode: 1 };
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: `webinput: ${(body || '').split('\n')[0].slice(0, 60)}`,
      output: renderWebInput(fmtCmdOutput(result)),
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  // ```apidiscover <target> -> map the API attack surface: OpenAPI/Swagger specs, Link service-doc,
  // endpoints mined from JS, GraphQL introspection, and allowed HTTP methods. GET/OPTIONS only.
  if (type === 'apidiscover') {
    const command = buildApiDiscoverCommand(body);
    if (!command) return { label: 'apidiscover', output: 'Usage: ```apidiscover <target-url>```', exitCode: 1 };
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: `apidiscover: ${(body || '').split('\n')[0].slice(0, 60)}`,
      output: renderApiDiscover(fmtCmdOutput(result)),
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  // ```authsession <target> -> review authentication & session security: cookie flags, HSTS/clickjacking
  // headers, CORS reflection, login-form CSRF/transport, JWT alg:none/expiry, OIDC discovery. Non-destructive.
  if (type === 'authsession') {
    const command = buildAuthSessionCommand(body);
    if (!command) return { label: 'authsession', output: 'Usage: ```authsession <target-url>```', exitCode: 1 };
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: `authsession: ${(body || '').split('\n')[0].slice(0, 60)}`,
      output: renderAuthSession(fmtCmdOutput(result)),
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  // ```loginbypass <login-url> [user=field] [pass=field] -> try classic SQLi auth-bypass payloads against
  // the login form and detect a real bypass (redirect / session cookie / failure-marker gone). CRITICAL if hit.
  if (type === 'loginbypass') {
    const command = buildLoginBypassCommand(body);
    if (!command) return { label: 'loginbypass', output: 'Usage: ```loginbypass <login-url>``` (optionally user=<field> pass=<field> to override auto-detection).', exitCode: 1 };
    const { result, findingsAdded } = await runAndCapture(command, { sessionId, userId });
    return {
      label: `loginbypass: ${(body || '').split('\n')[0].slice(0, 60)}`,
      output: renderLoginBypass(fmtCmdOutput(result)),
      exitCode: result.exitCode,
      blocked: result.blocked,
      findingsAdded,
    };
  }

  // ```dork <domain> -> automated Google/Bing/DDG dork SWEEP: runs the curated recon dork suite (exposed
  // .env/config/backups/logs, admin panels, SQL errors, git, pastebin/github/cloud leaks), classifies hits
  // into findings, and ALWAYS returns the actionable dork playbook. Passive OSINT — not gated.
  if (type === 'dork') {
    const sweep = await runDorkSweep(body, { signal });
    let findingsAdded = 0;
    try {
      if (sweep.findings.length) findingsAdded = await addFindings(sessionId, userId, sweep.findings.map(enrichCvss));
    } catch (e) { console.warn('dork finding add failed:', e.message); }
    return { label: 'dork: ' + String(body || '').trim().slice(0, 60), output: renderDork(sweep), exitCode: 0, findingsAdded };
  }

  // ```pwnedpass <password | one-per-line list> -> check password(s) against HaveIBeenPwned's breach corpus
  // via k-anonymity (only a 5-char SHA-1 prefix is sent; the full password never leaves). Defensive, not gated.
  if (type === 'pwnedpass') {
    const passwords = parsePasswords(body);
    if (!passwords.length) {
      return { label: 'pwnedpass', output: 'Usage: ```pwnedpass <password>``` — or paste/upload a .txt with one password per line. Only a 5-char SHA-1 prefix is sent (k-anonymity); your full password never leaves this machine.', exitCode: 1 };
    }
    const results = await checkMany(passwords, { signal });
    return { label: pwnedLabel(passwords), output: renderPwnedReport(results), exitCode: 0, findingsAdded: 0 };
  }

  // ```hashid <hash> -> identify the hash algorithm(s) and produce the hashcat -m mode, john format, and a
  // ready crack command. Accepts one hash, several (one per line), or a shadow/pwdump line. Local analysis.
  if (type === 'hashid') {
    return { label: 'hashid: ' + String(body || '').trim().split('\n')[0].slice(0, 50), output: renderHashid(body), exitCode: 0 };
  }

  // ```shodan <spec> -> internet OSINT via api.shodan.io: host lookups (open ports + CVEs), banner search,
  // subdomain/DNS enumeration, reverse-DNS. Host lookups become findings. Passive OSINT — not gated.
  if (type === 'shodan') {
    const result = await runShodan(body, { signal });
    let findingsAdded = 0;
    try {
      const fs = shodanFindings(result);
      if (fs.length) findingsAdded = await addFindings(sessionId, userId, fs.map(enrichCvss));
    } catch (e) { console.warn('shodan finding add failed:', e.message); }
    return { label: 'shodan: ' + String(body || '').trim().slice(0, 60), output: renderShodan(result), exitCode: result.error ? 1 : 0, findingsAdded };
  }

  return { label: type, output: 'Unknown tool', exitCode: 1 };
}

// Compact, severity-ordered digest of a session's findings — used both to (a) resume a session
// (tell the model what's already done) and (b) always show the user WHAT WAS FOUND on stop.
function renderFindingsDigest(list, stats, max = 30) {
  if (!list?.length) return '(none yet)';
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...list].sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  const lines = sorted.slice(0, max).map((f) => {
    const sev = (f.severity || 'info').toUpperCase();
    const loc = f.host ? ` @ ${f.host}${f.port ? ':' + f.port : ''}` : '';
    const cve = f.cve ? ` [${f.cve}]` : '';
    const cvss = f.cvss_score ? ` (CVSS ${f.cvss_score})` : '';
    return `- **${sev}** ${f.title}${loc}${cve}${cvss}`;
  });
  const more = list.length > max ? `\n…and ${list.length - max} more.` : '';
  const head = stats
    ? `Totals — critical ${stats.critical}, high ${stats.high}, medium ${stats.medium}, low ${stats.low}, info ${stats.info}.\n`
    : '';
  return head + lines.join('\n') + more;
}

// Guaranteed wrap-up: when a turn stops WITHOUT a natural final answer (hit the step cap, or the
// user pressed Stop) but tools DID run, make sure the user still gets a report of what was found.
// Tries a concise LLM summary (skipped on user-abort), always falls back to a deterministic digest.
async function finalizeSummary({ working, system, sessionId, emit, signal, append, aborted }) {
  let stats = null;
  let list = null;
  try {
    stats = await findingStats(sessionId);
    list = await listFindings(sessionId);
  } catch {
    /* DB best-effort */
  }
  const digest = list?.length ? renderFindingsDigest(list, stats, 40) : '';

  if (!aborted) {
    try {
      const wrapMsgs = [
        ...working,
        {
          role: 'user',
          content:
            'You have reached the step budget for THIS turn. STOP running tools now — do NOT emit any ' +
            'tool block. Write a concise FINAL REPORT of this turn: 1) what you tested, 2) what you ' +
            'FOUND (issue, severity, host/URL, CVE if any), 3) what is still pending, 4) the single ' +
            'best next step. Base it ONLY on the real results above.' +
            (digest ? '\n\nStructured findings recorded so far:\n' + digest : ''),
        },
      ];
      emit?.('notice', { text: 'Wrapping up — summarising findings…' });
      const summary = await streamChat({ history: wrapMsgs, system, signal, onDelta: (text) => emit('delta', { text }) });
      const clean = stripToolBlocks(summary || '').trim();
      if (clean) {
        append('\n\n---\n' + clean);
        return;
      }
    } catch {
      /* fall through to deterministic digest */
    }
  }

  if (digest) {
    append(`\n\n---\n## 🎯 Summary — findings so far (${stats?.total || 0})\n${digest}\n\n_Reached this turn's step limit. Say "continue" to resume from here (I won't repeat what's done)._`);
  } else {
    append('\n\n---\n_Reached this turn\'s step limit without a confirmed finding yet. Say "continue" to keep going from where I left off._');
  }
}

// Agent loop: model thinks -> emits tool blocks -> we run them -> feed output back ->
// repeat until the model stops requesting tools (or maxSteps reached).
// emit(event, data) streams SSE. Returns the canonical transcript to persist.
export async function runAgent({ history, sessionId, userId, emit, signal, memoryContext, autopilot }) {
  const working = [...history];
  let system = autopilot ? EXEC_SYSTEM + AUTOPILOT_PROMPT : EXEC_SYSTEM;
  if (memoryContext) system += '\n\n== RELEVANT MEMORY FROM EARLIER SESSIONS ==\n' + memoryContext;

  // Vulnerability/exploitation engagement: when the user's goal is about finding/exploiting a
  // vulnerability (or names a CVE/CWE/OWASP/known bug), load the force-prompt + the compact CVE/CWE
  // catalogue so the agent knows every famous vuln and actually RUNS the exploit tooling. Autopilot
  // always engages it. Kept OFF for ordinary chat to save tokens (and honour the conversation guard).
  const goalText = [...history].reverse().find((m) => m.role === 'user')?.content || '';
  if (autopilot || VULN_ENGAGE_RE.test(goalText)) {
    system += VULN_FORCE_PROMPT + '\n\n== VULNERABILITY KNOWLEDGE BASE (you know & can exploit these) ==\n' + renderCatalog();
    emit?.('notice', { text: 'Exploitation mode engaged — CVE/CWE/OWASP knowledge loaded.' });
  }

  // Resume awareness: surface what THIS session already found so the agent continues from there
  // instead of restarting recon from scratch when the user says "continue"/"resume".
  try {
    const prior = await listFindings(sessionId);
    if (prior.length) {
      system +=
        '\n\n== WORK ALREADY DONE IN THIS SESSION — DO NOT REPEAT ==\n' +
        renderFindingsDigest(prior, null, 30) +
        '\nThese were found by EARLIER steps in this same session. Do NOT re-run the same recon/scans ' +
        'or re-report these. If the user says "continue"/"resume" (or you were cut off at the step ' +
        'limit), pick up exactly where you left off and go after what is still untested.';
    }
  } catch {
    /* resume context is best-effort */
  }

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

  let ranAnyTool = false;
  let endedNaturally = false; // model produced a real final answer (vs. hitting the step cap)
  let corrections = 0;
  const MAX_CORRECTIONS = 2;

  for (let step = 0; step < maxSteps; step++) {
    // Safety: keep the running history from ever blowing past the model context window.
    // Preserve the original goal (first user msg) + the most recent exchanges.
    trimHistory(working);

    const stepText = await streamChat({
      history: working,
      system,
      signal,
      onDelta: (text) => emit('delta', { text }),
    });

    working.push({ role: 'assistant', content: stepText });

    // User pressed Stop mid-stream: keep the partial narration and stop cleanly, so the
    // route can persist what was generated (survives a page refresh).
    if (signal?.aborted) {
      const partial = stripToolBlocks(stepText);
      if (partial) append(partial);
      break;
    }

    const tools = parseToolBlocks(stepText);

    // No tool block: either a genuine final answer, OR the model simulated / just listed
    // commands without running them. Guard against the latter (the "prints instead of runs" bug).
    if (tools.length === 0) {
      const simulated = SIM_RE.test(stepText);
      const listedButNotRun = !ranAnyTool && CMD_HINT_RE.test(stepText);
      if ((simulated || listedButNotRun) && corrections < MAX_CORRECTIONS) {
        corrections++;
        emit?.('notice', { text: 'Enforcing real execution (no simulation)…' });
        working.push({ role: 'user', content: ANTI_SIM_NUDGE });
        continue; // re-prompt this step; do NOT persist the simulated text
      }
      const cleaned = stripToolBlocks(stepText);
      if (cleaned) append(cleaned);
      endedNaturally = true; // a genuine final answer — no forced wrap-up needed
      break;
    }

    // Tools present — keep the model's reasoning text, then run them.
    const cleaned = stripToolBlocks(stepText);
    if (cleaned) append(cleaned);
    ranAnyTool = true;

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
      // Live Hack Environment — a callback/capture session started: auto-open the Sessions panel + focus this job.
      if (r.jobId && r.live) emit('environment', { jobId: r.jobId, kind: r.kind, link: r.link || null, label: r.envLabel || r.kind });

      if (r.artifact) {
        // A generated file — render a clickable download link (NOT a fenced block), and tell
        // the UI so it can surface it too.
        emit('artifact', r.artifact);
        append(
          `📎 **[Download ${r.artifact.name}](${r.artifact.url})** — ${String(r.artifact.format || '').toUpperCase()} · ${r.artifact.sizeHuman}`
        );
      } else {
        append(
          '```bash\n' + r.label + '\n```\n```text\n' + (r.output || '(no output)') + '\n```\n' +
            `_exit ${r.exitCode}${r.blocked ? ' · blocked by host guard' : ''}_` +
            (r.findingsAdded > 0 ? ` · 🎯 ${r.findingsAdded} finding(s)` : '')
        );
      }

      observation += `${r.label}\n${clampForModel(r.output)}\n[exit ${r.exitCode}]\n\n`;
      if (signal?.aborted) break;
    }

    if (signal?.aborted) break;

    // Final safety cap on the whole step's observation before it re-enters the context.
    if (observation.length > OBS_TOTAL_MAX) {
      observation = observation.slice(0, OBS_TOTAL_MAX) + '\n…[step output truncated to fit context]…';
    }
    working.push({ role: 'user', content: `Tool output:\n${observation.trim()}` });
  }

  // Stopped without a natural final answer (hit the step cap, or the user pressed Stop) but tools
  // ran — guarantee the user still gets a report of WHAT WAS FOUND, and an easy way to resume.
  if (ranAnyTool && !endedNaturally) {
    await finalizeSummary({ working, system, sessionId, emit, signal, append, aborted: !!signal?.aborted });
  }

  return canonical || '(no response)';
}

export { activeModel };
