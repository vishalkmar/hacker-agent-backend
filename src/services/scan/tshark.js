// tshark (Wireshark CLI) — packet capture & analysis. Builds high-level "sniff" commands and parses their
// output into findings, with a focus on CLEARTEXT CREDENTIAL extraction (HTTP basic-auth, GET/POST login
// params, FTP, Telnet, IMAP/POP/SMTP) — the highest-value thing you pull off the wire. Offline pcap analysis
// (`-r file.pcap`) works anywhere; live capture (`-i iface`) needs NET_RAW (the sandbox has it) and, for real
// LAN traffic, the right placement — same physical reality as the desktop build.

const PCAP = '/tmp/sniff.pcap';

export function detectTshark(command = '') {
  return /\btshark\b|\bdumpcap\b|\btcpdump\b/i.test(command);
}

// Auto-detect the capture interface (default route iface), fall back to eth0. Live capture needs NET_RAW.
const IFACE_DETECT = 'IFACE="${IFACE:-$(ip route 2>/dev/null | awk "/default/{print \\$5; exit}")}"; IFACE="${IFACE:-eth0}";';

// Compound cleartext-credential extractor over a pcap. Emits SNIFF-CRED<TAB>type<TAB>value lines that
// parseTshark turns into findings (and decodes HTTP basic-auth base64).
function credsExtractor(pcap) {
  const q = (proto, fields, filter, grep) =>
    `tshark -r ${pcap} -Y '${filter}' -T fields ${fields} 2>/dev/null${grep ? ` | grep -aiE '${grep}'` : ''} | sed '/^[[:space:]]*$/d' | while IFS= read -r l; do echo "SNIFF-CRED\t${proto}\t$l"; done;`;
  return [
    `echo "[*] extracting cleartext credentials from ${pcap}...";`,
    q('http-basic', '-e ip.dst -e http.authorization', 'http.authorization', 'Basic'),
    q('http-post', '-e http.host -e http.request.uri -e urlencoded-form.key -e urlencoded-form.value', 'http.request.method=="POST"', 'pass|pwd|user|login|email|token'),
    q('http-get', '-e http.host -e http.request.uri', 'http.request.uri contains "pass" or http.request.uri contains "pwd" or http.request.uri contains "login"', ''),
    q('ftp', '-e ip.dst -e ftp.request.command -e ftp.request.arg', 'ftp.request.command=="USER" or ftp.request.command=="PASS"', ''),
    q('telnet', '-e telnet.data', 'telnet.data', 'login|password|user'),
    q('mail', '-e ip.dst -e imap.request -e pop.request -e smtp.req.parameter', 'imap.request or pop.request or smtp.auth.username or smtp.req.command=="AUTH"', 'login|user|pass|AUTH'),
    `echo "[*] credential extraction complete";`,
  ].join(' ');
}

// action: capture | creds | http | dns | hosts | protocols | read | info
export function buildSniffCommand({ action, iface, count, pcap = PCAP, filter, duration } = {}) {
  const c = Math.min(Math.max(parseInt(count, 10) || 500, 1), 100000);
  const d = Math.min(Math.max(parseInt(duration, 10) || 30, 1), 3600);
  switch (action) {
    case 'capture':
      // live capture to a pcap; auto-detect iface; always terminates (packet count OR duration).
      return `${iface ? `IFACE="${iface}";` : ''} ${IFACE_DETECT} echo "[*] capturing on $IFACE (max ${c} pkts / ${d}s) -> ${pcap}"; ` +
        `tshark -i "$IFACE" -a duration:${d} -c ${c} -w ${pcap} 2>&1 | tail -3; ` +
        `echo "[*] saved ${pcap}"; capinfos -c -u ${pcap} 2>/dev/null | grep -iE "packet|duration" | head -2 || echo "SNIFF-NOCAPTURE: capture produced no file — need a network interface + NET_RAW (or run on the local/desktop machine).";`;
    case 'creds':
      return `[ -f "${pcap}" ] || { echo "SNIFF-USAGE: no pcap ${pcap} — capture one first (sniff capture) or pass a pcap path."; exit 3; }; ${credsExtractor(pcap)}`;
    case 'http':
      return `tshark -r ${pcap} -Y "http.request" -T fields -e ip.dst -e http.host -e http.request.method -e http.request.uri 2>/dev/null | head -100`;
    case 'dns':
      return `tshark -r ${pcap} -Y "dns.flags.response==0" -T fields -e dns.qry.name 2>/dev/null | sort -u | head -100`;
    case 'hosts':
      return `echo "[*] IP conversations:"; tshark -r ${pcap} -z conv,ip -q 2>/dev/null | head -40`;
    case 'protocols':
      return `tshark -r ${pcap} -z io,phs -q 2>/dev/null`;
    case 'read':
      return `tshark -r ${pcap} ${filter ? `-Y '${filter}'` : ''} 2>/dev/null | head -100`;
    case 'info':
      return `capinfos ${pcap} 2>/dev/null`;
    default:
      return `tshark -r ${pcap} 2>/dev/null | head -50`;
  }
}

// ---- parsing ----
function decodeBasic(b64) {
  try { const s = Buffer.from(b64, 'base64').toString('utf8'); return /^[\x20-\x7e]+:[\x20-\x7e]*$/.test(s) ? s : null; } catch { return null; }
}
function credFromUrl(uri) {
  const m = /[?&](?:pass|passwd|pwd|password)=([^&\s]+)/i.exec(uri);
  const u = /[?&](?:user|username|login|email|uname)=([^&\s]+)/i.exec(uri);
  if (m) return `${u ? decodeURIComponent(u[1]) + ' / ' : ''}${decodeURIComponent(m[1])}`;
  return null;
}

export function parseTshark(command, output) {
  if (!detectTshark(command) || !output) return [];
  const text = String(output);
  const out = [];
  const seen = new Set();
  const add = (sev, title, evidence, type = 'credential-access') => {
    const k = title;
    if (seen.has(k)) return; seen.add(k);
    out.push({ finding_type: type, severity: sev, source: 'tshark', title, evidence: String(evidence).slice(0, 200),
      remediation: sev === 'critical' || sev === 'high' ? 'Cleartext credentials on the wire — enforce TLS everywhere (HTTPS/FTPS/SSH), rotate the exposed creds, and disable plaintext protocols (HTTP/FTP/Telnet).' : sev === 'medium' ? 'Unencrypted protocol in use — migrate to its TLS/SSH equivalent; anything sent over it (creds, cookies, data) is sniffable.' : null });
  };

  // 1) HTTP basic-auth anywhere in the output -> decode base64 -> user:pass (critical)
  for (const m of text.matchAll(/Basic\s+([A-Za-z0-9+/]{8,}={0,2})/g)) {
    const dec = decodeBasic(m[1]);
    if (dec) add('critical', `Cleartext HTTP Basic-Auth credentials: ${dec}`, `Authorization: Basic ${m[1]} -> ${dec}`);
  }
  // 2) SNIFF-CRED marker lines from the creds extractor
  for (const m of text.matchAll(/^SNIFF-CRED\t([^\t]+)\t(.+)$/gim)) {
    const type = m[1]; const val = m[2].trim();
    if (!val) continue;
    const b64 = /Basic\s+([A-Za-z0-9+/]{8,}={0,2})/.exec(val);
    if (b64) { const d = decodeBasic(b64[1]); if (d) { add('critical', `Cleartext HTTP Basic-Auth credentials: ${d}`, val); continue; } }
    const urlc = credFromUrl(val);
    if (urlc) { add('high', `Credentials in ${type} request: ${urlc}`, val); continue; }
    add(type === 'ftp' || type === 'telnet' ? 'critical' : 'high', `Cleartext credential (${type}): ${val.slice(0, 80)}`, val);
  }
  // 3) credentials in GET/POST URLs seen in plain tshark http output
  for (const m of text.matchAll(/(https?:\/\/\S+|\/\S*(?:pass|pwd|password)=\S+)/gi)) {
    const c = credFromUrl(m[1]);
    if (c) add('high', `Credentials passed in a URL: ${c}`, m[1]);
  }
  // 4) cleartext protocol usage (from -z io,phs hierarchy) -> medium
  if (/frames:\d+/.test(text)) {
    for (const [re, name] of [[/\bhttp\b\s+frames:[1-9]/i, 'HTTP'], [/\bftp\b\s+frames:[1-9]/i, 'FTP'], [/\btelnet\b\s+frames:[1-9]/i, 'Telnet']]) {
      if (re.test(text)) add('medium', `Unencrypted ${name} traffic observed`, `${name} present in the capture (cleartext, sniffable)`, 'exposure');
    }
  }
  return out.slice(0, 60);
}
