// STRONGLY-BOUND live-session detection — the Live Hack Environment is NOT just for the 4 named tags
// (hound/camphish/msf/set). Most Kali tooling that involves a callback, a capture, a tunnel, a listener, or an
// interactive console needs a session that STAYS ALIVE and is driven live. This catalog recognises such
// commands from a raw `execute`/`bash` block so ANY of them automatically becomes a live environment (persistent
// job + auto-opened panel + AI management box) instead of a one-shot command that would block or time out.
//
// Matchers are deliberately SPECIFIC (tool + the flag/subcommand that makes it long-lived) so ordinary scans
// (nmap, nikto, a plain sqlmap run, a curl) are NOT misclassified. `interactive` = you type INTO it (a caught
// shell / a console) → the manager uses SEND (stdin); otherwise it's a capture/server you INSPECT → RUN/SAY.

// Each rule: { kind, interactive, why, re }. First match wins.
export const LIVE_TOOL_RULES = [
  // ── shell listeners / catchers (you interact with the shell that connects back) ──
  { kind: 'listener', interactive: true, why: 'a reverse/bind-shell listener (waits for a callback)',
    re: /\b(?:nc|ncat|netcat)\b[^\n|]*\s-[a-z]*l/i },
  { kind: 'listener', interactive: true, why: 'a socat listener (waits for a callback)',
    re: /\bsocat\b[^\n]*\b(?:TCP\d?-LISTEN|UDP-LISTEN|OPENSSL-LISTEN)\b/i },
  { kind: 'listener', interactive: true, why: 'a pwncat / powercat listener',
    re: /\b(?:pwncat(?:-cs)?|powercat)\b[^\n]*\s-l/i },

  // ── Metasploit (handler / console) ──
  { kind: 'msf', interactive: true, why: 'a Metasploit console/handler (sessions stay alive)',
    re: /\bmsfconsole\b|\bmulti\/handler\b|\bexploit\/multi\/handler\b/i },

  // ── modern C2 frameworks (server/console + listeners stay alive for implant callbacks) ──
  { kind: 'c2', interactive: true, why: 'a C2 framework server/console (listeners + implant sessions stay alive)',
    re: /\bsliver-server\b|\bsliver-client\b|(?:^|[;&|]\s*)sliver\b|\bhavoc\s+(?:server|client)\b|\bteamserver\b|\bposhc2\b|\bmythic(?:-cli)?\b|\bmerlinserver\b|\bcovenant\b|dotnet\s+Covenant\.dll/i },

  // ── file / HTTP servers you keep alive to serve payloads or receive uploads ──
  { kind: 'server', interactive: false, why: 'an HTTP/file server (stays up to serve or receive files)',
    re: /\bpython3?\s+-m\s+http\.server\b|\bphp\s+-S\b|\bruby\s+-run\s+-e\s+httpd\b|\bbusybox\s+httpd\b|\bupdog\b|\bwebfsd\b/i },
  // impacket file/relay servers (SMB/HTTP/WebDAV) + relays
  { kind: 'relay', interactive: false, why: 'an impacket server/relay (stays up for callbacks/relaying)',
    re: /\b(?:impacket-)?(?:smbserver|ntlmrelayx|krbrelayx|goldenpac|httprelayserver)\b|\bsmbserver\.py\b|\bntlmrelayx\.py\b|\bresponder\b/i },

  // ── Wi-Fi captures & continuous attacks (need a radio; run until stopped) ──
  { kind: 'wifi', interactive: false, why: 'a live Wi-Fi capture/attack (runs until stopped)',
    re: /\b(?:airodump-ng|aireplay-ng|airbase-ng|besside-ng|wifite|hcxdumptool|kismet|hostapd(?:-wpe)?|mdk3|mdk4|reaver|bully|wifiphisher|fluxion|eaphammer)\b/i },

  // ── MITM / sniffers (continuous capture) ──
  { kind: 'mitm', interactive: false, why: 'a live MITM/sniffer (continuous capture)',
    re: /\b(?:bettercap|ettercap|mitmproxy|mitmdump|mitmweb|arpspoof|dnsspoof|sslstrip)\b/i },
  // packet captures — only when capturing live (NOT reading a saved file with -r)
  { kind: 'mitm', interactive: false, why: 'a live packet capture (tcpdump/tshark)',
    re: /\b(?:tcpdump|tshark)\b(?![^\n]*\s-r\b)/i },

  // ── tunnels / phishing front-ends (public callback URL stays up) ──
  { kind: 'tunnel', interactive: false, why: 'a public tunnel / callback front-end (stays up)',
    re: /\bcloudflared\b|\bngrok\b|\blocaltunnel\b|\blt\s+--port\b|\bchisel\s+(?:server|client)\b|\bbore\b|\bgotunnel\b|\bpagekite\b/i },
  { kind: 'tunnel', interactive: false, why: 'an SSH port-forward / tunnel (stays open)',
    re: /\bssh\b[^\n]*\s-[a-zA-Z]*[RLD]\s*\d/i },
  { kind: 'set', interactive: false, why: 'a Social-Engineer Toolkit phishing/harvester session',
    re: /\bsetoolkit\b|\bset-automate\b/i },
  { kind: 'server', interactive: false, why: 'a BeEF browser-exploitation server',
    re: /\bbeef(?:-xss)?\b|\bbundle\s+exec\s+\.\/beef\b/i },

  // ── interactive remote consoles (you type into them) ──
  { kind: 'console', interactive: true, why: 'an interactive remote console (stays connected)',
    re: /\bevil-winrm\b|\bwmiexec\b|\bpsexec\b|\bsmbexec\b|\batexec\b|\bxfreerdp\b|\brdesktop\b/i },
  { kind: 'console', interactive: true, why: 'an interactive SQL/OS shell',
    re: /\bsqlmap\b[^\n]*\s--(?:sql-shell|os-shell|os-pwn)\b/i },
];

// Detect whether a raw command should run as a LIVE session. Returns { live, kind, interactive, why } or { live:false }.
export function detectLiveCommand(command = '') {
  const cmd = String(command || '');
  if (!cmd.trim()) return { live: false };
  for (const r of LIVE_TOOL_RULES) {
    if (r.re.test(cmd)) return { live: true, kind: r.kind, interactive: r.interactive, why: r.why };
  }
  return { live: false };
}

// A short label for the session tab from a live command (first meaningful token + kind).
export function liveLabel(command = '', kind = 'live') {
  const first = String(command).trim().replace(/^sudo\s+/, '').split(/\s+/).slice(0, 3).join(' ');
  return `${kind}: ${first}`.slice(0, 48);
}
