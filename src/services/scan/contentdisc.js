// Content-discovery output parser — turns dirb / gobuster / feroxbuster directory-brute-force results into
// findings. Auto-invoked for any such command via runAndCapture. Sensitive paths (admin, .git, .env, backup,
// config, phpmyadmin, api, upload…) are raised in severity; everything else is recorded as info/low so the
// operator has the full discovered surface.

export function detectContentDisc(command = '') {
  return /\bdirb\b|\bgobuster\b|\bferoxbuster\b|\bdirsearch\b/i.test(command);
}

// Sensitive path keywords -> these findings matter more (exposed admin/secrets/VCS/backup surface).
const SENSITIVE = /(\.git|\.svn|\.env|\.htpasswd|\.htaccess|\.ssh|admin|administrator|phpmyadmin|wp-admin|config|backup|\.bak|\.old|\.sql|dump|db_|database|secret|passwd|password|credential|upload|api[_/]?key|actuator|server-status|server-info|console|shell|cgi-bin|\.git\/config|id_rsa|web\.config|\.aws)/i;

function sevForPath(pathOrUrl, code) {
  const p = String(pathOrUrl);
  if (SENSITIVE.test(p)) {
    // an accessible (200) sensitive path is worse than a forbidden (403) one
    return String(code) === '200' ? 'high' : 'medium';
  }
  // login/interesting but not secret
  if (/login|signin|register|dashboard|portal|debug|test|dev|staging|old|tmp/i.test(p)) return 'low';
  return 'info';
}

function safeHost(url) {
  try { return url ? new URL(url).hostname : null; } catch { return null; }
}
function pathOf(url) {
  try { return new URL(url).pathname; } catch { return url; }
}

export function parseContentDisc(command, output) {
  if (!detectContentDisc(command) || !output) return [];
  const src = /gobuster/i.test(command) ? 'gobuster' : /feroxbuster/i.test(command) ? 'feroxbuster' : /dirsearch/i.test(command) ? 'dirsearch' : 'dirb';
  const out = [];
  const push = (url, code, extra = '') => {
    const path = pathOf(url);
    const sev = sevForPath(url, code);
    out.push({
      finding_type: SENSITIVE.test(url) ? 'exposure' : 'content-discovery',
      severity: sev,
      title: `Found ${path}${code ? ` (HTTP ${code})` : ''}`,
      host: safeHost(url),
      evidence: `${url}${code ? ` [${code}]` : ''}${extra}`.slice(0, 200),
      remediation: SENSITIVE.test(url) ? 'Sensitive path exposed — remove/relocate it, require auth, and block VCS/backup/config files at the web server (deny .git/.env/.bak etc.).' : null,
      source: src,
    });
  };

  for (const raw of String(output).split('\n')) {
    const line = raw.replace(/\x1b\[[0-9;]*m/g, '').trim(); // strip ANSI
    let m;
    // dirb: "+ http://t/admin (CODE:200|SIZE:1234)"  and  "==> DIRECTORY: http://t/images/"
    if ((m = /^\+\s*(https?:\/\/\S+)\s*\(CODE:(\d+)\|SIZE:(\d+)\)/i.exec(line))) { push(m[1], m[2], ` size=${m[3]}`); continue; }
    if ((m = /^==>\s*DIRECTORY:\s*(https?:\/\/\S+)/i.exec(line))) { push(m[1], '', ' [dir]'); continue; }
    // gobuster dir: "/admin (Status: 200) [Size: 1234]"  or with "--> redirect"
    if ((m = /^(\/\S*)\s+\(Status:\s*(\d+)\)(?:\s*\[Size:\s*(\d+)\])?/i.exec(line))) {
      const base = /gobuster/i.test(command) ? (/-u\s+(\S+)/i.exec(command)?.[1] || '') : '';
      const url = base ? base.replace(/\/+$/, '') + m[1] : m[1];
      push(url.startsWith('http') ? url : 'http://x' + m[1], m[2], m[3] ? ` size=${m[3]}` : '');
      continue;
    }
    // feroxbuster: "200      GET       10l       20w      512c http://t/admin"
    if ((m = /^(\d{3})\s+\w+\s+\S+\s+\S+\s+\S+\s+(https?:\/\/\S+)/i.exec(line))) { push(m[2], m[1]); continue; }
    // dirsearch: "[HH:MM:SS] 200 -  512B  - /admin"
    if ((m = /^\[[0-9:]+\]\s+(\d{3})\s+-\s+\S+\s+-\s+(\/\S+)/i.exec(line))) { push('http://x' + m[2], m[1]); continue; }
  }

  // dedup by title
  const seen = new Set();
  return out.filter((f) => (seen.has(f.title) ? false : seen.add(f.title)));
}
