// PHASE 5 — Default credentials risk detection.
//
// Powers the ```defaultcreds agent tag. Finds exposed admin/login panels and services on a target
// and tests them against a curated default-credential list:
//   • HTTP Basic-Auth endpoints  -> tries default creds (admin:admin, root:root, tomcat:tomcat, …);
//     a 200/30x = the default credentials WORK (critical).
//   • Known admin consoles (Tomcat manager, Jenkins, Grafana, phpMyAdmin, Kibana, Adminer, Solr,
//     Portainer, pgAdmin, mod_status) fingerprinted from the response = exposed panel (review creds).
//   • deep: nmap NSE default-account / empty-password / anonymous-access checks for network services
//     (FTP anon, MySQL/MSSQL empty password, Mongo/Redis no-auth, VNC).
// Emits `CREDFIND<TAB><sev><TAB><type><TAB><title><TAB><evidence><TAB><url>` -> parseCredReport().
// This actively attempts logins against a target, so the tag is AUTHORIZATION-GATED. bash -n clean.

import { normSev, dedupCap } from '../appsec/engine.js';

function hostOf(t) { return String(t || '').trim().replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/[^\w.\-]/g, '').toLowerCase(); }
function urlOf(t) { const s = String(t || '').trim(); return /^https?:\/\//i.test(s) ? s.replace(/[^\w.\-:/?=&%#]/g, '') : 'https://' + hostOf(t); }
function hasPath(t) { const s = String(t || '').replace(/^[a-z]+:\/\//i, ''); return /\/[^/]/.test(s); }

// Common admin / login / console paths to probe.
const PANEL_PATHS = [
  'admin', 'admin/login', 'login', 'administrator', 'wp-login.php', 'wp-admin', 'user/login',
  'manager/html', 'host-manager/html', 'jenkins', 'grafana/login', 'phpmyadmin', 'pma', 'adminer.php',
  'solr/', 'kibana', 'portainer', 'pgadmin', 'server-status', 'console', 'actuator', 'management',
  'cockpit', 'webadmin', 'cpanel', 'dashboard', 'api/admin',
];
// Default credentials tried against Basic-Auth endpoints (user:pass; empty pass = trailing colon).
const DEFAULT_CREDS = ['admin:admin', 'admin:password', 'admin:', 'root:root', 'root:', 'root:toor', 'administrator:administrator', 'tomcat:tomcat', 'manager:manager', 'admin:changeme', 'admin:admin123', 'user:user', 'guest:guest'];
// Body signatures that identify a known admin console (case-insensitive).
const SIGS = 'Apache Tomcat|Tomcat.*Manager|Dashboard \\[Jenkins\\]|Jenkins|phpMyAdmin|Grafana|Kibana|Adminer|Solr Admin|Apache Status|mod_status|Portainer|pgAdmin|GitLab|Cockpit|Zabbix|Kubernetes Dashboard';

export function buildDefaultCredsScan(target, { deep = false } = {}) {
  const host = hostOf(target);
  const base = 'https://' + host;
  const creds = DEFAULT_CREDS.join(' ');
  const lines = [
    `BASE="${base}"; CREDS="${creds}";`,
    `emit(){ printf 'CREDFIND\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$1" "$2" "$3" "$4" "$5"; };`,
    `probe(){`,
    `  url="$1"; h=$(mktemp); b=$(mktemp);`,
    `  code=$(curl -s -m 7 -D "$h" -o "$b" -w '%{http_code}' "$url" 2>/dev/null);`,
    `  case "$code" in 404|000|"") rm -f "$h" "$b"; return;; esac;`,
    `  if grep -qi 'www-authenticate: *basic' "$h" 2>/dev/null; then`,
    `    emit medium exposed-panel "Basic-Auth endpoint (testing default creds): $url" "HTTP $code, WWW-Authenticate: Basic" "$url";`,
    `    for cp in $CREDS; do`,
    `      c2=$(curl -s -m 6 -o /dev/null -w '%{http_code}' -u "$cp" "$url" 2>/dev/null);`,
    `      case "$c2" in 200|301|302|303|307) emit critical default-cred "DEFAULT CREDENTIALS WORK: $url" "auth '$cp' -> HTTP $c2" "$url"; break;; esac;`,
    `    done;`,
    `  elif grep -qiE '${SIGS}' "$b" 2>/dev/null; then`,
    `    sig=$(grep -aioE '${SIGS}' "$b" | head -1);`,
    `    emit medium exposed-panel "Exposed admin console ($sig, HTTP $code): $url" "matched signature: $sig" "$url";`,
    `  fi;`,
    `  rm -f "$h" "$b";`,
    `};`,
    `export -f probe emit; export CREDS;`,
    `echo "== default-creds scan: ${host}${deep ? ' (deep)' : ''} =="`,
    // job list: the exact target URL (if it has a path) + BASE/<panel path>
    `{ ${hasPath(target) ? `echo "${urlOf(target)}";` : ''} for p in ${PANEL_PATHS.join(' ')}; do echo "$BASE/$p"; done; } | xargs -P 15 -I{} bash -c 'probe "{}"';`,
  ];
  if (deep) {
    lines.push(
      `command -v nmap >/dev/null 2>&1 && { N=$(mktemp);`,
      `nmap -Pn -T4 --script "ftp-anon,http-default-accounts,mysql-empty-password,ms-sql-empty-password,mongodb-databases,redis-info,vnc-info" -p 21,80,443,3306,1433,27017,6379,5900,8080 "${host}" -oN "$N" >/dev/null 2>&1;`,
      `grep -qi 'Anonymous FTP login allowed' "$N" && emit high anon-access "Anonymous FTP login allowed" "nmap ftp-anon" "ftp://${host}";`,
      `grep -qiE 'mysql.*empty password|Login Success.*root:<empty>' "$N" && emit critical default-cred "MySQL root has an EMPTY password" "nmap mysql-empty-password" "${host}:3306";`,
      `grep -qi 'ms-sql-empty-password' "$N" && grep -qi 'Login Success' "$N" && emit critical default-cred "MSSQL sa empty/default password" "nmap ms-sql-empty-password" "${host}:1433";`,
      `grep -qi 'MongoDB' "$N" && grep -qi 'databases' "$N" && emit high anon-access "MongoDB reachable without auth" "nmap mongodb-databases" "${host}:27017";`,
      `grep -qiE 'redis-info|Redis version' "$N" && emit high anon-access "Redis reachable without auth" "nmap redis-info" "${host}:6379";`,
      `grep -A3 'http-default-accounts' "$N" | grep -qiE 'valid|found' && emit critical default-cred "Default web accounts found (nmap http-default-accounts)" "see nmap output" "${base}";`,
      `rm -f "$N"; };`,
    );
  }
  lines.push(`echo "== default-creds scan complete =="`);
  return lines.join('\n');
}

export function buildDefaultCredsCommand(body) {
  const raw = String(body || '').trim();
  if (!raw) return null;
  if (/^(hydra|medusa|ncrack|nmap|patator|changeme)\b/i.test(raw)) return raw; // raw tool passthrough
  const tokens = raw.split(/\s+/);
  const deep = tokens.some((t) => /^deep$/i.test(t));
  return buildDefaultCredsScan(tokens[0], { deep });
}

export function parseCredReport(output) {
  const out = [];
  for (const line of String(output || '').split('\n')) {
    if (!line.startsWith('CREDFIND\t')) continue;
    const [, sev, type, title, evidence, url] = line.split('\t');
    if (!title) continue;
    out.push({
      finding_type: 'credentials',
      severity: normSev(sev),
      title: title.slice(0, 200),
      host: (url || '').slice(0, 200) || null,
      evidence: (evidence || '').slice(0, 240),
      cve: type === 'default-cred' ? 'CWE-1392' : (type === 'anon-access' ? 'CWE-306' : null),
      remediation: type === 'default-cred'
        ? 'Change the default credentials IMMEDIATELY to a strong unique password; disable the default account; restrict the panel by IP/VPN and add MFA.'
        : type === 'anon-access'
          ? 'Require authentication on this service; bind it to localhost/VPN, not the public internet.'
          : 'Restrict this admin panel (IP allow-list/VPN), ensure it does not use default/weak credentials, and add MFA.',
      source: `defcred-${type || 'panel'}`,
    });
  }
  return out;
}

export function extractDefaultCredsFindings(command, output) {
  if (!/CREDFIND\t/.test(String(output || ''))) return [];
  return dedupCap(parseCredReport(output), 150);
}

export function renderDefaultCreds(output) {
  const finds = parseCredReport(output);
  if (!finds.length) return '_No exposed admin panels, default credentials, or unauthenticated services found on the tested paths._';
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  finds.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  const hit = finds.filter((f) => /default-cred|anon-access/.test(f.source));
  const panels = finds.filter((f) => !/default-cred|anon-access/.test(f.source));
  const parts = [];
  if (hit.length) parts.push('**🚨 Credential / access issues:**\n' + hit.map((f) => `- **${f.severity.toUpperCase()}** ${f.title}\n  ↳ ${f.evidence}\n  ↳ fix: ${f.remediation}`).join('\n'));
  if (panels.length) parts.push('**🔎 Exposed panels (review for weak creds):**\n' + panels.map((f) => `- ${f.title}`).join('\n'));
  return parts.join('\n\n');
}
