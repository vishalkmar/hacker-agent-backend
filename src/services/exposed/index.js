// PHASE 6 — Exposed databases, dashboards & admin panels.
//
// Powers the ```exposed agent tag. Where Phase 5 (defaultcreds) tests whether a login accepts default
// credentials, Phase 6 hunts the more dangerous case: services that leak data or grant control with NO
// authentication at all. It probes, on the target:
//   • Unauthenticated data stores — Elasticsearch (/_cat/indices, /_cluster/health), CouchDB (/_all_dbs),
//     Kibana, Prometheus (/metrics), Grafana anonymous, MongoDB HTTP, CouchDB.
//   • Exposed control-plane APIs — Docker daemon (:2375/version), Kubernetes API/kubelet, Consul, etcd,
//     Spring Boot Actuator (/actuator/env, /heapdump), Jenkins script console.
//   • Exposed dashboards / admin panels — Grafana, Kibana, Prometheus, RabbitMQ mgmt, Airflow, Traefik,
//     Portainer, MinIO console, phpMyAdmin, Adminer, pgAdmin, Zabbix, Kubernetes Dashboard.
//   • deep: nmap -sV + NSE (redis-info, mongodb-info, mysql-info, http-title) on DB/dashboard ports to
//     confirm raw (non-HTTP) database services reachable from the internet.
// Each check has a deterministic body/header signature, so a hit means the service is genuinely exposed
// (low false-positive). Emits `EXPOFIND<TAB><sev><TAB><type><TAB><title><TAB><evidence><TAB><url>`.
// Actively probes a remote target -> AUTHORIZATION-GATED. bash -n clean.

import { normSev, dedupCap } from '../appsec/engine.js';

function hostOf(t) { return String(t || '').trim().replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/[^\w.\-]/g, '').toLowerCase(); }

// HTTP-speaking exposures probed on their own host:port. sig = case-insensitive regex proving the
// service is really there AND unauthenticated. sev/type drive the finding.
// Fields: name | port | scheme | path | sig | sev | type
const HTTP_CHECKS = [
  ['Elasticsearch', 9200, 'http', '/_cluster/health', 'cluster_name|"status":"(green|yellow|red)"', 'critical', 'exposed-db'],
  ['Elasticsearch indices', 9200, 'http', '/_cat/indices?format=json', '"index"|"docs.count"|health.*status', 'critical', 'exposed-db'],
  ['CouchDB', 5984, 'http', '/_all_dbs', '^\\s*\\[', 'critical', 'exposed-db'],
  ['CouchDB welcome', 5984, 'http', '/', '"couchdb":"Welcome"', 'high', 'exposed-db'],
  ['MongoDB HTTP console', 28017, 'http', '/', 'mongod|db version|replSet', 'high', 'exposed-db'],
  ['Prometheus', 9090, 'http', '/api/v1/status/buildinfo', '"status":"success".*version|"version"', 'high', 'exposed-dashboard'],
  ['Prometheus metrics', 9090, 'http', '/metrics', '# HELP|# TYPE', 'medium', 'exposed-dashboard'],
  ['Grafana', 3000, 'http', '/api/health', '"database":\\s*"ok"', 'high', 'exposed-dashboard'],
  ['Kibana', 5601, 'http', '/api/status', '"name"|"kibana"|"status":\\{', 'high', 'exposed-dashboard'],
  ['Docker Engine API', 2375, 'http', '/version', '"ApiVersion"|"GoVersion"', 'critical', 'exposed-api'],
  ['Docker Engine API (TLS)', 2376, 'https', '/version', '"ApiVersion"|"GoVersion"', 'critical', 'exposed-api'],
  ['Consul', 8500, 'http', '/v1/status/leader', '^\\s*"\\d+\\.\\d+\\.\\d+\\.\\d+:', 'high', 'exposed-api'],
  ['etcd', 2379, 'http', '/version', '"etcdserver"|"etcdcluster"', 'critical', 'exposed-api'],
  ['Kubernetes API (insecure)', 8080, 'http', '/api', '"kind":"APIVersions"|"serverAddressByClientCIDRs"', 'critical', 'exposed-api'],
  ['Kubernetes API', 6443, 'https', '/version', '"gitVersion"|"buildDate"', 'high', 'exposed-api'],
  ['Kubelet', 10250, 'https', '/pods', '"kind":"PodList"|"apiVersion"', 'critical', 'exposed-api'],
  ['Spark Master UI', 8080, 'http', '/', 'Spark Master at|Spark Jobs', 'medium', 'exposed-dashboard'],
  ['Airflow', 8080, 'http', '/health', '"metadatabase"|"scheduler"', 'high', 'exposed-dashboard'],
  ['RabbitMQ Management', 15672, 'http', '/', 'RabbitMQ Management', 'medium', 'exposed-dashboard'],
  ['Traefik dashboard', 8080, 'http', '/dashboard/', 'Traefik|<title>Traefik', 'medium', 'exposed-dashboard'],
  ['MinIO console', 9001, 'http', '/', 'MinIO Console|minio', 'medium', 'exposed-dashboard'],
  ['Portainer', 9000, 'http', '/api/status', '"Version"|Portainer', 'medium', 'exposed-dashboard'],
];

// Path-based exposures probed on the MAIN web host (443) — catch reverse-proxied services and app
// endpoints. These are the highest-value checks against a normal website behind a CDN.
// Fields: path | sig | sev | type | title
const PATH_CHECKS = [
  ['/actuator/env', '"activeProfiles"|"propertySources"|systemProperties', 'high', 'exposed-api', 'Spring Boot Actuator /env exposed (leaks env vars & config)'],
  ['/actuator/heapdump', 'application/octet-stream|JAVA PROFILE|HPROF', 'critical', 'exposed-api', 'Spring Boot Actuator /heapdump exposed (full memory dump — secrets)'],
  ['/actuator', '"_links"|"health"|"metrics"', 'medium', 'exposed-api', 'Spring Boot Actuator index exposed'],
  ['/_cat/indices?format=json', '"index"|"docs.count"', 'critical', 'exposed-db', 'Elasticsearch reachable via web host (/_cat/indices)'],
  ['/_all_dbs', '^\\s*\\["', 'critical', 'exposed-db', 'CouchDB reachable via web host (/_all_dbs)'],
  ['/api/v1/status/config', '"yaml"|global:', 'high', 'exposed-dashboard', 'Prometheus config exposed via web host'],
  ['/metrics', '# HELP|# TYPE|process_cpu', 'low', 'exposed-dashboard', 'Prometheus/exporter /metrics exposed (info leak)'],
  ['/script', 'Script Console|Groovy script', 'critical', 'exposed-api', 'Jenkins script console reachable (RCE)'],
  ['/debug/pprof/', 'Types of profiles available|goroutine', 'high', 'exposed-api', 'Go net/http/pprof debug endpoint exposed'],
  ['/.git/HEAD', 'ref:\\s*refs/', 'high', 'exposed-db', 'Exposed .git repository (source & secrets recoverable)'],
  ['/graphql', '__schema|"data":\\{|GraphQL', 'low', 'exposed-api', 'GraphQL endpoint present (check introspection/authz)'],
];

// Raw (non-HTTP) database & service ports confirmed via nmap -sV in deep mode.
const DEEP_PORTS = '21,1433,1521,2375,2379,3000,3306,5432,5601,5984,6379,7000,8080,8086,9042,9092,9200,9300,11211,15672,27017,28017,50070';

export function buildExposedScan(target, { deep = false } = {}) {
  const host = hostOf(target);
  const base = 'https://' + host;
  // Serialize as one TAB-delimited record per line (sig regexes contain '|', so '|' can't be the
  // field separator; tabs never appear in a name/path/sig/title). One record per line.
  const httpTable = HTTP_CHECKS.map((c) => c.join('\t')).join('\n');
  const pathTable = PATH_CHECKS.map((c) => c.join('\t')).join('\n');
  const lines = [
    `HOST="${host}"; BASE="${base}";`,
    `emit(){ printf 'EXPOFIND\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$1" "$2" "$3" "$4" "$5"; };`,
    `echo "== exposure scan: ${host}${deep ? ' (deep)' : ''} =="`,
    // --- direct host:port service probes ---
    `echo "-- data stores / dashboards / control-plane APIs --"`,
    `checkhttp(){`,
    `  name="$1"; port="$2"; scheme="$3"; path="$4"; sig="$5"; sev="$6"; typ="$7";`,
    `  url="$scheme://$HOST:$port$path"; b=$(mktemp);`,
    `  code=$(curl -sk -m 6 -o "$b" -w '%{http_code}' "$url" 2>/dev/null);`,
    `  case "$code" in 000|"") rm -f "$b"; return;; esac;`,
    `  if [ "$code" = "401" ] || [ "$code" = "403" ]; then`,
    `    emit low protected "$name present but authenticated ($scheme:$port)" "HTTP $code at $url" "$url"; rm -f "$b"; return;`,
    `  fi;`,
    `  if grep -qiE "$sig" "$b" 2>/dev/null; then`,
    `    ev=$(grep -aioE "$sig" "$b" | head -1);`,
    `    emit "$sev" "$typ" "$name exposed WITHOUT authentication (HTTP $code)" "$url matched: $ev" "$url";`,
    `  fi; rm -f "$b";`,
    `};`,
    // Read the TAB-delimited table line by line and probe ports in parallel (background jobs inherit
    // the functions automatically). A jobs throttle caps concurrency at 12. Avoids xargs quote-parsing,
    // which chokes on the '"' inside the sig regexes.
    `throttle(){ while [ "$(jobs -r | wc -l)" -ge "$1" ]; do wait -n 2>/dev/null || sleep 0.2; done; };`,
    `printf '%s\\n' ${shSingle(httpTable)} | { while IFS="$(printf '\\t')" read -r name port scheme path sig sev typ; do`,
    `  [ -n "$name" ] || continue; checkhttp "$name" "$port" "$scheme" "$path" "$sig" "$sev" "$typ" & throttle 12;`,
    `done; wait; };`,
    // --- path probes on the main web host (443) ---
    `echo "-- application/proxied exposure paths on ${host}:443 --"`,
    `checkpath(){`,
    `  path="$1"; sig="$2"; sev="$3"; typ="$4"; title="$5";`,
    `  url="$BASE$path"; h=$(mktemp); b=$(mktemp);`,
    `  code=$(curl -sk -m 7 -D "$h" -o "$b" -w '%{http_code}' "$url" 2>/dev/null);`,
    `  case "$code" in 200) : ;; *) rm -f "$h" "$b"; return;; esac;`,
    // require the signature in the BODY or (for binary dumps) in the content-type header
    `  if grep -qiE "$sig" "$b" 2>/dev/null || grep -qiE "$sig" "$h" 2>/dev/null; then`,
    `    ev=$( (grep -aioE "$sig" "$b"; grep -aioE "$sig" "$h") 2>/dev/null | head -1);`,
    `    emit "$sev" "$typ" "$title" "HTTP 200 at $url (matched: $ev)" "$url";`,
    `  fi; rm -f "$h" "$b";`,
    `};`,
    `printf '%s\\n' ${shSingle(pathTable)} | { while IFS="$(printf '\\t')" read -r path sig sev typ title; do`,
    `  [ -n "$path" ] || continue; checkpath "$path" "$sig" "$sev" "$typ" "$title" & throttle 8;`,
    `done; wait; };`,
  ];
  if (deep) {
    lines.push(
      `echo "-- deep: nmap service/version scan of DB & dashboard ports --"`,
      `command -v nmap >/dev/null 2>&1 || { apt-get update -y >/dev/null 2>&1; apt-get install -y nmap >/dev/null 2>&1; };`,
      `N=$(mktemp);`,
      `nmap -Pn -T4 -sV --version-light --script "redis-info,mongodb-info,mysql-info,ms-sql-info,pgsql-brute,http-title,rdp-ntlm-info" -p ${DEEP_PORTS} "${host}" -oN "$N" >/dev/null 2>&1;`,
      `grep -qiE '6379/tcp\\s+open' "$N" && emit high exposed-db "Redis port 6379 reachable from the internet" "nmap: $(grep -iE '6379/tcp' "$N" | head -1)" "${host}:6379";`,
      `grep -qiE '27017/tcp\\s+open' "$N" && emit high exposed-db "MongoDB port 27017 reachable from the internet" "nmap: $(grep -iE '27017/tcp' "$N" | head -1)" "${host}:27017";`,
      `grep -qiE '3306/tcp\\s+open' "$N" && emit medium exposed-db "MySQL port 3306 reachable from the internet" "nmap: $(grep -iE '3306/tcp' "$N" | head -1)" "${host}:3306";`,
      `grep -qiE '5432/tcp\\s+open' "$N" && emit medium exposed-db "PostgreSQL port 5432 reachable from the internet" "nmap: $(grep -iE '5432/tcp' "$N" | head -1)" "${host}:5432";`,
      `grep -qiE '11211/tcp\\s+open' "$N" && emit high exposed-db "Memcached port 11211 reachable (often no auth)" "nmap: $(grep -iE '11211/tcp' "$N" | head -1)" "${host}:11211";`,
      `grep -qiE '9200/tcp\\s+open' "$N" && emit medium exposed-db "Elasticsearch port 9200 reachable from the internet" "nmap: $(grep -iE '9200/tcp' "$N" | head -1)" "${host}:9200";`,
      `grep -qiE '1433/tcp\\s+open' "$N" && emit medium exposed-db "MSSQL port 1433 reachable from the internet" "nmap: $(grep -iE '1433/tcp' "$N" | head -1)" "${host}:1433";`,
      `grep -qiE 'Redis key-value store' "$N" && grep -qiE 'redis-info' "$N" && emit critical exposed-db "Redis answering without auth (redis-info returned data)" "nmap redis-info NSE" "${host}:6379";`,
      `rm -f "$N";`,
    );
  }
  lines.push(`echo "== exposure scan complete =="`);
  return lines.join('\n');
}

// Wrap a possibly-multiline string as a single-quoted shell literal (escape embedded single quotes).
function shSingle(s) { return `'${String(s).replace(/'/g, `'\\''`)}'`; }

export function buildExposedCommand(body) {
  const raw = String(body || '').trim();
  if (!raw) return null;
  if (/^(nmap|nuclei|masscan|curl|httpx)\b/i.test(raw)) return raw; // raw tool passthrough
  const tokens = raw.split(/\s+/);
  const deep = tokens.some((t) => /^deep$/i.test(t));
  const target = tokens.find((t) => !/^deep$/i.test(t));
  if (!target) return null;
  return buildExposedScan(target, { deep });
}

const TYPE_META = {
  'exposed-db': { finding_type: 'exposure', cwe: 'CWE-306', fix: 'Bind this datastore to localhost/VPN only, never the public internet; require authentication (and TLS); add a firewall/security-group rule blocking the port from 0.0.0.0/0.' },
  'exposed-api': { finding_type: 'exposure', cwe: 'CWE-306', fix: 'Remove this control-plane/debug endpoint from public exposure; require authentication; restrict by IP/VPN. For Docker/K8s/etcd, enable TLS + client-cert auth. Disable actuator heapdump/env in production.' },
  'exposed-dashboard': { finding_type: 'exposure', cwe: 'CWE-284', fix: 'Put this dashboard behind authentication and an IP allow-list/VPN; disable anonymous access; do not expose it directly to the internet.' },
  'protected': { finding_type: 'exposure', cwe: null, fix: 'Service is present but requires auth — verify it is not using default/weak credentials and is patched.' },
};

export function parseExposedReport(output) {
  const out = [];
  for (const line of String(output || '').split('\n')) {
    if (!line.startsWith('EXPOFIND\t')) continue;
    const [, sev, type, title, evidence, url] = line.split('\t');
    if (!title) continue;
    const meta = TYPE_META[type] || TYPE_META['exposed-api'];
    out.push({
      finding_type: meta.finding_type,
      severity: normSev(sev),
      title: title.slice(0, 200),
      host: (url || '').slice(0, 200) || null,
      evidence: (evidence || '').slice(0, 240),
      cve: meta.cwe,
      remediation: meta.fix,
      source: `exposed-${type || 'svc'}`,
    });
  }
  return out;
}

export function extractExposedFindings(command, output) {
  if (!/EXPOFIND\t/.test(String(output || ''))) return [];
  return dedupCap(parseExposedReport(output), 150);
}

export function renderExposed(output) {
  const finds = parseExposedReport(output);
  if (!finds.length) return '_No unauthenticated databases, dashboards, or control-plane APIs found exposed on the tested ports/paths._';
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  finds.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  const open = finds.filter((f) => !/-protected$/.test(f.source));
  const prot = finds.filter((f) => /-protected$/.test(f.source));
  const parts = [];
  if (open.length) parts.push('**🚨 Exposed without authentication:**\n' + open.map((f) => `- **${f.severity.toUpperCase()}** ${f.title}\n  ↳ ${f.evidence}\n  ↳ fix: ${f.remediation}`).join('\n'));
  if (prot.length) parts.push('**🔒 Present but authenticated (verify creds/patch):**\n' + prot.map((f) => `- ${f.title} — ${f.evidence}`).join('\n'));
  return parts.join('\n\n');
}
