// PHASE 10 — API endpoint & parameter discovery.
//
// Powers the ```apidiscover agent tag. Maps a web target's API attack surface, non-destructively:
//   • API specs: probes common OpenAPI/Swagger locations (openapi.json, swagger.json, v2/v3 api-docs,
//     swagger-ui, redoc) and the RFC-8631 Link: rel=service-doc/service-desc header; when a spec is found
//     it uses jq to enumerate every path + HTTP method (and counts parameters).
//   • JS mining: fetches the page's script bundles and regexes out API paths (/api/…, fetch()/axios URLs,
//     v1/v2 routes, graphql) — the endpoints a SPA actually calls.
//   • GraphQL: sends an introspection query to /graphql and flags if the schema is exposed.
//   • HTTP methods: an OPTIONS request enumerates allowed verbs and flags dangerous ones (PUT/DELETE/TRACE).
// Emits APIFIND<TAB>sev<TAB>type<TAB>title<TAB>evidence<TAB>url. finding_type 'api-discovery'. Most results
// are discovery (info); introspection/exposed-spec/dangerous-methods carry a real severity. GET/OPTIONS/
// benign introspection only — nothing destructive. Hits a remote target -> AUTHORIZATION-GATED.

import { normSev, dedupCap } from '../appsec/engine.js';

function urlOf(t) {
  const s = String(t || '').trim();
  if (!s) return null;
  const u = /^https?:\/\//i.test(s) ? s : 'https://' + s.replace(/^[a-z]+:\/\//i, '');
  return u.replace(/[^\w.\-:/?=&%#~+]/g, '').replace(/\/+$/, '');
}

// Common API spec / doc locations to probe.
const SPEC_PATHS = [
  'openapi.json', 'swagger.json', 'swagger/v1/swagger.json', 'v2/api-docs', 'v3/api-docs', 'api-docs',
  'api/openapi.json', 'api/swagger.json', 'api/v1/openapi.json', 'openapi.yaml', 'swagger.yaml',
  'swagger-ui.html', 'swagger-ui/', 'api/docs', 'docs/api', 'redoc', '.well-known/openapi',
];

export function buildApiDiscoverScan(target) {
  const url = urlOf(target);
  const specList = SPEC_PATHS.join(' ');
  const lines = [
    `URL="${url}";`,
    `emit(){ printf 'APIFIND\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$1" "$2" "$3" "$4" "$5"; };`,
    `command -v jq >/dev/null 2>&1 || { apt-get update -y >/dev/null 2>&1; apt-get install -y jq >/dev/null 2>&1; };`,
    `echo "== API endpoint & parameter discovery: $URL =="`,
    `echo "APIDISC-BEGIN $URL";`,
    // ---- 1. Link: rel=service-doc / service-desc (RFC 8631) ----
    `H=$(curl -s -k -L -m 12 -D - -o /dev/null "$URL" 2>/dev/null);`,
    `printf '%s' "$H" | grep -qiE 'rel="?service-(doc|desc)' && emit info api-doc "API documentation advertised via Link header" "$(printf '%s' "$H" | grep -iE 'link:.*service-(doc|desc)' | head -1 | tr -d '\\r' | cut -c1-160)" "$URL";`,
    // ---- 2. probe API spec locations ----
    `echo "-- API spec probing --";`,
    `for p in ${specList}; do`,
    `  b=$(mktemp); code=$(curl -s -k -L -m 8 -o "$b" -w '%{http_code}' "$URL/$p" 2>/dev/null);`,
    `  if [ "$code" = "200" ]; then`,
    `    if grep -qiE '"(openapi|swagger)"\\s*:' "$b" 2>/dev/null; then`,
    `      ver=$(jq -r '.openapi // .swagger // "?"' "$b" 2>/dev/null);`,
    `      np=$(jq -r '.paths | length' "$b" 2>/dev/null || echo '?');`,
    `      emit medium api-spec "Exposed OpenAPI/Swagger spec ($np paths, v$ver): /$p" "machine-readable API spec is publicly served" "$URL/$p";`,
    `      jq -r '.paths | to_entries[] | .key as $p | (.value | to_entries[] | "\\(.key|ascii_upcase) \\($p) params=\\((.value.parameters // [])|length)")' "$b" 2>/dev/null | head -60 | while read -r line; do emit info api-endpoint "API endpoint: $line" "from OpenAPI spec /$p" "$URL"; done;`,
    `    elif grep -qiE 'swagger-ui|redoc|swaggerui|openapi' "$b" 2>/dev/null; then`,
    `      emit low api-doc "Interactive API docs UI exposed: /$p" "Swagger-UI/Redoc served in production" "$URL/$p";`,
    `    fi;`,
    `  fi; rm -f "$b";`,
    `done;`,
    // ---- 3. GraphQL introspection ----
    `echo "-- GraphQL introspection --";`,
    `for gp in graphql api/graphql v1/graphql graphql/console; do`,
    `  g=$(curl -s -k -L -m 8 -H 'Content-Type: application/json' -d '{"query":"{__schema{queryType{name}}}"}' "$URL/$gp" 2>/dev/null);`,
    `  if printf '%s' "$g" | grep -qE '"__schema"|"queryType"'; then emit medium graphql-introspection "GraphQL introspection is ENABLED: /$gp" "schema is fully enumerable by anyone (aids attack mapping)" "$URL/$gp"; break; fi;`,
    `done;`,
    // ---- 4. endpoints mined from JS bundles ----
    `echo "-- JS endpoint mining --";`,
    `page=$(curl -s -k -L -m 12 "$URL" 2>/dev/null);`,
    `srcs=$(printf '%s' "$page" | grep -aoiE 'src="[^"]+\\.js[^"]*"' | sed -E 's/src="//;s/"$//' | head -10);`,
    `tmpe=$(mktemp);`,
    `for s in $srcs; do`,
    `  case "$s" in http*) js="$s";; /*) js="$URL$s";; *) js="$URL/$s";; esac;`,
    `  curl -s -k -L -m 8 "$js" 2>/dev/null | grep -aoiE '(/(api|v[0-9]|rest|graphql)/[A-Za-z0-9_./-]{2,60})|"/[A-Za-z0-9_./-]*(api|graphql)[A-Za-z0-9_./-]*"' ;`,
    `done | tr -d '"' | sort -u | head -40 >> "$tmpe";`,
    `cnt=$(wc -l < "$tmpe" | tr -d ' ');`,
    `if [ "$cnt" -gt 0 ]; then emit info api-jssurface "$cnt API path(s) referenced in the app's JavaScript" "mined from JS bundles (top shown as endpoints)" "$URL"; while read -r ep; do [ -n "$ep" ] && emit info api-endpoint "API path (from JS): $ep" "referenced in a JS bundle" "$URL$ep"; done < "$tmpe"; fi;`,
    `rm -f "$tmpe";`,
    // ---- 5. HTTP methods via OPTIONS ----
    `echo "-- HTTP methods (OPTIONS) --";`,
    `al=$(curl -s -k -L -m 8 -X OPTIONS -D - -o /dev/null "$URL" 2>/dev/null | grep -iE '^allow:|access-control-allow-methods:' | head -1 | tr -d '\\r');`,
    `if [ -n "$al" ]; then`,
    `  emit info http-methods "Allowed HTTP methods: $al" "OPTIONS response" "$URL";`,
    `  printf '%s' "$al" | grep -qiE '\\b(PUT|DELETE|PATCH)\\b' && emit low http-methods-write "State-changing HTTP methods enabled (PUT/DELETE/PATCH)" "$al" "$URL";`,
    `  printf '%s' "$al" | grep -qiE '\\bTRACE\\b' && emit low http-trace "HTTP TRACE method enabled (Cross-Site Tracing risk)" "$al" "$URL";`,
    `fi;`,
    `echo "APIDISC-END";`,
  ];
  return lines.join('\n');
}

export function buildApiDiscoverCommand(body) {
  const raw = String(body || '').trim();
  if (!raw) return null;
  if (/^(curl|ffuf|kiterunner|kr|arjun|gau|waybackurls|hakrawler)\b/i.test(raw)) return raw; // passthrough
  const target = raw.split(/\s+/).find((t) => /^https?:\/\//i.test(t) || /\./.test(t)) || raw.split(/\s+/)[0];
  if (!target) return null;
  return buildApiDiscoverScan(target);
}

const TYPE_META = {
  'api-spec': { cwe: 'CWE-200', fix: 'If the OpenAPI/Swagger spec is not meant to be public, restrict it to authenticated/internal users; a full spec hands attackers every endpoint, method and parameter.' },
  'graphql-introspection': { cwe: 'CWE-200', fix: 'Disable GraphQL introspection in production and enforce a query allow-list / depth+cost limits; require auth.' },
  'api-doc': { cwe: 'CWE-200', fix: 'Do not serve interactive API docs (Swagger-UI/Redoc) in production, or gate them behind auth.' },
  'http-methods-write': { cwe: 'CWE-650', fix: 'Disable HTTP methods the endpoint does not need; ensure PUT/DELETE/PATCH enforce authentication and authorization.' },
  'http-trace': { cwe: 'CWE-693', fix: 'Disable the TRACE method at the web server to prevent Cross-Site Tracing.' },
};

export function parseApiDiscoverReport(output) {
  const out = [];
  for (const line of String(output || '').split('\n')) {
    if (!line.startsWith('APIFIND\t')) continue;
    const [, sev, type, title, evidence, url] = line.split('\t');
    if (!title) continue;
    const meta = TYPE_META[type];
    out.push({
      finding_type: 'api-discovery',
      severity: normSev(sev),
      title: title.slice(0, 200),
      host: (url || '').slice(0, 200) || null,
      evidence: (evidence || '').slice(0, 240),
      cve: meta ? meta.cwe : null,
      remediation: meta ? meta.fix : 'Review this API surface: ensure every endpoint enforces authentication/authorization and input validation.',
      source: `api-${type || 'x'}`,
    });
  }
  return out;
}

export function extractApiDiscoverFindings(command, output) {
  if (!/APIFIND\t/.test(String(output || ''))) return [];
  // Endpoint-inventory lines are informational; keep them but cap generously.
  return dedupCap(parseApiDiscoverReport(output), 200);
}

export function renderApiDiscover(output) {
  const finds = parseApiDiscoverReport(output);
  if (!finds.length) return '_No API specs, GraphQL introspection, JS-referenced endpoints, or notable HTTP methods discovered on this target._';
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  finds.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  const issues = finds.filter((f) => f.severity !== 'info');
  const endpoints = finds.filter((f) => f.source === 'api-api-endpoint');
  const surface = finds.filter((f) => f.severity === 'info' && f.source !== 'api-api-endpoint');
  const parts = [];
  if (issues.length) parts.push('**🔎 API exposure issues:**\n' + issues.map((f) => `- **${f.severity.toUpperCase()}** ${f.title}${f.cve ? ` [${f.cve}]` : ''}\n  ↳ fix: ${f.remediation}`).join('\n'));
  if (surface.length) parts.push('**🌐 API surface:**\n' + surface.map((f) => `- ${f.title}`).join('\n'));
  if (endpoints.length) {
    const shown = endpoints.slice(0, 40).map((f) => `- ${f.title.replace(/^API endpoint: |^API path \(from JS\): /, '')}`).join('\n');
    parts.push(`**📇 Discovered endpoints (${endpoints.length}):**\n` + shown + (endpoints.length > 40 ? `\n…and ${endpoints.length - 40} more` : ''));
  }
  return parts.join('\n\n');
}
