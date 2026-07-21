// PHASE 9 — File upload, rate-limiting & input-validation testing.
//
// Powers the ```webinput agent tag. NON-DESTRUCTIVE, GET-only probing of a web target's input handling:
//   • Rate limiting: sends a small burst of requests and checks whether the app throttles (HTTP 429 /
//     RateLimit-* / Retry-After headers). No throttling on auth/API endpoints enables brute force,
//     credential stuffing and app-layer DoS.
//   • Input validation / reflection: injects a uniquely-marked canary carrying classic payloads (XSS,
//     SQL quote, path traversal) into a query parameter and inspects the response for (a) UNENCODED
//     reflection of the payload (reflected-XSS surface), (b) SQL error signatures (SQLi surface), (c) an
//     /etc/passwd signature (LFI surface), (d) whether an over-long value is accepted (no length cap).
//   • File-upload surface: fetches the page and finds <input type=file> / multipart forms and common
//     upload endpoints — the attack surface for unrestricted file upload (flagged for authorized deeper
//     testing; it does NOT upload anything).
// Emits WEBINFIND<TAB>sev<TAB>type<TAB>title<TAB>evidence<TAB>url. finding_type 'input-validation'.
// Hits a remote target -> AUTHORIZATION-GATED. bash -n clean.

import { normSev, dedupCap } from '../appsec/engine.js';
import { XSS_REFLECT_TESTS, CSTI_PROBES } from '../payloads/templates.js';

function urlOf(t) {
  const s = String(t || '').trim();
  if (!s) return null;
  return /^https?:\/\//i.test(s) ? s.replace(/[^\w.\-:/?=&%#~+]/g, '') : 'https://' + s.replace(/^[a-z]+:\/\//i, '').replace(/[^\w.\-:/?=&%#~+]/g, '');
}

export function buildWebInputScan(target, { burst = 20 } = {}) {
  const url = urlOf(target);
  const n = Math.min(Math.max(parseInt(burst, 10) || 20, 5), 40); // clamp 5..40 (non-abusive)
  // Multi-vector reflected-XSS probes generated from the curated XSS_REFLECT_TESTS: each payload is injected
  // (marker-prefixed) and we check whether it comes back UNENCODED next to the marker (proves live markup).
  // Trying several vectors catches apps that filter one tag but not another. Stops at the first confirmed hit.
  const xssProbes = XSS_REFLECT_TESTS.flatMap((t) => {
    const enc = encodeURIComponent(t.p);
    return [
      `if [ "$xssfound" = 0 ]; then r=$(probe "q=$MARK${enc}");`,
      `  printf '%s' "$r" | grep -qi "$MARK" && xssrefl=1;`,
      `  printf '%s' "$r" | grep -qiE "$MARK.{0,25}${t.sig}" && { emit high xss-reflect "Reflected XSS — the '${t.label}' vector is reflected UNENCODED (executable)" "marker reflected next to a live ${t.label} payload; app does not HTML-encode this parameter" "$URL"; xssfound=1; }; fi;`,
    ];
  });
  // Client-Side Template Injection probes: inject a marker + a math expression; if the EVALUATED result (49)
  // comes back right after the marker, the app evaluates our input as a template (AngularJS/Vue/SSTI) — a
  // separate, high-impact bug from reflected XSS. Marker-anchored so a literal "49" on the page is not a FP.
  // Escape shell-special chars ($, backtick, ", \) so a literal like ${7*7} in the emit text is NOT expanded.
  const shq = (s) => String(s).replace(/[\\$`"]/g, (c) => '\\' + c);
  const cstiProbes = CSTI_PROBES.flatMap((t) => {
    const enc = encodeURIComponent(t.inject);
    const inj = shq(t.inject);
    return [
      `if [ "$cstifound" = 0 ]; then r=$(probe "q=$MARK${enc}");`,
      `  printf '%s' "$r" | grep -qE "$MARK[^0-9]{0,3}${t.sig}" && { emit high csti "Template injection — '${shq(t.label)}' evaluated (rendered ${t.sig})" "injected ${inj} after marker; response shows the computed ${t.sig} — AngularJS/Vue/SSTI template evaluation, often escalates to XSS or RCE" "$URL"; cstifound=1; }; fi;`,
    ];
  });
  const lines = [
    `URL="${url}"; N=${n};`,
    `emit(){ printf 'WEBINFIND\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$1" "$2" "$3" "$4" "$5"; };`,
    `echo "== web input testing (upload / rate-limit / validation): $URL =="`,
    `echo "WEBIN-BEGIN $URL";`,
    // ---- 1. rate limiting: small burst, tally status codes, look for throttling ----
    `echo "-- rate-limit burst ($N requests) --";`,
    `codes=$(for i in $(seq 1 "$N"); do curl -s -k -m 8 -o /dev/null -w '%{http_code} ' "$URL"; done);`,
    `echo "status codes: $codes";`,
    `hdr=$(curl -s -k -m 8 -D - -o /dev/null "$URL" 2>/dev/null);`,
    `n429=$(printf '%s' "$codes" | tr ' ' '\\n' | grep -c '^429$' || true);`,
    `if [ "$n429" -gt 0 ]; then emit info rate-ok "Rate limiting active (saw $n429/$N HTTP 429)" "burst returned 429 Too Many Requests" "$URL";`,
    `elif printf '%s' "$hdr" | grep -qiE 'ratelimit-|x-rate-limit|retry-after'; then emit info rate-ok "Rate-limit headers present" "$(printf '%s' "$hdr" | grep -iE 'ratelimit-|x-rate-limit|retry-after' | head -1 | tr -d '\\r')" "$URL";`,
    `else emit medium rate-none "No rate limiting observed over $N rapid requests" "no 429 / RateLimit / Retry-After — endpoint permits high-rate automation (brute force / credential stuffing / app-DoS)" "$URL"; fi;`,
    // ---- 2. input validation via a marked canary ----
    `echo "-- input validation (reflection / errors) --";`,
    `MARK="CMQAz9x";`,
    `sep='?'; case "$URL" in *\\?*) sep='&';; esac;`,
    `probe(){ curl -s -k -L -m 12 "$URL$sep$1" 2>/dev/null; };`,
    // XSS reflection: try several vectors; flag if ANY reflects UNENCODED (marker-anchored, low false-positive).
    `xssfound=0; xssrefl=0;`,
    ...xssProbes,
    `[ "$xssfound" = 0 ] && [ "$xssrefl" = 1 ] && emit info reflect-safe "Input is reflected but HTML-encoded (safe against the tested XSS vectors)" "marker $MARK present in the response but all ${XSS_REFLECT_TESTS.length} payloads were encoded" "$URL";`,
    // Client-side template injection (AngularJS/Vue/SSTI): {{7*7}} -> 49
    `cstifound=0;`,
    ...cstiProbes,
    // SQL error signature
    `sqlr=$(probe "id=$MARK%27");`,
    `if printf '%s' "$sqlr" | grep -qiE 'SQL syntax|mysql_fetch|mysqli|ORA-[0-9]{5}|PostgreSQL.*ERROR|SQLite3?::|Unclosed quotation|ODBC.*Driver|syntax error at or near|SQLSTATE'; then emit high sqli-error "SQL error surfaced from a single quote (SQL injection surface)" "$(printf '%s' "$sqlr" | grep -aioiE 'SQL syntax|ORA-[0-9]{5}|PostgreSQL.*ERROR|Unclosed quotation|syntax error at or near|SQLSTATE' | head -1)" "$URL"; fi;`,
    // path traversal / LFI signature
    `lfir=$(probe "file=..%2f..%2f..%2f..%2fetc%2fpasswd");`,
    `if printf '%s' "$lfir" | grep -qE 'root:.*:0:0:'; then emit critical lfi "Path traversal returned /etc/passwd (LFI)" "response contains root:x:0:0: — server read an arbitrary file" "$URL"; fi;`,
    // input length handling
    `long=$(printf 'A%.0s' $(seq 1 6000));`,
    `lc=$(curl -s -k -m 10 -o /dev/null -w '%{http_code}' "$URL\${sep}q=$long" 2>/dev/null);`,
    `if [ "$lc" = "200" ]; then emit low no-lengthcap "6KB parameter value accepted (HTTP 200) — no obvious input-length cap" "long q= value -> HTTP 200 (verify server-side limits/WAF)" "$URL";`,
    `elif [ "$lc" = "413" ] || [ "$lc" = "414" ] || [ "$lc" = "400" ]; then emit info length-ok "Over-long input rejected (HTTP $lc)" "6KB value -> HTTP $lc" "$URL"; fi;`,
    // ---- 3. file-upload surface discovery ----
    `echo "-- file-upload surface --";`,
    `page=$(curl -s -k -m 12 -L "$URL" 2>/dev/null);`,
    `if printf '%s' "$page" | grep -qiE 'type=["'\\'']?file|enctype=["'\\'']?multipart/form-data'; then`,
    `  ev=$(printf '%s' "$page" | grep -aioE 'action=["'\\''][^"'\\'' ]+|enctype=["'\\'']?multipart/form-data' | head -2 | tr '\\n' ' ');`,
    `  emit medium upload-form "File-upload form detected — test for unrestricted upload (ext/content-type bypass)" "$ev" "$URL";`,
    `fi;`,
    // probe a few common upload endpoints (existence only)
    `for p in upload uploads api/upload file/upload admin/upload wp-admin/async-upload.php; do`,
    `  c=$(curl -s -k -m 6 -o /dev/null -w '%{http_code}' "$URL/$p" 2>/dev/null);`,
    `  case "$c" in 200|401|403|405) emit low upload-endpoint "Possible upload endpoint: /$p (HTTP $c)" "reachable — verify auth + file-type restrictions" "$URL/$p";; esac;`,
    `done;`,
    `echo "WEBIN-END";`,
  ];
  return lines.join('\n');
}

export function buildWebInputCommand(body) {
  const raw = String(body || '').trim();
  if (!raw) return null;
  if (/^(curl|ffuf|wfuzz|ab|siege|nikto|wpscan)\b/i.test(raw)) return raw; // passthrough
  const tokens = raw.split(/\s+/);
  const burstTok = tokens.find((t) => /^(burst=)?\d+$/.test(t) && !/^https?/.test(t));
  const burst = burstTok ? burstTok.replace('burst=', '') : 20;
  const target = tokens.find((t) => /^https?:\/\//i.test(t) || /\./.test(t)) || tokens[0];
  if (!target) return null;
  return buildWebInputScan(target, { burst });
}

const TYPE_META = {
  'xss-reflect': { sev: 'high', cwe: 'CWE-79', fix: 'Context-encode all reflected output (HTML/attr/JS) and add a strict Content-Security-Policy; validate/allow-list input server-side.' },
  'csti': { sev: 'high', cwe: 'CWE-1336', fix: 'Never render user input inside a client/server template expression. In AngularJS remove ng-app from user-controlled DOM (or upgrade to Angular 2+); in Vue never bind user data into v-html/templates; sandbox/escape template contexts. Often escalates to full XSS.' },
  'sqli-error': { sev: 'high', cwe: 'CWE-89', fix: 'Use parameterised queries/prepared statements everywhere; never build SQL by string concat; hide DB errors from responses.' },
  'lfi': { sev: 'critical', cwe: 'CWE-22', fix: 'Never pass user input into file paths; canonicalise and allow-list, reject "../"; run with least privilege.' },
  'rate-none': { sev: 'medium', cwe: 'CWE-307', fix: 'Add per-IP/per-account rate limiting + exponential backoff/lockout on auth and expensive endpoints; put a WAF/edge rate rule in front.' },
  'no-lengthcap': { sev: 'low', cwe: 'CWE-20', fix: 'Enforce server-side max-length on every field; reject oversized bodies (413) to prevent buffer/DoS abuse.' },
  'upload-form': { sev: 'medium', cwe: 'CWE-434', fix: 'Restrict uploads to an allow-list of extensions AND validated content-type/magic bytes; store outside web root; randomise names; scan for malware.' },
  'upload-endpoint': { sev: 'low', cwe: 'CWE-434', fix: 'Ensure the upload endpoint requires auth and enforces strict file-type/size validation and out-of-webroot storage.' },
};

export function parseWebInputReport(output) {
  const out = [];
  for (const line of String(output || '').split('\n')) {
    if (!line.startsWith('WEBINFIND\t')) continue;
    const [, sev, type, title, evidence, url] = line.split('\t');
    if (!title) continue;
    const meta = TYPE_META[type];
    out.push({
      finding_type: 'input-validation',
      severity: normSev(sev),
      title: title.slice(0, 200),
      host: (url || '').slice(0, 200) || null,
      evidence: (evidence || '').slice(0, 240),
      cve: meta ? meta.cwe : null,
      remediation: meta ? meta.fix : 'Review server-side input validation and handling for this endpoint.',
      source: `webin-${type || 'x'}`,
    });
  }
  return out;
}

export function extractWebInputFindings(command, output) {
  if (!/WEBINFIND\t/.test(String(output || ''))) return [];
  return dedupCap(parseWebInputReport(output), 120);
}

export function renderWebInput(output) {
  const finds = parseWebInputReport(output);
  if (!finds.length) return '_No input-validation, rate-limit, or file-upload issues surfaced on the non-destructive checks (or the target did not respond)._';
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  finds.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  const issues = finds.filter((f) => !/-ok$|reflect-safe|length-ok/.test(f.source));
  const good = finds.filter((f) => /-ok$|reflect-safe|length-ok/.test(f.source));
  const parts = [];
  if (issues.length) parts.push('**🚨 Input-handling weaknesses:**\n' + issues.map((f) => `- **${f.severity.toUpperCase()}** ${f.title}${f.cve ? ` [${f.cve}]` : ''}\n  ↳ ${f.evidence}\n  ↳ fix: ${f.remediation}`).join('\n'));
  if (good.length) parts.push('**✅ Good controls observed:**\n' + good.map((f) => `- ${f.title}`).join('\n'));
  return parts.join('\n\n');
}
