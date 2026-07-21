// PHASE 11 — Authentication & session weaknesses.
//
// Powers the ```authsession agent tag. Non-destructive review of a web target's auth/session security:
//   • Cookie flags: session cookies missing Secure / HttpOnly / SameSite (hijacking, XSS theft, CSRF).
//   • Auth security headers: missing HSTS (SSL-strip), missing X-Frame-Options/CSP frame-ancestors
//     (clickjacking a login page = credential theft), missing X-Content-Type-Options.
//   • CORS: reflects an arbitrary Origin (optionally with Access-Control-Allow-Credentials:true) — lets a
//     malicious site read authenticated responses / steal tokens.
//   • Login form: served/submitted over HTTP, no CSRF token, password field with autocomplete on.
//   • JWT: any JWT seen in a cookie/body is decoded — alg:"none" (signature bypass) or no exp claim.
//   • Discovery: OIDC /.well-known/openid-configuration, HTTP Basic auth over cleartext.
// Emits AUTHFIND<TAB>sev<TAB>type<TAB>title<TAB>evidence<TAB>url. finding_type 'auth-session'. GET/OPTIONS
// only (a benign forged Origin header) — nothing destructive. Hits a remote target -> AUTHORIZATION-GATED.

import { normSev, dedupCap } from '../appsec/engine.js';

function hostOf(t) { return String(t || '').trim().replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/[^\w.\-]/g, '').toLowerCase(); }
function urlOf(t) {
  const s = String(t || '').trim();
  const u = /^https?:\/\//i.test(s) ? s : 'https://' + s.replace(/^[a-z]+:\/\//i, '');
  return u.replace(/[^\w.\-:/?=&%#~+]/g, '').replace(/\/+$/, '');
}

export function buildAuthSessionScan(target) {
  const url = urlOf(target);
  const host = hostOf(target);
  const lines = [
    `URL="${url}"; HOST="${host}";`,
    `emit(){ printf 'AUTHFIND\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$1" "$2" "$3" "$4" "$5"; };`,
    `echo "== auth & session review: $URL =="`,
    `echo "AUTHSESS-BEGIN $URL";`,
    `H=$(mktemp); B=$(mktemp);`,
    `curl -s -k -L -m 12 -D "$H" -o "$B" "$URL" 2>/dev/null;`,
    // ---- 1. Set-Cookie flags ----
    `echo "-- cookies --";`,
    `grep -iE '^set-cookie:' "$H" 2>/dev/null | while IFS= read -r c; do`,
    `  c=$(printf '%s' "$c" | tr -d '\\r');`,
    `  name=$(printf '%s' "$c" | sed -E 's/^[Ss]et-[Cc]ookie:\\s*([^=]+)=.*/\\1/');`,
    `  sessish=0; printf '%s' "$name" | grep -qiE 'sess|sid|token|jwt|auth|login|csrf|connect' && sessish=1;`,
    `  printf '%s' "$c" | grep -qi 'HttpOnly' || { [ "$sessish" = 1 ] && emit medium cookie-httponly "Session cookie \\"$name\\" is missing HttpOnly" "$c" "$URL" || emit low cookie-httponly "Cookie \\"$name\\" is missing HttpOnly" "$c" "$URL"; };`,
    `  printf '%s' "$c" | grep -qi 'Secure' || emit medium cookie-secure "Cookie \\"$name\\" is missing the Secure flag" "$c" "$URL";`,
    `  printf '%s' "$c" | grep -qi 'SameSite' || emit low cookie-samesite "Cookie \\"$name\\" has no SameSite attribute (CSRF exposure)" "$c" "$URL";`,
    `done;`,
    // ---- 2. security headers ----
    `echo "-- security headers --";`,
    `grep -qi '^strict-transport-security:' "$H" || emit medium no-hsts "No HSTS header (Strict-Transport-Security) — vulnerable to SSL-strip / downgrade" "HSTS absent on $URL" "$URL";`,
    `grep -qiE '^x-frame-options:|content-security-policy:.*frame-ancestors' "$H" || emit medium clickjacking "No X-Frame-Options / CSP frame-ancestors — login page can be framed (clickjacking -> credential theft)" "no anti-framing header" "$URL";`,
    `grep -qi '^x-content-type-options:' "$H" || emit low no-xcto "No X-Content-Type-Options: nosniff header" "MIME-sniffing not disabled" "$URL";`,
    `grep -qiE '^www-authenticate:\\s*basic' "$H" && case "$URL" in http://*) emit high basic-http "HTTP Basic authentication over cleartext HTTP" "credentials sent base64 in the clear" "$URL";; esac;`,
    // ---- 3. CORS misconfiguration (forged Origin) ----
    `echo "-- CORS --";`,
    `EVIL="https://evil.attacker.example";`,
    `CH=$(curl -s -k -L -m 10 -H "Origin: $EVIL" -D - -o /dev/null "$URL" 2>/dev/null | tr -d '\\r');`,
    `acao=$(printf '%s' "$CH" | grep -iE '^access-control-allow-origin:' | head -1);`,
    `acac=$(printf '%s' "$CH" | grep -iE '^access-control-allow-credentials:\\s*true' | head -1);`,
    `if printf '%s' "$acao" | grep -qi "$EVIL"; then`,
    `  if [ -n "$acac" ]; then emit high cors-credentials "CORS reflects an arbitrary Origin AND allows credentials" "$acao / $acac" "$URL";`,
    `  else emit medium cors-reflect "CORS reflects an arbitrary Origin (evil.attacker.example)" "$acao" "$URL"; fi;`,
    `elif printf '%s' "$acao" | grep -qiE 'allow-origin:\\s*\\*'; then`,
    `  [ -n "$acac" ] && emit high cors-credentials "CORS wildcard * with credentials (invalid+dangerous)" "$acao / $acac" "$URL" || emit low cors-wildcard "CORS Access-Control-Allow-Origin: * (fine only for public, unauthenticated data)" "$acao" "$URL";`,
    `fi;`,
    // ---- 4. HTTP -> HTTPS downgrade for login ----
    `echo "-- transport --";`,
    `redir=$(curl -s -k -m 8 -o /dev/null -w '%{http_code} %{redirect_url}' "http://$HOST/" 2>/dev/null);`,
    `printf '%s' "$redir" | grep -qE '^(30[1278])' && printf '%s' "$redir" | grep -qi 'https://' || emit medium no-https-redirect "http:// does not redirect to https:// (creds/session can be sent in cleartext)" "http://$HOST -> $redir" "http://$HOST";`,
    // ---- 5. login form review ----
    `echo "-- login form --";`,
    `for lp in "" login signin sign-in account/login user/login auth/login users/sign_in wp-login.php; do`,
    `  u="$URL/$lp"; [ -z "$lp" ] && u="$URL";`,
    `  pg=$(curl -s -k -L -m 10 "$u" 2>/dev/null);`,
    `  if printf '%s' "$pg" | grep -qiE 'type=["'\\'']?password'; then`,
    `    emit info login-found "Login form found: $u" "contains a password field" "$u";`,
    `    printf '%s' "$pg" | grep -qiE 'csrf|authenticity_token|__requestverificationtoken|xsrf' || emit medium login-nocsrf "Login form has no visible CSRF token: $u" "no csrf/authenticity_token/xsrf field in the form" "$u";`,
    `    printf '%s' "$pg" | grep -qiE 'type=["'\\'']?password[^>]*autocomplete=["'\\'']?off' || printf '%s' "$pg" | grep -qiE 'autocomplete=["'\\'']?off' || emit low pw-autocomplete "Password field allows autocomplete (browser may cache credentials): $u" "no autocomplete=off on the password field" "$u";`,
    `    break;`,
    `  fi;`,
    `done;`,
    // ---- 6. JWT decode (from cookies or body) ----
    `echo "-- JWT --";`,
    `jwt=$( (cat "$H"; cat "$B") | grep -aoiE 'eyJ[A-Za-z0-9_-]{5,}\\.eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*' | head -1);`,
    `if [ -n "$jwt" ]; then`,
    `  hdr=$(printf '%s' "$jwt" | cut -d. -f1); pl=$(printf '%s' "$jwt" | cut -d. -f2);`,
    `  pad(){ s="$1"; while [ $(( \${#s} % 4 )) -ne 0 ]; do s="\${s}="; done; printf '%s' "$s"; };`,
    `  hjson=$(printf '%s' "$(pad "$hdr")" | tr '_-' '/+' | base64 -d 2>/dev/null);`,
    `  pjson=$(printf '%s' "$(pad "$pl")" | tr '_-' '/+' | base64 -d 2>/dev/null);`,
    `  emit info jwt-found "JWT present in the response/cookies" "header: $(printf '%s' "$hjson" | head -c 80)" "$URL";`,
    `  printf '%s' "$hjson" | grep -qiE '"alg"\\s*:\\s*"none"' && emit critical jwt-none "JWT uses alg:none (signature not verified — trivial forgery)" "$hjson" "$URL";`,
    `  printf '%s' "$hjson" | grep -qiE '"alg"\\s*:\\s*"HS256"' && emit info jwt-hs256 "JWT signed with HS256 (verify the secret is strong & not a known/default key)" "$hjson" "$URL";`,
    `  printf '%s' "$pjson" | grep -qi '"exp"' || emit low jwt-noexp "JWT has no exp (expiry) claim — tokens never expire" "$(printf '%s' "$pjson" | head -c 80)" "$URL";`,
    `fi;`,
    // ---- 7. OIDC discovery ----
    `oc=$(curl -s -k -L -m 8 "$URL/.well-known/openid-configuration" 2>/dev/null);`,
    `printf '%s' "$oc" | grep -qi '"authorization_endpoint"' && emit info oidc "OpenID Connect discovery document exposed" "/.well-known/openid-configuration present" "$URL/.well-known/openid-configuration";`,
    `rm -f "$H" "$B";`,
    `echo "AUTHSESS-END";`,
  ];
  return lines.join('\n');
}

export function buildAuthSessionCommand(body) {
  const raw = String(body || '').trim();
  if (!raw) return null;
  if (/^(curl|jwt_tool|jwt-tool|hydra|ffuf|cookie-monster)\b/i.test(raw)) return raw; // passthrough
  const target = raw.split(/\s+/).find((t) => /^https?:\/\//i.test(t) || /\./.test(t)) || raw.split(/\s+/)[0];
  if (!target) return null;
  return buildAuthSessionScan(target);
}

const TYPE_META = {
  'cookie-httponly': { cwe: 'CWE-1004', fix: 'Set HttpOnly on all session/auth cookies so JavaScript (and thus XSS) cannot read them.' },
  'cookie-secure': { cwe: 'CWE-614', fix: 'Set the Secure flag so cookies are only sent over HTTPS (never in cleartext).' },
  'cookie-samesite': { cwe: 'CWE-1275', fix: 'Set SameSite=Lax or Strict on session cookies to blunt CSRF.' },
  'no-hsts': { cwe: 'CWE-319', fix: 'Send Strict-Transport-Security (max-age>=31536000; includeSubDomains; preload) to prevent SSL-strip/downgrade.' },
  'clickjacking': { cwe: 'CWE-1021', fix: 'Add X-Frame-Options: DENY (or CSP frame-ancestors \'none\') so the login/app cannot be framed.' },
  'no-xcto': { cwe: 'CWE-693', fix: 'Add X-Content-Type-Options: nosniff.' },
  'basic-http': { cwe: 'CWE-319', fix: 'Never use HTTP Basic auth over cleartext — require HTTPS and a proper session mechanism.' },
  'cors-credentials': { cwe: 'CWE-942', fix: 'Never reflect arbitrary Origins with Access-Control-Allow-Credentials:true. Use a strict server-side allow-list of trusted origins.' },
  'cors-reflect': { cwe: 'CWE-942', fix: 'Do not echo the request Origin into Access-Control-Allow-Origin. Allow-list specific trusted origins only.' },
  'cors-wildcard': { cwe: 'CWE-942', fix: 'ACAO:* is acceptable only for public, unauthenticated data; never combine it with credentials.' },
  'no-https-redirect': { cwe: 'CWE-319', fix: 'Force an HTTP->HTTPS 301 redirect and enable HSTS so login/session data is never sent in cleartext.' },
  'login-nocsrf': { cwe: 'CWE-352', fix: 'Add an anti-CSRF token (or SameSite cookies + origin checks) to the login and all state-changing forms.' },
  'pw-autocomplete': { cwe: 'CWE-522', fix: 'On shared-device apps, consider disabling autocomplete on sensitive fields; ensure the transport and storage are otherwise hardened.' },
  'jwt-none': { cwe: 'CWE-347', fix: 'Reject alg:none and enforce a fixed expected algorithm server-side; verify every token signature.' },
  'jwt-noexp': { cwe: 'CWE-613', fix: 'Add a short exp claim to JWTs and honor it; use refresh tokens for longer sessions.' },
};

export function parseAuthSessionReport(output) {
  const out = [];
  for (const line of String(output || '').split('\n')) {
    if (!line.startsWith('AUTHFIND\t')) continue;
    const [, sev, type, title, evidence, url] = line.split('\t');
    if (!title) continue;
    const meta = TYPE_META[type];
    out.push({
      finding_type: 'auth-session',
      severity: normSev(sev),
      title: title.slice(0, 200),
      host: (url || '').slice(0, 200) || null,
      evidence: (evidence || '').slice(0, 240),
      cve: meta ? meta.cwe : null,
      remediation: meta ? meta.fix : 'Review this authentication/session control and harden it.',
      source: `auth-${type || 'x'}`,
    });
  }
  return out;
}

export function extractAuthSessionFindings(command, output) {
  if (!/AUTHFIND\t/.test(String(output || ''))) return [];
  return dedupCap(parseAuthSessionReport(output), 150);
}

export function renderAuthSession(output) {
  const finds = parseAuthSessionReport(output);
  if (!finds.length) return '_No authentication or session weaknesses surfaced on the checked controls (cookies, headers, CORS, login form, JWT)._';
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  finds.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  const issues = finds.filter((f) => f.severity !== 'info');
  const info = finds.filter((f) => f.severity === 'info');
  const parts = [];
  if (issues.length) parts.push('**🔐 Auth/session weaknesses:**\n' + issues.map((f) => `- **${f.severity.toUpperCase()}** ${f.title}${f.cve ? ` [${f.cve}]` : ''}\n  ↳ fix: ${f.remediation}`).join('\n'));
  if (info.length) parts.push('**ℹ️ Auth surface:**\n' + info.map((f) => `- ${f.title}`).join('\n'));
  return parts.join('\n\n');
}
