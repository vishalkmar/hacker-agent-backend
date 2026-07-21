// PHASE 2 — Exposed environment variables & secrets detection (live web target).
//
// Powers the ```websecrets agent tag. Distinct from the appsec `secrets`/`gitsecrets` tags (which
// scan LOCAL source/git) — this hunts secrets that a LIVE web app leaks to the browser:
//   • API keys / tokens baked into JS bundles (SPA/Next.js NEXT_PUBLIC_* vars, Firebase configs,
//     Stripe/Google/AWS/GitHub/Slack/SendGrid/Mapbox keys, private keys, JWTs)
//   • web-served config/env/dotfiles (.env, .env.production, .git/config, config.json, actuator/env)
//   • exposed JavaScript source maps (.js.map → full source + often secrets)
//
// The script downloads the homepage, extracts asset URLs, pulls each JS/JSON/map, and greps for a
// library of secret patterns, emitting `SECRETFIND\t<sev>\t<type>\t<title>\t<evidence>\t<location>`
// lines that parseSecretReport() turns into findings. Every generated command passes `bash -n`.

import { normSev, dedupCap } from '../appsec/engine.js';

function hostOf(t) {
  return String(t || '').trim().replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/[^\w.\-]/g, '').toLowerCase();
}
function urlOf(t) {
  const s = String(t || '').trim();
  return /^https?:\/\//i.test(s) ? s.replace(/[^\w.\-:/?=&%#]/g, '') : 'https://' + hostOf(t);
}

// Build the live secret-exposure scan for a target URL/domain.
export function buildWebSecretsScan(target, { maxAssets = 30 } = {}) {
  const url = urlOf(target);
  const host = hostOf(target);
  const base = 'https://' + host;
  // Brace-free bash vars so JS template literals don't interpolate ${...}; redaction via sed (no braces).
  return [
    `U="${url}"; BASE="${base}"; D=$(mktemp -d);`,
    `emit(){ printf 'SECRETFIND\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$1" "$2" "$3" "$4" "$5"; };`,
    `red(){ echo "$1" | sed -E 's/(.{12}).*/\\1…[redacted]/'; };`,
    // one file scanned against the whole pattern library
    `scan(){`,
    `  f="$1"; src="$2"; [ -s "$f" ] || return;`,
    `  m=$(grep -aoE 'AKIA[0-9A-Z]{16}' "$f" | head -1); [ -n "$m" ] && emit critical aws-key "AWS access key ID exposed in JS" "$(red "$m") @ $src" "$src";`,
    `  m=$(grep -aoE 'sk_live_[0-9a-zA-Z]{20,}' "$f" | head -1); [ -n "$m" ] && emit critical stripe-secret "Stripe LIVE secret key exposed" "$(red "$m") @ $src" "$src";`,
    `  m=$(grep -aoE 'ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{40,}' "$f" | head -1); [ -n "$m" ] && emit critical github-pat "GitHub personal access token exposed" "$(red "$m") @ $src" "$src";`,
    `  m=$(grep -aoE 'SG\\.[0-9A-Za-z_-]{20,}\\.[0-9A-Za-z_-]{30,}' "$f" | head -1); [ -n "$m" ] && emit critical sendgrid "SendGrid API key exposed" "$(red "$m") @ $src" "$src";`,
    `  m=$(grep -aoE 'xox[baprs]-[0-9A-Za-z-]{10,}' "$f" | head -1); [ -n "$m" ] && emit high slack-token "Slack token exposed" "$(red "$m") @ $src" "$src";`,
    `  m=$(grep -aoE 'AIza[0-9A-Za-z_-]{35}' "$f" | head -1); [ -n "$m" ] && emit medium google-api-key "Google API key in JS (restrict by referrer/API)" "$(red "$m") @ $src" "$src";`,
    `  m=$(grep -aoE 'pk\\.eyJ[0-9A-Za-z_.-]{50,}' "$f" | head -1); [ -n "$m" ] && emit medium mapbox "Mapbox access token in JS" "$(red "$m") @ $src" "$src";`,
    `  grep -aqE 'BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY' "$f" && emit critical private-key "Private key material exposed in asset" "PEM private key block @ $src" "$src";`,
    `  grep -aqiE 'firebaseConfig|apiKey["'"'"':\\s=]+[\"'"'"']AIza' "$f" && emit medium firebase "Firebase client config exposed (apiKey/projectId)" "firebaseConfig object @ $src" "$src";`,
    `  m=$(grep -aoE 'AC[0-9a-f]{32}' "$f" | head -1); [ -n "$m" ] && emit high twilio "Possible Twilio Account SID exposed" "$(red "$m") @ $src" "$src";`,
    `  m=$(grep -aoE 'https://[0-9a-f]{16,}@[a-z0-9.]*sentry[a-z0-9.]*/[0-9]+' "$f" | head -1); [ -n "$m" ] && emit low sentry-dsn "Sentry DSN exposed" "$(red "$m") @ $src" "$src";`,
    `  m=$(grep -aoE 'eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}' "$f" | head -1); [ -n "$m" ] && emit low jwt "JWT embedded in client asset (verify it is not a privileged token)" "$(red "$m") @ $src" "$src";`,
    `  m=$(grep -aoE '(secret|api[_-]?key|access[_-]?token|private[_-]?key|client[_-]?secret)["'"'"':\\s=]+[\"'"'"'][^\"'"'"']{12,}' "$f" | head -1); [ -n "$m" ] && emit medium generic-secret "Hardcoded secret-like assignment in JS" "$(red "$m") @ $src" "$src";`,
    `  n=$(grep -aoE 'NEXT_PUBLIC_[A-Z0-9_]+|VITE_[A-Z0-9_]+|REACT_APP_[A-Z0-9_]+' "$f" | sort -u | head -8 | tr '\\n' ' '); [ -n "$n" ] && emit info env-var "Client-exposed build env vars" "$n @ $src" "$src";`,
    `};`,
    // fetch homepage + follow redirect
    `EFF=$(curl -sSL -m 15 -o "$D/index.html" -w '%{url_effective}' "$U" 2>/dev/null); [ -n "$EFF" ] && BASE=$(echo "$EFF" | sed -E 's~^(https?://[^/]+).*~\\1~');`,
    `echo "== websecrets: $U (base $BASE) =="`,
    // scan inline HTML too
    `scan "$D/index.html" "$U (inline)";`,
    // extract asset URLs (js/json/map) referenced in HTML
    `grep -aoE '(src|href)="[^"]+\\.(js|json|map)"' "$D/index.html" 2>/dev/null | sed 's/.*="//;s/"$//' | sort -u > "$D/assets.txt";`,
    `grep -aoE '"[^"]+\\.(js|json|map)"' "$D/index.html" 2>/dev/null | tr -d '"' | sort -u >> "$D/assets.txt";`,
    `i=0;`,
    `while read a; do`,
    `  [ -z "$a" ] && continue;`,
    `  case "$a" in http*) url="$a";; //*) url="https:$a";; /*) url="$BASE$a";; *) url="$BASE/$a";; esac;`,
    `  curl -sSL -m 6 "$url" -o "$D/asset_$i" 2>/dev/null;`,
    `  scan "$D/asset_$i" "$url";`,
    `  # if a .js, probe its source map`,
    `  case "$url" in *.js) mc=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$url.map" 2>/dev/null); [ "$mc" = "200" ] && emit medium source-map "Exposed JS source map (leaks source): $(basename "$url").map" "$url.map returned 200" "$url.map";; esac;`,
    `  i=$((i+1)); [ $i -ge ${maxAssets} ] && break;`,
    `done < "$D/assets.txt";`,
    // web-served dotfiles / env / config
    `for p in .env .env.local .env.production .git/config .git/HEAD config.json config.js appsettings.json .npmrc credentials.json actuator/env; do`,
    `  code=$(curl -s -m 6 -o "$D/df" -w '%{http_code}' "$BASE/$p" 2>/dev/null);`,
    `  if [ "$code" = "200" ] && ! grep -qiE '<html|<!doctype|<head|<body' "$D/df" 2>/dev/null; then`,
    `    if grep -aqiE 'secret|api[_-]?key|password|token|aws_access|BEGIN (RSA|PRIVATE)|DB_(PASS|HOST)|\\[core\\]|^ref:' "$D/df" 2>/dev/null || echo "$p" | grep -qE 'env|git|npmrc|cred'; then`,
    `      emit high exposed-file "Web-served secret/config file: /$p" "HTTP 200 (non-HTML) at $BASE/$p" "$BASE/$p";`,
    `    fi;`,
    `  fi;`,
    `done;`,
    `rm -rf "$D";`,
    `echo "== websecrets scan complete =="`,
  ].join('\n');
}

// Passthrough for a raw command (trufflehog/gitleaks/etc.), else build the live scan.
export function buildWebSecretsCommand(body) {
  const raw = String(body || '').trim();
  if (!raw) return null;
  if (/^(trufflehog|gitleaks|secretfinder|mantra|jsluice|linkfinder)\b/i.test(raw)) return raw;
  const maxAssets = /\bdeep\b/i.test(raw) ? 80 : 30;
  return buildWebSecretsScan(raw.split(/\s+/)[0], { maxAssets });
}

// Parse SECRETFIND lines into findings.
export function parseSecretReport(output) {
  const out = [];
  for (const line of String(output || '').split('\n')) {
    if (!line.startsWith('SECRETFIND\t')) continue;
    const [, sev, type, title, evidence, location] = line.split('\t');
    if (!title) continue;
    out.push({
      finding_type: 'secret',
      severity: normSev(sev),
      title: title.slice(0, 200),
      host: (location || '').slice(0, 200) || null,
      evidence: (evidence || '').slice(0, 240),
      cve: /key|token|secret|pat|private/i.test(type || '') ? 'CWE-798' : null,
      remediation: remediationForType(type),
      source: type || 'websecrets',
    });
  }
  return out;
}

function remediationForType(type) {
  const t = String(type || '');
  if (/aws-key|stripe|github|sendgrid|slack|private-key|twilio/.test(t)) return 'Revoke/rotate this credential NOW (assume compromised). Never ship server secrets to the browser — move to a backend proxy/env; the client bundle is public.';
  if (/google-api|mapbox|firebase/.test(t)) return 'These client keys are visible by design, but LOCK THEM DOWN: restrict by HTTP referrer/domain, API, and quota; enable Firebase security rules; monitor usage.';
  if (/source-map/.test(t)) return 'Disable source-map upload to production (or restrict access); they expose your full source and often secrets.';
  if (/exposed-file/.test(t)) return 'Remove the file from the web root and rotate any credentials it contained.';
  if (/env-var/.test(t)) return 'Confirm no sensitive values are prefixed NEXT_PUBLIC_/VITE_/REACT_APP_ (those are embedded in client JS).';
  if (/jwt/.test(t)) return 'Confirm this JWT is a public/anon token (e.g. Supabase anon) and not a privileged session/service token.';
  return 'Review this exposure and rotate if it grants access.';
}

export function extractWebSecretsFindings(command, output) {
  if (!/SECRETFIND\t/.test(String(output || ''))) return [];
  return dedupCap(parseSecretReport(output), 150);
}

// Human-readable rendering for the chat.
export function renderWebSecrets(output) {
  const finds = parseSecretReport(output);
  if (!finds.length) return '_No exposed secrets, env files, or source maps found on the tested assets._';
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  finds.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  return `**Exposed secrets & env (${finds.length}):**\n` +
    finds.map((f) => `- **${f.severity.toUpperCase()}** ${f.title}\n  ↳ ${f.evidence}\n  ↳ fix: ${f.remediation}`).join('\n');
}
