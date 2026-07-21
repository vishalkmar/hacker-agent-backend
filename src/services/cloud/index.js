// PHASE 1 — Cloud misconfiguration scanning (AWS / Azure / GCP).
//
// Powers the ```cloud agent tag. Two modes:
//   • DOMAIN mode (default, uncredentialed): external cloud-posture assessment of a target domain —
//     which cloud/CDN it runs on, publicly-listable storage buckets (S3/GCS/Azure), exposed
//     secret/env/config files over HTTP, and nuclei cloud/exposure/takeover templates. This is what
//     runs when the body is a domain/URL and is fully testable against a live target.
//   • CREDENTIALED CSPM mode: `cloud aws|azure|gcp` → Prowler (self-installs) audits the account the
//     ambient credentials point at (hundreds of CIS/misconfig checks: public buckets, over-permissive
//     IAM, default creds, exposed secrets, logging, encryption…). Results parsed from Prowler JSON.
//
// The domain script emits normalized `CLOUDFIND\t<sev>\t<type>\t<title>\t<evidence>\t<remediation>`
// lines which parseCloudReport() turns into findings — deterministic, unit-testable, and it also
// prints a human-readable section. Every generated command passes `bash -n`.

import { ensure, normSev, parseJsonLoose, dedupCap } from '../appsec/engine.js';

// ---- helpers -------------------------------------------------------------------------------
function hostOf(target) {
  return String(target || '').trim()
    .replace(/^[a-z]+:\/\//i, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '')
    .replace(/[^\w.\-]/g, '')
    .toLowerCase();
}
function urlOf(target) {
  const t = String(target || '').trim();
  if (/^https?:\/\//i.test(t)) return t.replace(/[^\w.\-:/?=&%#]/g, '');
  return 'https://' + hostOf(t);
}
// Second-level label ("iamalive" from "iamalive.app" or "www.iamalive.app") for bucket guessing.
function keyword(host) {
  const parts = host.split('.').filter(Boolean);
  if (parts.length >= 2) return parts[parts.length - 2];
  return parts[0] || 'app';
}

// Prowler / ScoutSuite installers (heavy; only used in credentialed mode).
const PROWLER = ensure('prowler', { pip: 'prowler' });
const NUCLEI = ensure('nuclei', { apt: 'nuclei' });

// ---- DOMAIN mode: external cloud-posture script --------------------------------------------
export function buildCloudDomainScan(target, { deep = false } = {}) {
  const url = urlOf(target);
  const host = hostOf(target);
  const kw = keyword(host);
  // nuclei is slow (template load + hundreds of templates). Default = a 60s-bounded, cloud-focused
  // pass that returns whatever it flushed (findings stream to -o incrementally); `deep` = full sweep.
  const nucleiCmd = deep
    ? `timeout 300 nuclei -u "$U" -tags aws,azure,gcp,cloud,takeover,exposure,config -duc -c 50 -rl 150 -mhe 30 -silent -j -o /tmp/cf_nuclei.json 2>/dev/null; cat /tmp/cf_nuclei.json 2>/dev/null;`
    : `timeout 60 nuclei -u "$U" -tags aws,azure,gcp,cloud -duc -c 60 -rl 200 -mhe 30 -silent -j -o /tmp/cf_nuclei.json 2>/dev/null; cat /tmp/cf_nuclei.json 2>/dev/null;`;
  // Single self-contained bash script. Brace-free bash vars ($U not ${U}) so JS doesn't interpolate.
  return [
    `U="${url}"; HOST="${host}"; KW="${kw}";`,
    `prov(){ printf 'CLOUDFIND\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$1" "$2" "$3" "$4" "$5"; };`,
    `echo "== Cloud posture: $HOST =="`,
    // resolve + headers
    `IP=$(getent hosts "$HOST" 2>/dev/null | awk '{print $1}' | head -1);`,
    `H=$(curl -sSL -m 15 -D - -o /dev/null "$U" 2>/dev/null);`,
    // follow the apex->www (or http->https) redirect so file/path probes hit the canonical host
    `EFF=$(curl -sSL -m 15 -o /dev/null -w '%{url_effective}' "$U" 2>/dev/null); [ -n "$EFF" ] && U=$(echo "$EFF" | sed 's:/*$::');`,
    `echo "resolved: $IP"`,
    // ---- cloud/CDN provider fingerprinting (headers + IP heuristics) ----
    `echo "$H" | grep -qi 'x-vercel-id' && prov info provider "Origin hosted on Vercel" "$(echo "$H" | grep -i x-vercel-id | head -1 | tr -d '\\r')" "Lock down Vercel project: disable public preview deployments, review env vars & team access.";`,
    `echo "$H" | grep -qiE 'server: *cloudflare|cf-ray:' && prov info provider "Fronted by Cloudflare (CDN/WAF)" "server: cloudflare" "Ensure the origin IP is hidden and the origin firewall only allows Cloudflare IP ranges (prevents WAF bypass).";`,
    `echo "$H" | grep -qiE 'x-amz-|amazonaws|server: *AmazonS3|x-amz-cf-id' && prov info provider "AWS assets detected (S3/CloudFront)" "$(echo "$H" | grep -iE 'x-amz-|amazonaws' | head -1 | tr -d '\\r')" "Review S3 bucket policies & CloudFront OAC; ensure no public ACLs.";`,
    `echo "$H" | grep -qiE 'x-azure-ref|azureedge|azurewebsites|x-ms-' && prov info provider "Azure assets detected" "$(echo "$H" | grep -iE 'x-azure|x-ms-' | head -1 | tr -d '\\r')" "Review Azure Storage anonymous-access & App Service settings.";`,
    `echo "$H" | grep -qiE 'x-goog-|googleusercontent|appspot|gws|server: *GSE' && prov info provider "GCP/Google assets detected" "$(echo "$H" | grep -iE 'x-goog-|gws' | head -1 | tr -d '\\r')" "Review GCS bucket IAM (remove allUsers/allAuthenticatedUsers).";`,
    `echo "$H" | grep -qi 'x-fastly\\|fastly' && prov info provider "Fastly CDN detected" "fastly header" "Verify origin shielding & TLS config.";`,
    // email/cloud SaaS from MX
    `MX=$(dig +short "$HOST" MX 2>/dev/null | tr '\\n' ' ');`,
    `echo "$MX" | grep -qi 'google\\|aspmx' && prov info provider "Email on Google Workspace" "MX: $MX" "Enforce SPF/DKIM/DMARC; review Workspace admin MFA.";`,
    `echo "$MX" | grep -qi 'outlook\\|protection.outlook' && prov info provider "Email on Microsoft 365" "MX: $MX" "Enforce DMARC; review M365 conditional access.";`,
    // ---- exposed secret / env / config files over HTTP ----
    `for p in .env .env.local .env.production .git/config .git/HEAD .aws/credentials config.json settings.py wp-config.php docker-compose.yml .npmrc .dockercfg .DS_Store phpinfo.php server-status actuator/env .well-known/security.txt; do`,
    `  code=$(curl -s -m 8 -o /tmp/cf_body -w '%{http_code}' "$U/$p" 2>/dev/null);`,
    // Only a real hit: HTTP 200 AND the body is NOT an HTML page (SPA fallbacks return 200 index.html
    // for every path — flagging those would be a false positive) AND it carries secret/config content.
    `  if [ "$code" = "200" ] && ! grep -qiE '<html|<!doctype|<head|<body' /tmp/cf_body 2>/dev/null; then`,
    `    sz=$(wc -c </tmp/cf_body 2>/dev/null | tr -d ' ');`,
    `    if grep -qiE 'secret|api[_-]?key|password|token|aws_access|BEGIN (RSA|PRIVATE)|DB_(PASS|HOST)|\\[core\\]|^ref:| instance_url' /tmp/cf_body 2>/dev/null || echo "$p" | grep -qE 'env|cred|npmrc|dockercfg'; then`,
    `      prov high exposed-file "Exposed sensitive file: /$p" "HTTP 200, $sz bytes (non-HTML) at $U/$p" "Remove /$p from the web root and rotate any leaked credentials immediately.";`,
    `    fi;`,
    `  fi;`,
    `done;`,
    // ---- public storage bucket enumeration (S3 / GCS / Azure) by keyword ----
    `for b in "$KW" "$KW-assets" "$KW-static" "$KW-backup" "$KW-prod" "$KW-dev" "$KW-media" "$KW-uploads" "$KW-public" "$HOST"; do`,
    `  s3c=$(curl -s -m 6 -o /tmp/cf_s3 -w '%{http_code}' "https://$b.s3.amazonaws.com/" 2>/dev/null);`,
    `  if [ "$s3c" = "200" ] && grep -q 'ListBucketResult' /tmp/cf_s3 2>/dev/null; then prov high public-bucket "Public S3 bucket is world-listable: $b" "https://$b.s3.amazonaws.com/ returned 200 + ListBucketResult" "Enable S3 Block Public Access; remove public ACLs/policy; make objects private."; fi;`,
    `  gcc=$(curl -s -m 6 -o /tmp/cf_gc -w '%{http_code}' "https://storage.googleapis.com/$b/" 2>/dev/null);`,
    `  if [ "$gcc" = "200" ] && grep -qE 'ListBucketResult|<Contents>' /tmp/cf_gc 2>/dev/null; then prov high public-bucket "Public GCS bucket is world-listable: $b" "storage.googleapis.com/$b returned 200" "Remove allUsers/allAuthenticatedUsers from the bucket IAM; enable uniform bucket-level access."; fi;`,
    `  azc=$(curl -s -m 6 -o /tmp/cf_az -w '%{http_code}' "https://$b.blob.core.windows.net/$b?restype=container&comp=list" 2>/dev/null);`,
    `  if [ "$azc" = "200" ] && grep -qE 'EnumerationResults|<Blob>' /tmp/cf_az 2>/dev/null; then prov high public-bucket "Public Azure blob container: $b" "$b.blob.core.windows.net anonymous list = 200" "Set container public access level to Private on the storage account."; fi;`,
    `done;`,
    // ---- nuclei cloud/exposure/takeover (bonus; parsed by the web-finding extractor too) ----
    // nuclei cloud templates (bounded; see nucleiCmd above). JSONL parsed by the existing nuclei
    // parser (services/scan/webparsers.js).
    NUCLEI + nucleiCmd,
    `rm -f /tmp/cf_body /tmp/cf_s3 /tmp/cf_gc /tmp/cf_az;`,
    `echo "== cloud scan complete =="`,
  ].join('\n');
}

// ---- CREDENTIALED CSPM mode: Prowler --------------------------------------------------------
export function buildCloudCspm(provider = 'aws') {
  const p = String(provider || 'aws').toLowerCase();
  const prov = ['aws', 'azure', 'gcp', 'kubernetes'].includes(p) ? p : 'aws';
  return `${PROWLER}O=$(mktemp -d); prowler ${prov} -M json-ocsf --output-directory "$O" >/dev/null 2>&1; cat "$O"/*.json 2>/dev/null | head -c 4000000; rm -rf "$O"`;
}

// ---- dispatcher ----------------------------------------------------------------------------
const CSPM_RE = /^(aws|azure|gcp|kubernetes)\b/i;
const RAW_RE = /^(prowler|scout|scoutsuite|nuclei|s3scanner|cloudbrute|cloud_enum)\b/i;
export function buildCloudCommand(body) {
  const raw = String(body || '').trim();
  if (!raw) return null;
  if (RAW_RE.test(raw)) return raw; // power-user raw command
  const tokens = raw.split(/\s+/);
  const first = tokens[0];
  if (CSPM_RE.test(first)) return buildCloudCspm(first);
  const deep = tokens.some((t) => /^deep$/i.test(t));
  return buildCloudDomainScan(first, { deep });
}

// ---- parsers -------------------------------------------------------------------------------
// Normalized CLOUDFIND lines from the domain script.
export function parseCloudReport(output) {
  const out = [];
  for (const line of String(output || '').split('\n')) {
    if (!line.startsWith('CLOUDFIND\t')) continue;
    const parts = line.split('\t');
    const [, sev, type, title, evidence, remediation] = parts;
    if (!title) continue;
    out.push({
      finding_type: 'cloud',
      severity: normSev(sev),
      title: title.slice(0, 200),
      evidence: (evidence || '').slice(0, 240),
      remediation: (remediation || '').slice(0, 300),
      source: type || 'cloud',
    });
  }
  return out;
}

// Prowler JSON (handles v3 PascalCase and v4/OCSF snake_case; only FAILed checks become findings).
export function parseProwler(json) {
  const arr = Array.isArray(json) ? json : (json?.findings || []);
  if (!Array.isArray(arr)) return [];
  const out = [];
  for (const f of arr) {
    const status = String(f.status_code || f.status || f.Status || f.StatusExtended || '').toLowerCase();
    if (/pass|manual|info|skip/.test(status)) continue;
    const sev = f.severity || f.Severity || f.severity_id || (f.finding_info && f.finding_info.severity);
    const resource = f.resource_uid || f.ResourceId || f.resource_id ||
      (Array.isArray(f.resources) && f.resources[0] && (f.resources[0].uid || f.resources[0].name)) || f.region || f.Region;
    const rem = f.remediation?.recommendation?.text || f.Remediation?.Recommendation?.Text ||
      f.remediation_recommendation_text || f.risk_details || '';
    out.push({
      finding_type: 'cloud',
      severity: normSev(sev),
      title: String(f.check_title || f.CheckTitle || f.finding_info?.title || f.check_id || f.CheckID || 'Cloud misconfiguration').slice(0, 200),
      host: resource ? String(resource).slice(0, 200) : null,
      service: f.service_name || f.ServiceName || null,
      evidence: String(f.status_detail || f.StatusExtended || f.finding_info?.desc || '').slice(0, 240),
      remediation: String(rem).slice(0, 300),
      source: 'prowler',
    });
  }
  return out;
}

// Global extractor — added to the agent's finding pipeline. Inert unless the output carries
// CLOUDFIND lines or the command ran prowler.
export function extractCloudFindings(command, output) {
  const cmd = String(command || '');
  const out = [];
  if (/CLOUDFIND\t/.test(output)) out.push(...parseCloudReport(output));
  if (/\bprowler\b/.test(cmd)) {
    const j = parseJsonLoose(output);
    if (j) out.push(...parseProwler(j));
  }
  return dedupCap(out, 150);
}

// ---- human-readable rendering --------------------------------------------------------------
// Turn the raw script output (CLOUDFIND lines + echoes) into a clean summary for the chat.
export function renderCloud(output) {
  const lines = String(output || '').split('\n');
  const finds = parseCloudReport(output);
  const providers = finds.filter((f) => f.source === 'provider');
  const risks = finds.filter((f) => f.source !== 'provider');
  const resolved = lines.find((l) => l.startsWith('resolved:'));
  const parts = [];
  if (resolved) parts.push(`**Resolved:** ${resolved.replace('resolved:', '').trim() || '(behind CDN)'}`);
  if (providers.length) parts.push('**Cloud footprint:**\n' + providers.map((p) => `- ${p.title} — _${p.evidence}_`).join('\n'));
  if (risks.length) {
    parts.push('**Misconfigurations / exposure:**\n' + risks.map((r) => `- **${r.severity.toUpperCase()}** ${r.title}\n  ↳ ${r.evidence}\n  ↳ fix: ${r.remediation}`).join('\n'));
  } else {
    parts.push('_No public buckets or exposed secret/env files found on the tested paths._');
  }
  return parts.join('\n\n') || '(no cloud output)';
}
