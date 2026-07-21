// PHASE 3 — Public storage bucket detection.
//
// Powers the ```buckets agent tag. Goes far deeper than the quick bucket check inside the `cloud`
// tag: it derives many keyword permutations from the target and probes AWS S3 (virtual + path
// style), Google Cloud Storage, Azure Blob and DigitalOcean Spaces, classifying each hit as:
//   • PUBLIC & LISTABLE (HIGH) — anonymous listing works; sample object keys are captured
//   • EXISTS but PRIVATE (LOW) — bucket/account exists (AccessDenied) = a named target for the attacker
// Emits `BUCKETFIND\t<sev>\t<provider>\t<title>\t<evidence>\t<url>` lines → parseBucketReport().
// Every generated command passes `bash -n`.

import { normSev, dedupCap } from '../appsec/engine.js';

function hostOf(t) {
  return String(t || '').trim().replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/[^\w.\-]/g, '').toLowerCase();
}
function sld(host) {
  const p = host.split('.').filter(Boolean);
  return p.length >= 2 ? p[p.length - 2] : (p[0] || 'app');
}
// Bucket-name-safe keyword permutations from a host (+ optional extra seed word).
export function bucketKeywords(host, extra, { deep = false } = {}) {
  const clean = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9-]/g, '');
  // Seed (user-supplied brand keyword) goes FIRST so its permutations survive the cap.
  const bases = [...new Set([clean(extra), clean(sld(host)), clean(host.replace(/\./g, '')), clean(host.replace(/\./g, '-'))].filter(Boolean))];
  const affixesFast = ['assets', 'static', 'backup', 'prod', 'dev', 'media', 'uploads', 'files', 'data', 'public', 'cdn', 'images'];
  const affixesDeep = [...affixesFast, 'backups', 'staging', 'img', 'downloads', 'logs', 'dump', 'archive', 'storage', 'web', 'api', 'test', 'user', 'users', 'content', 'private', 'tmp', 'db', 'app', 'internal', 'secret'];
  const affixes = deep ? affixesDeep : affixesFast;
  const out = new Set();
  for (const b of bases) {
    out.add(b);
    for (const a of affixes) { out.add(`${b}-${a}`); out.add(`${b}${a}`); if (deep) out.add(`${a}-${b}`); }
  }
  // S3 bucket names are 3–63 chars; drop invalid.
  return [...out].filter((k) => k.length >= 3 && k.length <= 63).slice(0, deep ? 220 : 60);
}

export function buildBucketScan(target, { deep = false, seed } = {}) {
  const host = hostOf(target);
  const kws = bucketKeywords(host, seed, { deep });
  // Parallel design: one exported `check` fn handles all providers; xargs -P 20 fans out the
  // (provider bucket) jobs concurrently so 60–220 candidates finish in seconds (a short BUCKETFIND
  // printf is atomic < PIPE_BUF, so parallel emits don't interleave). Brace-free bash (no JS ${}).
  const providers = deep ? ['s3', 'gcs', 'azure', 'do'] : ['s3', 'gcs'];
  return [
    `KWS="${kws.join(' ')}";`,
    `emit(){ printf 'BUCKETFIND\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$1" "$2" "$3" "$4" "$5"; };`,
    `check(){`,
    `  set -- $1; prov="$1"; b="$2"; t=$(mktemp);`,
    `  if [ "$prov" = s3 ]; then`,
    `    code=$(curl -s -m 4 -o "$t" -w '%{http_code}' "https://$b.s3.amazonaws.com/" 2>/dev/null);`,
    `    if grep -q ListBucketResult "$t" 2>/dev/null; then k=$(grep -oE '<Key>[^<]+' "$t" | head -3 | sed 's/<Key>//' | tr '\\n' ','); [ -z "$k" ] && k='(empty listing)'; emit high s3 "PUBLIC S3 bucket is world-listable: $b" "objects: $k" "https://$b.s3.amazonaws.com/";`,
    `    elif [ "$code" = 403 ] || grep -q AccessDenied "$t" 2>/dev/null; then emit low s3 "S3 bucket exists but is private: $b" "HTTP 403 / AccessDenied" "https://$b.s3.amazonaws.com/"; fi;`,
    `  elif [ "$prov" = gcs ]; then`,
    `    code=$(curl -s -m 4 -o "$t" -w '%{http_code}' "https://storage.googleapis.com/$b/" 2>/dev/null);`,
    `    if grep -qE 'ListBucketResult|<Contents>' "$t" 2>/dev/null; then emit high gcs "PUBLIC GCS bucket is world-listable: $b" "storage.googleapis.com/$b" "https://storage.googleapis.com/$b/";`,
    `    elif [ "$code" = 403 ] || grep -q AccessDenied "$t" 2>/dev/null; then emit low gcs "GCS bucket exists but is private: $b" "HTTP 403 / AccessDenied" "https://storage.googleapis.com/$b/"; fi;`,
    `  elif [ "$prov" = azure ]; then`,
    `    code=$(curl -s -m 4 -o "$t" -w '%{http_code}' "https://$b.blob.core.windows.net/$b?restype=container&comp=list" 2>/dev/null);`,
    `    if grep -qE 'EnumerationResults|<Blob>' "$t" 2>/dev/null; then emit high azure "PUBLIC Azure blob container is listable: $b" "$b.blob.core.windows.net" "https://$b.blob.core.windows.net/$b?restype=container&comp=list";`,
    `    elif echo "$code" | grep -qE '40[034]'; then emit low azure "Azure storage account exists: $b" "HTTP $code (account resolves)" "https://$b.blob.core.windows.net/"; fi;`,
    `  elif [ "$prov" = do ]; then`,
    `    for r in nyc3 sgp1; do code=$(curl -s -m 4 -o "$t" -w '%{http_code}' "https://$b.$r.digitaloceanspaces.com/" 2>/dev/null); if grep -q ListBucketResult "$t" 2>/dev/null; then emit high do-spaces "PUBLIC DO Space is listable: $b ($r)" "$b.$r.digitaloceanspaces.com" "https://$b.$r.digitaloceanspaces.com/"; break; fi; done;`,
    `  fi;`,
    `  rm -f "$t";`,
    `};`,
    `export -f check emit;`,
    `echo "== bucket enum: ${host} (${kws.length} candidates x ${providers.length} providers${deep ? ', deep' : ''}) =="`,
    `for b in $KWS; do ${providers.map((p) => `echo "${p} $b";`).join(' ')} done | xargs -P 20 -I{} bash -c 'check "{}"';`,
    `echo "== bucket enum complete =="`,
  ].join('\n');
}

// Passthrough for raw tools, else build the enum. Grammar: "<domain> [deep] [seed:<word>]".
export function buildBucketCommand(body) {
  const raw = String(body || '').trim();
  if (!raw) return null;
  if (/^(cloud_enum|s3scanner|cloudbrute|gcpbucketbrute|lazys3)\b/i.test(raw)) return raw;
  const tokens = raw.split(/\s+/);
  const target = tokens[0];
  const deep = tokens.some((t) => /^deep$/i.test(t));
  const seed = (tokens.find((t) => /^seed:/i.test(t)) || '').split(':')[1];
  return buildBucketScan(target, { deep, seed });
}

export function parseBucketReport(output) {
  const out = [];
  for (const line of String(output || '').split('\n')) {
    if (!line.startsWith('BUCKETFIND\t')) continue;
    const [, sev, provider, title, evidence, url] = line.split('\t');
    if (!title) continue;
    out.push({
      finding_type: 'storage',
      severity: normSev(sev),
      title: title.slice(0, 200),
      host: (url || '').slice(0, 200) || null,
      service: provider || null,
      evidence: (evidence || '').slice(0, 240),
      remediation: /PUBLIC/i.test(title)
        ? 'Make the bucket/container PRIVATE immediately: enable S3 Block Public Access / remove allUsers (GCS) / set container access to Private (Azure). Audit what was exposed and rotate any secrets found.'
        : 'Bucket/account exists but is private — confirm least-privilege ACLs and that no path is unintentionally public.',
      source: provider ? `bucket-${provider}` : 'buckets',
    });
  }
  return out;
}

export function extractBucketFindings(command, output) {
  if (!/BUCKETFIND\t/.test(String(output || ''))) return [];
  return dedupCap(parseBucketReport(output), 200);
}

export function renderBuckets(output) {
  const finds = parseBucketReport(output);
  if (!finds.length) return '_No public or private storage buckets found for the tested keyword permutations._';
  const pub = finds.filter((f) => /PUBLIC/i.test(f.title));
  const priv = finds.filter((f) => !/PUBLIC/i.test(f.title));
  const parts = [];
  if (pub.length) parts.push('**🔓 Public / listable buckets:**\n' + pub.map((f) => `- **${f.severity.toUpperCase()}** ${f.title}\n  ↳ ${f.evidence}\n  ↳ ${f.host}`).join('\n'));
  if (priv.length) parts.push('**🔒 Existing (private) buckets — named targets:**\n' + priv.map((f) => `- ${f.title} — ${f.evidence}`).join('\n'));
  return parts.join('\n\n');
}
