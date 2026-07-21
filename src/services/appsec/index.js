// AppSec / DevSecOps area registry — the 14 code-security capabilities.
//
// Each area maps a high-level intent to a real, self-installing scanner command (built here) and a
// parser (in engine.js). The agent exposes each as its own ```<area> tool tag. Areas:
//   sast · secrets · gitsecrets · sca · depcve · iac · container · config · license · supplychain
//   codereview · remediation · fixverify · cicd
//
// Scanner areas write JSON to a temp file and cat it, so the captured stdout is clean JSON. Repo
// URLs are shallow-cloned to a temp dir first. Every command is single-statement bash (bash -n safe).

import {
  INSTALL, SCANNER_BINS,
  parseSemgrep, parseBandit, parseGitleaks, parseTrivy, parseGrype, parseSyft, parseOsv, parseCheckov, parseNpmAudit,
  parseJsonLoose, dedupCap, classifyLicense,
} from './engine.js';

// ---- target handling -----------------------------------------------------------------------
// Resolve a scan target to a shell ref. A git URL is shallow-cloned into $T first; a local path is
// sanitized (shell metacharacters stripped) and quoted. Returns { prep, ref }.
function targetRef(target) {
  const t = String(target || '.').trim() || '.';
  if (/^(https?:\/\/\S+\.git|https?:\/\/(?:www\.)?(github|gitlab|bitbucket)\.com\/|git@)/i.test(t)) {
    const url = t.replace(/[^\w.\-:/@]/g, '');
    return { prep: `T=$(mktemp -d); git clone --depth 1 "${url}" "$T" >/dev/null 2>&1; `, ref: '"$T"' };
  }
  const safe = t.replace(/["'`$;|&<>(){}]/g, '');
  return { prep: '', ref: `"${safe}"` };
}
// A container image / OCI ref (nginx:1.25, ghcr.io/org/app@sha256:...). Kept to a safe charset.
function imageRef(img) {
  return String(img || '').trim().replace(/[^\w.\-:/@]/g, '') || 'alpine:latest';
}
// Wrap a scanner command that writes JSON to $O: install first, prep (clone) if needed, then cat.
const wrap = (install, prep, scan) => `${install}${prep}O=$(mktemp); ${scan}; cat "$O" 2>/dev/null; rm -f "$O"`;

// ---- the 14 areas --------------------------------------------------------------------------
export const AREAS = {
  // 1. Static Application Security Testing — semgrep across all languages (auto ruleset).
  sast: {
    label: 'SAST', kind: 'scanner',
    build(t) { const { prep, ref } = targetRef(t); return wrap(INSTALL.semgrep, prep, `semgrep --config auto --json --quiet --timeout 120 ${ref} -o "$O" 2>/dev/null`); },
  },
  // 2. Secret scanning — gitleaks on the working tree (no git history).
  secrets: {
    label: 'Secret scan', kind: 'scanner',
    build(t) { const { prep, ref } = targetRef(t); return wrap(INSTALL.gitleaks, prep, `gitleaks detect --no-git -s ${ref} -f json -r "$O" >/dev/null 2>&1 || gitleaks dir ${ref} -f json -r "$O" >/dev/null 2>&1`); },
  },
  // 3. Git history secret scanning — gitleaks across the full commit history.
  gitsecrets: {
    label: 'Git-history secret scan', kind: 'scanner',
    build(t) { const { prep, ref } = targetRef(t); return wrap(INSTALL.gitleaks, prep, `gitleaks detect -s ${ref} -f json -r "$O" >/dev/null 2>&1 || gitleaks git ${ref} -f json -r "$O" >/dev/null 2>&1`); },
  },
  // 4. Software Composition Analysis — syft SBOM (component inventory). Findings = summary, not noise.
  sca: {
    label: 'SCA / SBOM', kind: 'sbom',
    build(t) { const { prep, ref } = targetRef(t); return wrap(INSTALL.syft, prep, `syft ${ref} -o json 2>/dev/null > "$O"`); },
  },
  // 5. Dependency CVE detection — osv-scanner across every lockfile/manifest.
  depcve: {
    label: 'Dependency CVEs', kind: 'scanner',
    build(t) { const { prep, ref } = targetRef(t); return wrap(INSTALL.osv, prep, `osv-scanner --format json -r ${ref} > "$O" 2>/dev/null || osv-scanner scan --format json -r ${ref} > "$O" 2>/dev/null`); },
  },
  // 6. Infrastructure-as-Code — checkov (Terraform / CloudFormation / K8s / ARM / Helm).
  iac: {
    label: 'IaC scan', kind: 'scanner',
    build(t) { const { prep, ref } = targetRef(t); return wrap(INSTALL.checkov, prep, `checkov -d ${ref} -o json --compact --quiet > "$O" 2>/dev/null`); },
  },
  // 7. Container security — trivy image (OS + app vulns + secrets + misconfig).
  container: {
    label: 'Container scan', kind: 'scanner',
    build(img) { return wrap(INSTALL.trivy, '', `trivy image --format json --quiet --scanners vuln,secret,misconfig ${imageRef(img)} > "$O" 2>/dev/null`); },
  },
  // 8. Configuration security — trivy config (Dockerfile / compose / K8s / Terraform misconfig).
  config: {
    label: 'Config scan', kind: 'scanner',
    build(t) { const { prep, ref } = targetRef(t); return wrap(INSTALL.trivy, prep, `trivy config --format json --quiet ${ref} > "$O" 2>/dev/null`); },
  },
  // 9. License risk — trivy fs license scan; risky/unknown licenses surfaced.
  license: {
    label: 'License risk', kind: 'scanner',
    build(t) { const { prep, ref } = targetRef(t); return wrap(INSTALL.trivy, prep, `trivy fs --scanners license --license-full --format json --quiet ${ref} > "$O" 2>/dev/null`); },
  },
  // 10. Supply-chain — SBOM (syft) then OSV-scan the SBOM (transitive, ecosystem-wide advisories).
  supplychain: {
    label: 'Supply-chain scan', kind: 'scanner',
    build(t) {
      const { prep, ref } = targetRef(t);
      return wrap(INSTALL.syft + INSTALL.osv, prep,
        `S=$(mktemp); syft ${ref} -o cyclonedx-json 2>/dev/null > "$S"; osv-scanner --format json --sbom="$S" > "$O" 2>/dev/null || osv-scanner --format json -r ${ref} > "$O" 2>/dev/null; rm -f "$S"`);
    },
  },
};

export const SCANNER_AREAS = Object.keys(AREAS);
export const SPECIAL_AREAS = ['codereview', 'remediation', 'fixverify', 'cicd'];
export const ALL_AREAS = [...SCANNER_AREAS, ...SPECIAL_AREAS];

// Build a scanner command for one area. Passthrough: if the body already starts with a known
// scanner binary, run it verbatim (power users / the agent can hand-write flags).
export function buildAppsecCommand(area, body) {
  const raw = String(body || '').trim();
  if (SCANNER_BINS.test(raw.split(/\s+/)[0] || '')) return raw; // raw scanner command, run as-is
  const a = AREAS[area];
  if (!a) return null;
  const target = raw.split(/\s+/)[0] || (area === 'container' ? '' : '.');
  return a.build(target);
}

// ---- finding extraction (global; sniffs the tool from the command) --------------------------
// Added to the agent's finding-extraction pipeline, so ANY appsec scanner output (whether run via a
// dedicated ```<area> tag or a raw ```execute) is parsed into structured findings.
export function extractAppsecFindings(command, output) {
  const cmd = String(command || '');
  if (!SCANNER_BINS.test(cmd)) return [];
  const json = parseJsonLoose(output);
  if (!json) return [];
  let items = [];
  if (/\bsemgrep\b/.test(cmd)) items = parseSemgrep(json);
  else if (/\bbandit\b/.test(cmd)) items = parseBandit(json);
  else if (/\bgitleaks\b/.test(cmd)) items = parseGitleaks(json, { history: !/--no-git/.test(cmd) });
  else if (/\bcheckov\b/.test(cmd)) items = parseCheckov(json);
  else if (/\bosv-scanner\b/.test(cmd)) items = parseOsv(json, { finding_type: /--sbom|cyclonedx/.test(cmd) ? 'supplychain' : 'dependency' });
  else if (/\btrivy\b/.test(cmd)) items = parseTrivy(json);
  else if (/\bgrype\b/.test(cmd)) items = parseGrype(json);
  else if (/npm audit|yarn audit/.test(cmd)) items = parseNpmAudit(json);
  else if (/\bsyft\b/.test(cmd)) items = /license/.test(cmd) ? parseSyft(json, { mode: 'license' }) : []; // SBOM inventory summarised, not persisted as noise
  return dedupCap(items, 200);
}

// SBOM summary for the ```sca tag — an inventory readout (not 300 info-level findings).
export function summarizeSbom(output) {
  const json = parseJsonLoose(output);
  const arts = json?.artifacts;
  if (!Array.isArray(arts) || !arts.length) return { total: 0, text: 'No components detected (is this a source/dep directory?).' };
  const byType = {};
  const risky = [];
  for (const a of arts) {
    byType[a.type || 'other'] = (byType[a.type || 'other'] || 0) + 1;
    const lics = [].concat(a.licenses || []).map((l) => (typeof l === 'string' ? l : l?.value || l?.spdxExpression)).filter(Boolean);
    for (const lic of lics) { const r = classifyLicense(lic); if (['critical', 'high'].includes(r.severity)) risky.push(`${a.name}@${a.version}: ${lic}`); }
  }
  const top = arts.slice(0, 25).map((a) => `- ${a.name} ${a.version}${a.type ? ` (${a.type})` : ''}`).join('\n');
  const typeLine = Object.entries(byType).sort((x, y) => y[1] - x[1]).map(([k, v]) => `${k}:${v}`).join(', ');
  return {
    total: arts.length,
    text:
      `SBOM: **${arts.length} components** (${typeLine}).\n\n${top}${arts.length > 25 ? `\n…and ${arts.length - 25} more.` : ''}` +
      (risky.length ? `\n\n⚠️ Copyleft/restricted licenses:\n${risky.slice(0, 15).map((r) => '- ' + r).join('\n')}` : ''),
  };
}

// ---- remediation knowledge base ------------------------------------------------------------
// Concrete, framework-agnostic fix guidance keyed to common vuln classes (CWE / rule / keyword).
// The ```remediation tag matches a finding/description here and hands the agent a fix recipe to
// apply to the user's actual code.
const REMEDIATION_KB = [
  { re: /\b(sql\s?inj|sqli|cwe-?89)\b/i, title: 'SQL Injection (CWE-89)', fix: 'Use parameterised queries / prepared statements (never string-concatenate input into SQL). Use an ORM or a query builder with bound parameters. Apply least-privilege DB accounts. Validate/allow-list any dynamic identifiers (table/column names).' },
  { re: /\b(xss|cross[- ]site scripting|cwe-?79)\b/i, title: 'Cross-Site Scripting (CWE-79)', fix: 'Context-aware output encoding at every sink (HTML/attr/JS/URL). Prefer a framework that auto-escapes (React/Vue). Set a strict Content-Security-Policy. Sanitise HTML with a vetted library (DOMPurify). Never use innerHTML/dangerouslySetInnerHTML with untrusted data.' },
  { re: /\b(command\s?inj|os\s?command|rce|cwe-?78)\b/i, title: 'OS Command Injection (CWE-78)', fix: 'Avoid the shell: use exec APIs that take an argv array (execFile/spawn with args, not exec with a string). Never interpolate user input into a shell command. Allow-list commands/args; validate strictly.' },
  { re: /\b(path\s?travers|directory\s?travers|lfi|cwe-?22)\b/i, title: 'Path Traversal (CWE-22)', fix: 'Resolve the path and verify it stays within an allowed base dir (path.resolve + startsWith check). Reject "..", null bytes, and absolute paths. Map user input to an ID, not a raw filename.' },
  { re: /\b(ssrf|server[- ]side request|cwe-?918)\b/i, title: 'SSRF (CWE-918)', fix: 'Allow-list destination hosts/schemes; block private/link-local ranges (169.254.169.254, 10/8, 127/8, ::1). Resolve DNS and re-check the IP. Disable redirects to internal hosts. Use a dedicated egress proxy.' },
  { re: /\b(deserial|cwe-?502|ysoserial)\b/i, title: 'Insecure Deserialization (CWE-502)', fix: 'Do not deserialize untrusted data. Use data-only formats (JSON) with a schema; avoid native serializers (pickle/Java ObjectInputStream/PHP unserialize). If unavoidable, use allow-listed types + integrity checks (HMAC).' },
  { re: /\b(hard[- ]?cod|secret|api[_ ]?key|password|cwe-?798|token)\b/i, title: 'Hardcoded Secret (CWE-798)', fix: 'Remove the secret from source; rotate it immediately (assume it is compromised). Load from env/secret manager (Vault, AWS/GCP Secrets Manager). Add the path to .gitignore. Purge from git history (git filter-repo / BFG). Add a pre-commit secret scanner (gitleaks).' },
  { re: /\b(weak\s?crypto|md5|sha1|des\b|ecb|insecure random|cwe-?327|cwe-?328|cwe-?330)\b/i, title: 'Weak Cryptography (CWE-327/328/330)', fix: 'Use vetted algorithms: AES-256-GCM for symmetric, RSA-2048+/ECDSA for asymmetric, SHA-256+ for hashing, Argon2id/bcrypt/scrypt for passwords. Use a CSPRNG (crypto.randomBytes), never Math.random for security. Never roll your own crypto.' },
  { re: /\b(xxe|xml external|cwe-?611)\b/i, title: 'XXE (CWE-611)', fix: 'Disable external entity and DTD processing in the XML parser (FEATURE_SECURE_PROCESSING / disallow-doctype-decl). Prefer JSON. Use a hardened parser configuration.' },
  { re: /\b(open\s?redirect|cwe-?601)\b/i, title: 'Open Redirect (CWE-601)', fix: 'Never redirect to a raw user-supplied URL. Allow-list target paths, or map an ID to a known destination. If external redirects are needed, validate the host against an allow-list.' },
  { re: /\b(csrf|cwe-?352)\b/i, title: 'CSRF (CWE-352)', fix: 'Use anti-CSRF tokens (synchronizer or double-submit) on state-changing requests. Set cookies SameSite=Lax/Strict. Require re-auth for sensitive actions. Prefer non-cookie auth (Bearer) for APIs.' },
  { re: /\b(idor|broken\s?(access|object)|missing\s?authz|cwe-?639|cwe-?862|cwe-?285)\b/i, title: 'Broken Access Control / IDOR (CWE-639/862)', fix: 'Enforce authorization on the server for every object access (owner/tenant check), not just the UI. Use unguessable IDs is not enough — always verify the caller may access the specific resource. Centralise access checks.' },
  { re: /\b(jwt|alg.?none|cwe-?347)\b/i, title: 'JWT Verification Flaw (CWE-347)', fix: 'Pin the expected algorithm (reject alg=none and HS/RS confusion). Verify signature with the correct key, check exp/nbf/aud/iss. Use short-lived tokens + rotation. Store signing keys in a secret manager.' },
  { re: /\b(cors|cwe-?942)\b/i, title: 'Permissive CORS (CWE-942)', fix: 'Do not reflect arbitrary Origin or use "*" with credentials. Maintain an explicit allow-list of origins. Set Access-Control-Allow-Credentials only for trusted origins.' },
  { re: /\b(ssti|template\s?inj)\b/i, title: 'Server-Side Template Injection', fix: 'Never render user input as a template. Use logic-less templates or sandboxed engines. Pass user data as bound variables, not into the template source.' },
];
export function remediationFor(text) {
  const s = String(text || '');
  const hits = REMEDIATION_KB.filter((r) => r.re.test(s));
  if (hits.length) {
    return hits.slice(0, 3).map((h) => `### ${h.title}\n${h.fix}`).join('\n\n') +
      '\n\n**Now:** apply this to the user\'s actual code — read the vulnerable file, produce the exact patched code (a diff), then verify with the matching scanner (```fixverify).';
  }
  return 'No specific class matched. General remediation: identify the exact vulnerable line, apply input validation + output encoding + least privilege, add a regression test, then re-scan to verify. Read the flagged file and produce a concrete patch.';
}

// ---- CI/CD pipeline generator --------------------------------------------------------------
// Emits a ready-to-commit pipeline that runs this whole suite as a security gate.
export function generateCicdPipeline(platform = 'github') {
  const p = String(platform || 'github').toLowerCase();
  if (p.includes('gitlab')) {
    return {
      filename: '.gitlab-ci.yml',
      content: `# DevSecOps security gate — generated by CypherMind
stages: [security]

.security_defaults: &security_defaults
  stage: security
  allow_failure: false

secret_scan:
  <<: *security_defaults
  image: zricethezav/gitleaks:latest
  script: [ "gitleaks detect --source . --redact -v" ]

sast:
  <<: *security_defaults
  image: returntocorp/semgrep:latest
  script: [ "semgrep ci --config auto" ]

dependency_cve:
  <<: *security_defaults
  image: ghcr.io/google/osv-scanner:latest
  script: [ "osv-scanner -r ." ]

iac_scan:
  <<: *security_defaults
  image: bridgecrew/checkov:latest
  script: [ "checkov -d . --compact" ]

container_scan:
  <<: *security_defaults
  image: aquasec/trivy:latest
  script: [ "trivy fs --exit-code 1 --severity HIGH,CRITICAL ." ]
`,
    };
  }
  if (p.includes('jenkins')) {
    return {
      filename: 'Jenkinsfile.security',
      content: `// DevSecOps security gate — generated by CypherMind
pipeline {
  agent any
  stages {
    stage('Secret Scan')     { steps { sh 'gitleaks detect --source . --redact -v' } }
    stage('SAST')            { steps { sh 'semgrep ci --config auto' } }
    stage('Dependency CVEs') { steps { sh 'osv-scanner -r .' } }
    stage('IaC')             { steps { sh 'checkov -d . --compact' } }
    stage('Vuln/Container')  { steps { sh 'trivy fs --exit-code 1 --severity HIGH,CRITICAL .' } }
  }
  post { failure { echo 'Security gate failed — see logs.' } }
}
`,
    };
  }
  // default: GitHub Actions
  return {
    filename: '.github/workflows/security.yml',
    content: `# DevSecOps security gate — generated by CypherMind
name: Security
on:
  push: { branches: [main, master] }
  pull_request:
jobs:
  security:
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write }
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }   # full history for secret scanning
      - name: Secret scan (gitleaks)
        uses: gitleaks/gitleaks-action@v2
        env: { GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }} }
      - name: SAST (Semgrep)
        uses: returntocorp/semgrep-action@v1
        with: { config: auto }
      - name: Dependency CVEs (OSV-Scanner)
        uses: google/osv-scanner-action@v1
        with: { scan-args: "-r ." }
      - name: IaC scan (Checkov)
        uses: bridgecrewio/checkov-action@v12
        with: { directory: ., quiet: true }
      - name: Vulnerabilities (Trivy)
        uses: aquasecurity/trivy-action@master
        with: { scan-type: fs, severity: "HIGH,CRITICAL", exit-code: "1" }
`,
  };
}
