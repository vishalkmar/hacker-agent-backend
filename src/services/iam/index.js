// PHASE 4 — Over-permissive IAM roles / policies.
//
// Powers the ```iam agent tag. Two ways in:
//   • ```iam <path-to-policy.json>``` — analyze an IAM policy document, a trust policy, OR a full
//     `aws iam get-account-authorization-details` dump with a built-in risk engine (works offline —
//     no cloud creds — so it's fully testable). Flags admin-equivalent grants, service wildcards,
//     privilege-escalation action sets, Allow+NotAction, public principals, PassRole-on-* etc.
//   • ```iam aws|azure|gcp``` — credentialed CSPM: Prowler's IAM-category checks on the live account.
//
// The analyzer is a small Python program (base64-embedded to dodge all shell/JS escaping) that emits
// `IAMFIND<TAB><sev><TAB><type><TAB><title><TAB><evidence>` lines → parseIamReport(). Python is in
// the Kali image. Every generated command passes `bash -n`.

import { normSev, dedupCap } from '../appsec/engine.js';

// ---- the analyzer (no backslash escapes; uses chr() so it survives JS template + base64) --------
const ANALYZER_PY = [
  'import sys, json',
  'TAB = chr(9)',
  'def norm(x):',
  '    return [] if x is None else (x if isinstance(x, list) else [x])',
  'ESC = set(["iam:createpolicyversion","iam:setdefaultpolicyversion","iam:passrole","iam:createaccesskey","iam:createloginprofile","iam:updateloginprofile","iam:attachuserpolicy","iam:attachgrouppolicy","iam:attachrolepolicy","iam:putuserpolicy","iam:putgrouppolicy","iam:putrolepolicy","iam:addusertogroup","iam:updateassumerolepolicy","sts:assumerole","lambda:createfunction","glue:createdevendpoint","cloudformation:createstack","ec2:runinstances","datapipeline:createpipeline"])',
  'SENS = set(["iam","sts","kms","s3","secretsmanager","ec2","lambda","dynamodb","rds","organizations"])',
  'def emit(sev, typ, title, ev):',
  '    ev = str(ev).replace(chr(9), " ").replace(chr(10), " ")[:200]',
  '    print(TAB.join(["IAMFIND", sev, typ, title, ev]))',
  'def analyze(pol, ctx=""):',
  '    for st in norm(pol.get("Statement")):',
  '        if not isinstance(st, dict): continue',
  '        eff = st.get("Effect", "")',
  '        actions = [str(a).lower() for a in norm(st.get("Action"))]',
  '        nots = norm(st.get("NotAction"))',
  '        res = [str(r) for r in norm(st.get("Resource"))]',
  '        principal = st.get("Principal")',
  '        cond = st.get("Condition")',
  '        star_res = any(r == "*" for r in res)',
  '        if eff == "Allow" and principal is not None:',
  '            pv = principal if not isinstance(principal, dict) else " ".join([str(v) for v in principal.values()])',
  '            if "*" in str(pv):',
  '                emit("critical", "public-principal", "Grants access to ANY principal (Principal:*)", ctx + str(principal)[:80])',
  '        if eff != "Allow":',
  '            continue',
  '        if "*" in actions and star_res:',
  '            emit("critical", "admin", "Full administrative access (Action:* on Resource:*)", ctx + "Action:* Resource:*"); continue',
  '        if "*" in actions:',
  '            emit("high", "wildcard-action", "All actions allowed (Action:*)", ctx + "Resource: " + ",".join(res)[:80])',
  '        if nots:',
  '            emit("high", "notaction", "Allow with NotAction (broad implicit grant)", ctx + "NotAction: " + ",".join([str(x) for x in nots])[:80])',
  '        svcw = sorted(set([a.split(":")[0] for a in actions if a.endswith(":*")]))',
  '        for s in svcw:',
  '            sev = "critical" if s in ("iam", "sts", "kms", "organizations") else "high"',
  '            emit(sev, "service-wildcard", "All " + s + " actions allowed (" + s + ":*)", ctx + s + ":* on " + ",".join(res)[:60])',
  '        esc = sorted(set([a for a in actions if a in ESC]))',
  '        if esc:',
  '            emit("critical", "priv-esc", "Privilege-escalation actions permitted", ctx + ", ".join(esc)[:120])',
  '        if star_res and actions and "*" not in actions:',
  '            svcs = set([a.split(":")[0] for a in actions if ":" in a])',
  '            hit = sorted(svcs & SENS)',
  '            if hit:',
  '                emit("medium", "wildcard-resource", "Sensitive actions on all resources (Resource:*)", ctx + ",".join(hit))',
  '        if "iam:passrole" in actions and not cond and star_res:',
  '            emit("high", "passrole", "iam:PassRole on * without a condition", ctx + "iam:PassRole Resource:*")',
  'try:',
  '    doc = json.loads(open(sys.argv[1]).read())',
  'except Exception as e:',
  '    print(TAB.join(["IAMFIND", "info", "parse-error", "Could not parse IAM policy JSON", str(e)[:120]])); sys.exit(0)',
  'if isinstance(doc, dict) and any(k in doc for k in ("UserDetailList", "RoleDetailList", "GroupDetailList", "Policies")):',
  '    for pol in doc.get("Policies", []):',
  '        for ver in pol.get("PolicyVersionList", []):',
  '            d = ver.get("Document")',
  '            if isinstance(d, dict) and ver.get("IsDefaultVersion", True): analyze(d, "[" + pol.get("PolicyName", "policy") + "] ")',
  '    for r in doc.get("RoleDetailList", []):',
  '        arp = r.get("AssumeRolePolicyDocument")',
  '        if isinstance(arp, dict): analyze(arp, "[role " + r.get("RoleName", "?") + " trust] ")',
  '        for pp in r.get("RolePolicyList", []):',
  '            d = pp.get("PolicyDocument")',
  '            if isinstance(d, dict): analyze(d, "[role " + r.get("RoleName", "?") + "] ")',
  '    for u in doc.get("UserDetailList", []):',
  '        for pp in u.get("UserPolicyList", []):',
  '            d = pp.get("PolicyDocument")',
  '            if isinstance(d, dict): analyze(d, "[user " + u.get("UserName", "?") + "] ")',
  'else:',
  '    analyze(doc)',
].join('\n');

const ANALYZER_B64 = Buffer.from(ANALYZER_PY, 'utf8').toString('base64');

// Analyze a local IAM policy JSON file (path is in the exec backend / sandbox).
export function buildIamAnalyze(path) {
  const p = String(path || '').replace(/["'`$;|&<>(){}]/g, '');
  return `command -v python3 >/dev/null 2>&1 || apt-get install -y python3 >/dev/null 2>&1; echo ${ANALYZER_B64} | base64 -d > /tmp/iam_an.py 2>/dev/null; python3 /tmp/iam_an.py "${p}" 2>/dev/null; rm -f /tmp/iam_an.py`;
}

// Credentialed CSPM: Prowler IAM-category checks against the live account.
export function buildIamCspm(provider = 'aws') {
  const p = ['aws', 'azure', 'gcp'].includes(String(provider).toLowerCase()) ? String(provider).toLowerCase() : 'aws';
  const guard = `command -v prowler >/dev/null 2>&1 || pip install prowler --break-system-packages >/dev/null 2>&1;`;
  return `${guard} O=$(mktemp -d); prowler ${p} --category iam -M json-ocsf --output-directory "$O" >/dev/null 2>&1; cat "$O"/*.json 2>/dev/null | head -c 4000000; rm -rf "$O"`;
}

const CSPM_RE = /^(aws|azure|gcp)\b/i;
const RAW_RE = /^(prowler|cloudsplaining|pmapper|parliament|iamlive)\b/i;
export function buildIamCommand(body) {
  const raw = String(body || '').trim();
  if (!raw) return null;
  if (RAW_RE.test(raw)) return raw;
  const tokens = raw.split(/\s+/);
  if (CSPM_RE.test(tokens[0])) return buildIamCspm(tokens[0]);
  // treat as a policy file path (strip a leading "analyze" verb if present)
  const path = /^analyze$/i.test(tokens[0]) ? tokens[1] : tokens[0];
  return buildIamAnalyze(path);
}

// ---- parsing / rendering -------------------------------------------------------------------
const IAM_REMEDIATION = {
  admin: 'Remove Action:* / Resource:* — grant only the specific API actions and resource ARNs required (least privilege).',
  'wildcard-action': 'Replace Action:* with the explicit list of actions the workload actually calls.',
  'service-wildcard': 'Replace <service>:* with the specific API actions used, and scope Resource to exact ARNs.',
  'priv-esc': 'These actions allow escalating to higher privilege — remove them, or tightly scope the Resource and add Conditions; separate duties across roles.',
  notaction: 'Avoid Allow + NotAction (it grants everything except the listed actions). Use an explicit Action allow-list.',
  'public-principal': 'Never use Principal:"*" on an Allow — restrict to specific account IDs / role ARNs, and add Conditions (aws:SourceAccount/aws:PrincipalOrgID).',
  'wildcard-resource': 'Scope Resource to exact ARNs instead of "*".',
  passrole: 'Constrain iam:PassRole to specific role ARNs and add an iam:PassedToService condition.',
  'parse-error': 'Provide a valid IAM policy JSON (a policy document or an aws iam get-account-authorization-details dump).',
};

export function parseIamReport(output) {
  const out = [];
  for (const line of String(output || '').split('\n')) {
    if (!line.startsWith('IAMFIND\t')) continue;
    const [, sev, type, title, evidence] = line.split('\t');
    if (!title) continue;
    out.push({
      finding_type: 'iam',
      severity: normSev(sev),
      title: title.slice(0, 200),
      evidence: (evidence || '').slice(0, 240),
      remediation: IAM_REMEDIATION[type] || 'Apply least-privilege: scope actions, resources, and add conditions.',
      source: `iam-${type || 'policy'}`,
    });
  }
  return out;
}

export function extractIamFindings(command, output) {
  // Only the IAM policy-analyzer output. Prowler JSON (credentialed CSPM mode) is already parsed by
  // the cloud extractor (extractCloudFindings), so we don't double-parse it here.
  if (!/IAMFIND\t/.test(String(output || ''))) return [];
  return dedupCap(parseIamReport(output), 150);
}

export function renderIam(output) {
  const finds = parseIamReport(output);
  if (!finds.length) return '_No over-permissive statements found in the IAM policy (or the file was empty/unreadable)._';
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  finds.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  return `**IAM policy risks (${finds.length}):**\n` +
    finds.map((f) => `- **${f.severity.toUpperCase()}** ${f.title}\n  ↳ ${f.evidence}\n  ↳ fix: ${f.remediation}`).join('\n');
}
