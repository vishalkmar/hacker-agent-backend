// Live Hack Environment tests — the AI management brain (parse/system-prompt/verb routing) + job kind/meta
// plumbing. Deterministic: manageJob's LLM, jobs layer, and command runner are all injected fakes (no network,
// no processes, no DB). Run: node scripts/test-live-env.mjs
import { parseManageReply, buildManageSystem, manageJob } from '../src/services/exec/manage.js';
import { LIVE_KINDS, INTERACTIVE_KINDS } from '../src/services/exec/jobs.js';
import { detectLiveCommand } from '../src/services/exec/livetools.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };

console.log('\n[1] live-kind classification');
ok('hound/camphish/msf/set are live', ['hound', 'camphish', 'msf', 'set'].every((k) => LIVE_KINDS.has(k)));
ok('plain shell is NOT live', !LIVE_KINDS.has('shell') && !LIVE_KINDS.has('terminal'));
ok('msf/shell/terminal are interactive (raw stdin)', ['msf', 'shell', 'terminal'].every((k) => INTERACTIVE_KINDS.has(k)));
ok('hound/camphish/set are NOT interactive (capture servers)', !INTERACTIVE_KINDS.has('hound') && !INTERACTIVE_KINDS.has('camphish') && !INTERACTIVE_KINDS.has('set'));

console.log('\n[2] directive parsing');
ok('SAY: parsed', (() => { const r = parseManageReply('SAY: 3 captures so far'); return r.verb === 'SAY' && r.arg === '3 captures so far'; })());
ok('RUN: parsed', (() => { const r = parseManageReply('RUN: cat $HOME/hound/data.txt'); return r.verb === 'RUN' && r.arg === 'cat $HOME/hound/data.txt'; })());
ok('SEND: parsed', (() => { const r = parseManageReply('SEND: sessions -i 1'); return r.verb === 'SEND' && r.arg === 'sessions -i 1'; })());
ok('case-insensitive verb', parseManageReply('say: hi').verb === 'SAY');
ok('skips a stray leading line, finds the verb', parseManageReply('sure!\nRUN: ls').verb === 'RUN');
ok('unprefixed reply -> treated as SAY', (() => { const r = parseManageReply('The target is in Delhi.'); return r.verb === 'SAY' && /Delhi/.test(r.arg); })());

console.log('\n[3] scoped system prompt');
const houndJob = { id: 'ab12', kind: 'hound', meta: { link: 'https://x.trycloudflare.com' } };
const sysH = buildManageSystem(houndJob, 'Latitude: 28.6\nLongitude: 77.2');
ok('names the session id + kind', /ab12/.test(sysH) && /hound/.test(sysH));
ok('includes the public link', /x\.trycloudflare\.com/.test(sysH));
ok('embeds the recent terminal tail', /Latitude: 28\.6/.test(sysH));
ok('hound guidance mentions Google-Maps link', /google\.com\/maps/.test(sysH));
ok('non-interactive kind forbids SEND', /Do NOT use SEND/.test(sysH));
const msfSys = buildManageSystem({ id: 'z9', kind: 'msf', meta: {} }, '');
ok('interactive kind offers SEND', /SEND:/.test(msfSys) && !/Do NOT use SEND/.test(msfSys));

console.log('\n[4] manageJob verb routing (injected llm/jobs/runner)');
// fake jobs layer + runner recorders
function fakeJobs(job) {
  const calls = { write: [], append: [] };
  return {
    calls,
    getJob: () => job,
    readJob: () => ({ text: job._tail || '' }),
    writeJob: (id, input) => { calls.write.push(input); return { ok: true }; },
    appendToJob: (id, t) => { calls.append.push(t); return { ok: true }; },
  };
}

// SAY path (hound "show me the location")
{
  const j = fakeJobs({ id: 'h1', kind: 'hound', sessionId: 's', meta: {}, _tail: 'Latitude: 28.67\nLongitude: 77.27' });
  const r = await manageJob({ id: 'h1', prompt: 'where is the target?' },
    { jobs: j, llm: async () => 'SAY: Target at 28.67,77.27 (Delhi).', run: async () => ({ stdout: 'x' }) });
  ok('SAY -> reply is the answer, nothing run', r.verb === 'SAY' && r.ran === false && /Delhi/.test(r.reply) && j.calls.write.length === 0 && j.calls.append.length === 0);
}

// RUN path (capture server -> sibling command via runner, appended to terminal)
{
  const j = fakeJobs({ id: 'h2', kind: 'hound', sessionId: 's', meta: {} });
  let ranCmd = null;
  const r = await manageJob({ id: 'h2', prompt: 'list the capture files' },
    { jobs: j, llm: async () => 'RUN: ls $HOME/hound', run: async (cmd) => { ranCmd = cmd; return { stdout: 'data.txt\nip.txt', stderr: '' }; } });
  ok('RUN -> runner invoked with the command', ranCmd === 'ls $HOME/hound' && r.ran === true && r.verb === 'RUN');
  ok('RUN -> command + output appended to the terminal', j.calls.append.some((t) => /ls \$HOME\/hound/.test(t)) && j.calls.append.some((t) => /data\.txt/.test(t)));
  ok('RUN -> did NOT type into stdin (capture server)', j.calls.write.length === 0);
}

// SEND path (interactive msf -> writeJob stdin, not the runner)
{
  const j = fakeJobs({ id: 'm1', kind: 'msf', sessionId: 's', meta: {} });
  let ranCmd = null;
  const r = await manageJob({ id: 'm1', prompt: 'interact with session 1' },
    { jobs: j, llm: async () => 'SEND: sessions -i 1', run: async (cmd) => { ranCmd = cmd; return { stdout: '' }; } });
  ok('SEND -> typed into the session stdin', j.calls.write[0] === 'sessions -i 1' && r.ran === true && r.verb === 'SEND');
  ok('SEND -> runner NOT used', ranCmd === null);
}

console.log('\n[5] guards');
ok('missing prompt -> error', (await manageJob({ id: 'x', prompt: '  ' }, { jobs: fakeJobs({ id: 'x' }), llm: async () => 'SAY: hi' })).error === 'prompt is required');
ok('unknown job -> job not found', (await manageJob({ id: 'nope', prompt: 'hi' }, { jobs: { getJob: () => null }, llm: async () => 'SAY: hi' })).error === 'job not found');
ok('llm failure -> surfaced, no throw', /management LLM failed/.test((await manageJob({ id: 'h', prompt: 'hi' }, { jobs: fakeJobs({ id: 'h', kind: 'hound', meta: {} }), llm: async () => { throw new Error('boom'); } })).error || ''));

console.log('\n[6] STRONGLY-BOUND live-command detection (ANY Kali tool, not just the 4 tags)');
const isLive = (c) => detectLiveCommand(c);
// listeners / consoles -> live + interactive (you type in)
ok('nc listener -> live+interactive', (() => { const r = isLive('nc -lvnp 4444'); return r.live && r.kind === 'listener' && r.interactive; })());
ok('ncat listener -> live', isLive('ncat --ssl -lvnp 443').live);
ok('socat listener -> live', (() => { const r = isLive('socat TCP-LISTEN:9001,reuseaddr,fork -'); return r.live && r.interactive; })());
ok('msfconsole -> live msf', (() => { const r = isLive('msfconsole -q -x "use exploit/multi/handler"'); return r.live && r.kind === 'msf'; })());
ok('evil-winrm -> live+interactive console', (() => { const r = isLive('evil-winrm -i 10.0.0.5 -u admin -p pass'); return r.live && r.interactive && r.kind === 'console'; })());
// captures / servers / tunnels -> live but NOT interactive (inspect, not type)
ok('airodump-ng -> live wifi (not interactive)', (() => { const r = isLive('airodump-ng wlan0mon'); return r.live && r.kind === 'wifi' && !r.interactive; })());
ok('wifite -> live wifi', isLive('wifite --kill').live);
ok('bettercap -> live mitm', (() => { const r = isLive('bettercap -iface eth0'); return r.live && r.kind === 'mitm'; })());
ok('responder -> live relay/capture', isLive('responder -I eth0').live);
ok('tcpdump capture -> live', isLive('tcpdump -i eth0 -w cap.pcap').live);
ok('cloudflared tunnel -> live tunnel', (() => { const r = isLive('cloudflared tunnel --url http://localhost:8080'); return r.live && r.kind === 'tunnel'; })());
ok('python http.server -> live server', (() => { const r = isLive('python3 -m http.server 8000'); return r.live && r.kind === 'server' && !r.interactive; })());
ok('impacket-smbserver -> live relay', isLive('impacket-smbserver share ./ -smb2support').live);
ok('sqlmap --os-shell -> live console', (() => { const r = isLive('sqlmap -u http://x/?id=1 --os-shell'); return r.live && r.interactive; })());
// C2 frameworks (Phase C) — server/console + listeners stay alive
ok('sliver-server -> live c2 interactive', (() => { const r = isLive('sliver-server'); return r.live && r.kind === 'c2' && r.interactive; })());
ok('sliver console -> live c2', (() => { const r = isLive('sliver'); return r.live && r.kind === 'c2'; })());
ok('havoc server -> live c2', (() => { const r = isLive('havoc server --profile p.yaotl -v'); return r.live && r.kind === 'c2'; })());
ok('covenant -> live c2', (() => { const r = isLive('dotnet Covenant.dll'); return r.live && r.kind === 'c2'; })());
// NEGATIVES — ordinary scans/commands must NOT be flagged live
ok('word "sliver" in a path -> NOT live', !isLive('ls /opt/silversliver/notes.txt').live);
ok('plain nmap -> NOT live', !isLive('nmap -sV -Pn 10.0.0.1').live);
ok('plain sqlmap dump -> NOT live', !isLive('sqlmap -u http://x/?id=1 --dbs').live);
ok('tshark READING a file (-r) -> NOT live', !isLive('tshark -r cap.pcap -Y http').live);
ok('nikto scan -> NOT live', !isLive('nikto -h http://x').live);
ok('curl -> NOT live', !isLive('curl -s https://x').live);
ok('empty -> NOT live', !isLive('').live);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
