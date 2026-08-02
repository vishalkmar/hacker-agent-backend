// Live Hack Environment — the AI-driven MANAGEMENT brain for a single live job.
//
// The Sessions panel shows a live shell (Metasploit handler, Hound/CamPhish capture server, …). Beside it
// sits a natural-language prompt box: the user types "show me the received images", "any new GPS hits?",
// "interact with session 1" and the AI operates THAT live session for them — no need to know the raw syntax.
//
// One LLM call, scoped to the job (its kind, link, and recent terminal tail). The model replies with a
// single directive verb:
//   SEND: <input>     -> type a line into the live interactive console's stdin  (msf, shells)
//   RUN:  <command>   -> run a sibling command in the SAME environment/container and stream it into the
//                        terminal                                                (inspect Hound/CamPhish captures)
//   SAY:  <answer>    -> just answer from what's already on screen               (summarise GPS/device/images)
// Anything unprefixed is treated as SAY. The result streams back to the box; the terminal updates via polling.

import { getJob, readJob, writeJob, appendToJob, INTERACTIVE_KINDS } from './jobs.js';
import { runCommand } from './runner.js';
import { streamChat } from '../llm/index.js';

const TAIL = 4000; // how much recent terminal output the model gets as context

// Per-kind hint so the model knows what it can do in this environment.
function kindGuidance(kind) {
  switch (kind) {
    case 'hound':
      return "This is a Hound geolocation tracker (a PHP page behind a cloudflared tunnel). When a target opens the link and allows location, their EXACT GPS + device intel (OS, model, public IP, ISP, browser) appear in the terminal above. Prefer SAY to summarise captures already on screen (give the Google-Maps link https://www.google.com/maps?q=<lat>,<lon>). Use RUN only to inspect files, e.g. `cat $HOME/hound/data.txt` or `cat $HOME/hound/ip.txt`.";
    case 'camphish':
      return "This is a CamPhish webcam-grab + geolocation lure. When a target opens the link and allows CAMERA, front-camera snapshots (cam*.png) plus GPS/IP land in the capture folder. Prefer SAY to summarise. Use RUN to list/inspect captures, e.g. `ls -t $HOME/CamPhish/*.png 2>/dev/null | head` or `cat $HOME/CamPhish/*.txt`.";
    case 'msf':
      return "This is a live Metasploit console/handler. Use SEND to drive it: `sessions -l` to list sessions, `sessions -i 1` to interact, then shell commands (`getuid`, `sysinfo`, `ps`). Use SAY to explain what's on screen.";
    case 'set':
      return "This is a live Social-Engineer Toolkit server (credential harvester / clone). Captured credentials appear in the terminal. Prefer SAY to summarise them; use RUN to inspect report files under `$HOME/.set/reports`.";
    default:
      return "This is a live shell. Use SEND to type a command into it, or SAY to explain the output above.";
  }
}

// Build the scoped system prompt for a job.
export function buildManageSystem(job, tail) {
  const link = job?.meta?.link ? `\nPublic link: ${job.meta.link}` : '';
  const interactive = job?.interactive ?? INTERACTIVE_KINDS.has(job?.kind);
  const verbs = interactive
    ? "Reply with ONE of: `SEND: <input>` (type into the console), `RUN: <command>` (sibling command in the same box), or `SAY: <answer>`."
    : "Reply with ONE of: `RUN: <command>` (run a command in the same environment), or `SAY: <answer>`. Do NOT use SEND (this session has no interactive prompt).";
  return [
    `You are operating a LIVE hacking session for an authorized operator. Session id: ${job?.id}. Kind: ${job?.kind}.${link}`,
    kindGuidance(job?.kind),
    '',
    'Recent terminal output (most recent last):',
    '"""',
    tail || '(no output yet)',
    '"""',
    '',
    verbs,
    'Output EXACTLY one line starting with SEND:, RUN:, or SAY: — no code fences, no preamble, no extra lines.',
    'Keep commands non-destructive and scoped to this engagement. Prefer SAY when the answer is already on screen.',
  ].join('\n');
}

// Parse the model's directive line into { verb, arg }.
export function parseManageReply(text) {
  const raw = String(text || '').trim();
  // find the first line that carries a verb (models sometimes add a stray blank/echo line)
  for (const line of raw.split('\n')) {
    const m = /^\s*(SEND|RUN|SAY)\s*:\s*([\s\S]+?)\s*$/i.exec(line);
    if (m) return { verb: m[1].toUpperCase(), arg: m[2].trim() };
  }
  // no verb -> treat the whole reply as a spoken answer
  return { verb: 'SAY', arg: raw };
}

// Manage a live job from a natural-language prompt. Dependencies are injectable for offline unit tests.
export async function manageJob(
  { id, prompt, userId = null } = {},
  { llm, jobs, run } = {}
) {
  const j = jobs || { getJob, readJob, writeJob, appendToJob };
  const runner = run || runCommand;
  const ask = llm || (async ({ system, user }) => streamChat({ history: [{ role: 'user', content: user }], system }));

  const question = String(prompt || '').trim();
  if (!question) return { error: 'prompt is required' };
  const job = j.getJob(id);
  if (!job) return { error: 'job not found' };

  const tail = j.readJob(id, 0).text?.slice(-TAIL) || '';
  const system = buildManageSystem(job, tail);
  let replyText = '';
  try {
    replyText = await ask({ system, user: question });
  } catch (e) {
    return { error: `management LLM failed: ${e.message}` };
  }
  const { verb, arg } = parseManageReply(replyText);

  if (verb === 'SEND') {
    const r = j.writeJob(id, arg);
    if (r.error) return { reply: `Couldn't type into the session: ${r.error}`, verb, command: arg, ran: false };
    return { reply: `⌨️ Sent to the session: \`${arg}\` — watch the terminal for the response.`, verb, command: arg, ran: true };
  }

  if (verb === 'RUN') {
    j.appendToJob(id, `\n\x1b[36m$ ${arg}\x1b[0m\n`); // show the command in the terminal (cyan)
    let out;
    try {
      const res = await runner(arg, { sessionId: job.sessionId, userId });
      out = (res.stdout || '') + (res.stderr ? `\n${res.stderr}` : '');
    } catch (e) {
      out = `[error] ${e.message}`;
    }
    j.appendToJob(id, (out || '(no output)') + '\n');
    return { reply: `▶️ Ran \`${arg}\` in the session. Output is in the terminal above.`, verb, command: arg, ran: true, output: out };
  }

  // SAY
  return { reply: arg, verb, ran: false };
}
