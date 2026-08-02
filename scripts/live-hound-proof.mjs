// LIVE end-to-end proof of the Live Hack Environment on Hound.
// Runs in ONE long-lived process (so the job + its cloudflared tunnel stay alive):
//   1. start a real Hound job (kind=hound) in the Docker sandbox
//   2. write the public trycloudflare link to a JSON file the moment it's ready (so the operator can open it)
//   3. wait for a real GPS capture (operator opens the link on their phone + allows location)
//   4. run the REAL AI management box against the live job: SAY ("show me the location") + RUN ("list captures")
//   5. write the proof results to the same JSON file, stop the job, exit
// Cross-process handoff is via the scratchpad JSON file (Git-Bash + Node agree on a C:/... absolute path).
import fs from 'node:fs';
import { startJob, readJob, updateJobMeta, stopJob } from '../src/services/exec/jobs.js';
import { buildHoundCommand, extractHoundLink } from '../src/services/hound/index.js';
import { manageJob } from '../src/services/exec/manage.js';

const OUT = process.env.PROOF_OUT || 'C:/Users/DELL/AppData/Local/Temp/claude/e--my-projects-hacker-ai/fac10edc-6107-4c5d-95f9-7d9b4d82ec6e/scratchpad/hound-proof.json';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const write = (o) => { try { fs.writeFileSync(OUT, JSON.stringify({ t: new Date().toISOString(), ...o }, null, 2)); } catch (e) { console.error('write fail', e.message); } };
const log = (...a) => console.log('[proof]', ...a);

const sessionId = 'liveproof-hound';
write({ status: 'starting' });
log('starting Hound as a live job (kind=hound) in the sandbox…');
const job = await startJob({ command: buildHoundCommand(), sessionId, userId: 'proof', label: 'hound GPS tracker', kind: 'hound' });
log('job', job.id, '·', job.backend, '·', job.status);
write({ status: 'launching', jobId: job.id, backend: job.backend, jobStatus: job.status });

// 1) wait for the cloudflared link (~15-60s)
let link = null;
for (let i = 0; i < 60 && !link; i++) {
  await sleep(2000);
  link = extractHoundLink(readJob(job.id, 0).text);
  if (job && readJob(job.id, 0).status !== 'running') break;
}
if (!link) {
  const tail = readJob(job.id, 0).text.slice(-1800);
  log('NO LINK — recent output:\n', tail);
  write({ status: 'no-link', jobId: job.id, tail });
  stopJob(job.id);
  process.exit(1);
}
updateJobMeta(job.id, { link });
log('LINK READY:', link);
write({ status: 'link-ready', jobId: job.id, link, instruction: 'Open this link on a phone and ALLOW location.' });

// 2) wait for a real GPS capture (up to ~8 min)
log('waiting for a target to open the link + allow location…');
let captured = false, tail = '';
for (let i = 0; i < 240 && !captured; i++) {
  await sleep(2000);
  tail = readJob(job.id, 0).text;
  if (/Latitude/i.test(tail) && /Longitude/i.test(tail)) captured = true;
}
if (!captured) {
  log('TIMEOUT — no capture within the window.');
  write({ status: 'timeout', jobId: job.id, link, tail: tail.slice(-1500) });
  stopJob(job.id);
  process.exit(2);
}
log('CAPTURE detected! Running the AI management box against the live session…');
write({ status: 'captured', jobId: job.id, link });

// 3) THE PROOF: drive the live session with natural language (real NVIDIA LLM, real job).
const say = await manageJob({ id: job.id, prompt: 'show me the target location' });
log('SAY  ->', JSON.stringify(say));
const run = await manageJob({ id: job.id, prompt: 'list the raw capture files hound saved' });
log('RUN  ->', JSON.stringify(run));

write({
  status: 'proven', jobId: job.id, link,
  manage_say: say, manage_run: run,
  terminal_tail: readJob(job.id, 0).text.slice(-2000),
});
log('DONE — proof written to', OUT);
stopJob(job.id);
process.exit(0);
