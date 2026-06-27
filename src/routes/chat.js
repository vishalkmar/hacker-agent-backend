import { Router } from 'express';
import { env } from '../config/env.js';
import { getSession, renameSession, touchSession } from '../db/sessions.repo.js';
import { addMessage, historyForLlm } from '../db/messages.repo.js';
import { streamChat, activeModel } from '../services/llm/index.js';
import { runAgent } from '../services/llm/agent.js';
import { getFile } from '../db/files.repo.js';
import { renderFileContext } from '../services/files/analyze.js';
import { recallMemories, storeMemories } from '../db/memory.repo.js';
import { checkAndCountMessage } from '../services/auth/auth.js';

export const chatRouter = Router();

// Turn the first user message into a short session title.
function deriveTitle(text) {
  const clean = text.replace(/\s+/g, ' ').trim();
  if (!clean) return 'New chat';
  return clean.length > 48 ? clean.slice(0, 48) + '…' : clean;
}

// POST /api/chat/:sessionId
// Body: { content }
// Streams Server-Sent Events:
//   event: delta  data: {"text": "..."}      (repeated)
//   event: done   data: {"message": {...}}   (final assistant message persisted)
//   event: error  data: {"error": "..."}
chatRouter.post('/:sessionId', async (req, res) => {
  const session = await getSession(req.userId, req.params.sessionId);
  if (!session) return res.status(404).json({ error: 'Session not found' });

  const content = (req.body?.content || '').toString().trim();
  if (!content) return res.status(400).json({ error: 'content is required' });

  // Enforce per-plan daily message limit (resets daily).
  const quota = await checkAndCountMessage(req.userId);
  if (!quota.allowed) {
    return res.status(429).json({
      error: `Daily message limit reached (${quota.limit}/day). Upgrade your plan or try again tomorrow.`,
    });
  }

  // Pull in any attached files' extracted content so the AI can use them.
  let attachmentContext = '';
  const attachments = Array.isArray(req.body?.attachments) ? req.body.attachments : [];
  for (const fileId of attachments.slice(0, 5)) {
    const file = await getFile(req.userId, fileId);
    if (file) attachmentContext += '\n\n' + renderFileContext(file);
  }
  const fullContent = attachmentContext ? `${content}\n${attachmentContext}` : content;

  // Persist the user's message (with any attachment context folded in).
  await addMessage({ sessionId: session.id, userId: req.userId, role: 'user', content: fullContent });

  // Auto-title the session from its first user message.
  if (!session.title || session.title === 'New chat') {
    await renameSession(req.userId, session.id, deriveTitle(content));
  }

  // Set up SSE.
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders?.();

  const send = (event, data) => {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  // Abort the upstream LLM call only if the client disconnects *before* we finish.
  // NB: req's 'close' fires once the request body is read (not on disconnect), so we
  // listen on the response instead and guard against normal completion.
  const ac = new AbortController();
  res.on('close', () => {
    if (!res.writableEnded) ac.abort();
  });

  const history = await historyForLlm(session.id);

  // Recall relevant context from the user's PAST sessions (cross-session memory).
  let memoryContext = '';
  try {
    const recalled = await recallMemories(req.userId, content, {
      topK: env.embed.topK,
      excludeSessionId: session.id,
    });
    const useful = recalled.filter((r) => r.score >= 0.25);
    if (useful.length) {
      memoryContext = useful
        .map((r) => `- (${(r.score).toFixed(2)}) ${r.content.replace(/\s+/g, ' ').slice(0, 400)}`)
        .join('\n');
      send('memory', { count: useful.length });
    }
  } catch {
    /* memory is best-effort */
  }

  try {
    // With the execution engine on, run the agent loop (model can run real commands).
    // Otherwise fall back to a single streamed completion.
    const full = env.exec.enabled
      ? await runAgent({
          history,
          sessionId: session.id,
          userId: req.userId,
          signal: ac.signal,
          emit: send,
          memoryContext,
          autopilot: !!req.body?.autopilot,
        })
      : await streamChat({
          history,
          signal: ac.signal,
          onDelta: (text) => send('delta', { text }),
        });

    const saved = await addMessage({
      sessionId: session.id,
      userId: req.userId,
      role: 'assistant',
      content: full,
      model: activeModel(),
    });
    await touchSession(session.id);

    // Persist this turn into long-term memory (best-effort, non-blocking for the response).
    const memItems = [
      { source: 'message', role: 'user', content },
      { source: 'message', role: 'assistant', content: full.slice(0, 4000) },
    ];
    // Remember uploaded file content (image descriptions / PDF / doc text) across sessions.
    if (attachmentContext.trim()) {
      memItems.push({ source: 'file', role: 'user', content: attachmentContext.trim().slice(0, 4000) });
    }
    storeMemories(req.userId, session.id, memItems).catch(() => {});

    send('done', { message: saved });
    res.end();
  } catch (err) {
    if (ac.signal.aborted) {
      // Client went away — nothing to send.
      return res.end();
    }
    send('error', { error: err.message || 'LLM error' });
    res.end();
  }
});
