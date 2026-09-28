import { env } from '../../config/env.js';

// Reasoning-model "answer directly, don't stream a separate thinking channel" flag. The kwarg
// name differs per family: nemotron uses `enable_thinking`, deepseek uses `thinking`. Mistral /
// others need nothing (they already stream `content` directly), so return {} for them.
function thinkingKwargs(model) {
  if (!env.llm.disableThinking) return {};
  if (/nemotron/i.test(model)) return { chat_template_kwargs: { enable_thinking: false } };
  if (/deepseek/i.test(model)) return { chat_template_kwargs: { thinking: false } };
  return {};
}

// Streaming client for any OpenAI-compatible Chat Completions endpoint (NVIDIA NIM, OpenRouter,
// OpenAI, DeepSeek, Mistral, … — all speak the same protocol).
//
// Auto-failover across a multi-provider CHAIN (env.llm.chain), highest priority first. Each entry
// has its own { model, baseUrl, apiKey }, so different links can hit different companies. If a
// model produces no first token within firstTokenTimeoutMs, or returns an HTTP/stream/empty error,
// the next link is tried. A USER cancel (outer signal) never triggers failover — it aborts.
//
// onDelta(textChunk) is called for every streamed token chunk.
// Returns the full assistant text once a model completes.
// The model that served the most recent completed request (for logging / UI "answered by" badges).
export let lastServedModel = null;

export async function streamOpenAICompatible({ messages, onDelta, signal }) {
  const { chain, temperature, maxTokens, firstTokenTimeoutMs } = env.llm;
  if (!chain.length) throw new Error('No LLM model configured (set LLM_MODELS or LLM_1_MODEL)');

  let lastErr;
  for (let i = 0; i < chain.length; i++) {
    const { model, baseUrl, apiKey } = chain[i];
    const isLast = i === chain.length - 1;

    if (!baseUrl || !apiKey) {
      lastErr = new Error(`endpoint for "${model}" is missing baseUrl/apiKey`);
      if (isLast) throw lastErr;
      console.warn(`[llm] ${lastErr.message} — skipping to "${chain[i + 1].model}"`);
      continue;
    }

    const url = `${baseUrl.replace(/\/$/, '')}/chat/completions`;
    try {
      const text = await streamOne({
        url, apiKey, model, messages, temperature, maxTokens,
        onDelta, outerSignal: signal, firstTokenTimeoutMs,
        // Only the non-last models get a first-token timeout; the last one is allowed
        // to take as long as it needs (there's no further fallback).
        allowFailover: !isLast,
      });
      // Always announce which model actually served this request, and at what priority — so it's
      // never a mystery which brain answered (esp. after a silent failover from a slow #1).
      console.log(`[llm] ✔ served by "${model}" (priority #${i + 1} of ${chain.length})${i > 0 ? ' — after failover' : ''}`);
      lastServedModel = { model, priority: i + 1, baseUrl };
      return text;
    } catch (e) {
      // User cancelled — do NOT fail over, just stop.
      if (signal?.aborted) throw e;
      lastErr = e;
      if (isLast) throw e;
      console.warn(`[llm] model "${model}" failed (${e.message}) — failing over to "${chain[i + 1].model}"`);
    }
  }
  throw lastErr || new Error('All LLM models failed');
}

// Stream a single model. Throws on HTTP error, empty response, or first-token timeout.
async function streamOne({ url, apiKey, model, messages, temperature, maxTokens, onDelta, outerSignal, firstTokenTimeoutMs, allowFailover }) {
  const ac = new AbortController();
  const relay = () => ac.abort();
  if (outerSignal) {
    if (outerSignal.aborted) ac.abort();
    else outerSignal.addEventListener('abort', relay, { once: true });
  }

  let firstTokenSeen = false;
  let timedOut = false;
  let timer = null;
  let lastActivity = Date.now();
  let full = ''; // declared here so the catch block can return partial output on user-abort
  // Idle-stall guard: fires if NO token arrives for firstTokenTimeoutMs — this covers BOTH the
  // first-token hang AND a mid-stream freeze (e.g. a free/rate-limited endpoint that emits a couple
  // tokens then stalls forever). Each token resets the clock. The last model gets no guard (there's
  // nothing left to fail over to, so let it take as long as it needs).
  if (allowFailover) {
    timer = setInterval(() => {
      if (Date.now() - lastActivity >= firstTokenTimeoutMs) {
        timedOut = true;
        ac.abort();
      }
    }, 1000);
  }

  try {
    const res = await fetch(url, {
      method: 'POST',
      signal: ac.signal,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model, messages, stream: true,
        // GPT-6 uses completion-token limits; direct answers avoid spending the
        // first-token timeout on hidden reasoning in this streaming agent loop.
        ...(/^gpt-6(?:-|$)/i.test(model)
          ? { max_completion_tokens: maxTokens, reasoning_effort: 'none' }
          : { temperature, max_tokens: maxTokens }),
        // Reasoning models stream their thinking into `reasoning_content` and sometimes leave
        // `content` empty → false "empty response" failovers. Ask them to answer directly. The
        // param differs per family, so it's model-aware (others are left untouched). Our own
        // agent loop supplies the step-by-step reasoning.
        ...thinkingKwargs(model),
      }),
    });

    if (!res.ok || !res.body) {
      const errText = await res.text().catch(() => '');
      throw new Error(`request failed (${res.status}): ${errText.slice(0, 300)}`);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      // SSE frames are separated by newlines; lines start with "data: ".
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? ''; // keep the last partial line in the buffer

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('data:')) continue;
        const data = trimmed.slice(5).trim();
        if (data === '[DONE]') continue;
        try {
          const json = JSON.parse(data);
          const delta = json.choices?.[0]?.delta || {};
          const piece = delta.content || '';
          // Reasoning models may stream thinking here first — count it as "alive" so the
          // hang timer doesn't fire, but only the real `content` becomes the answer.
          const thinking = delta.reasoning_content || '';
          // Any token (real content OR streamed thinking) counts as "alive" and resets the idle
          // clock, so the stall guard only fires on a genuine freeze — not on a slow-but-working model.
          if (piece || thinking) {
            firstTokenSeen = true;
            lastActivity = Date.now();
          }
          if (piece) {
            full += piece;
            onDelta?.(piece);
          }
        } catch {
          // Ignore keep-alive / non-JSON lines.
        }
      }
    }

    // A model that streamed nothing is treated as a failure so failover can try the next.
    if (!full && allowFailover) throw new Error('empty response');
    return full;
  } catch (e) {
    if (timedOut) throw new Error(firstTokenSeen
      ? `stalled mid-stream (no token for ${firstTokenTimeoutMs}ms)`
      : `no first token in ${firstTokenTimeoutMs}ms (hang)`);
    // User pressed Stop / disconnected mid-stream — keep what we already generated so the
    // caller can persist it (otherwise a stopped answer vanishes on refresh). Don't fail over.
    if (outerSignal?.aborted) return full;
    throw e;
  } finally {
    if (timer) clearInterval(timer);
    if (outerSignal) outerSignal.removeEventListener('abort', relay);
  }
}
