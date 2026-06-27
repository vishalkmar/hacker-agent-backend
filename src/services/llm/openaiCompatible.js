import { env } from '../../config/env.js';

// Streaming client for any OpenAI-compatible Chat Completions endpoint.
// Covers provider = "openai" and "nvidia" (NVIDIA NIM is OpenAI-compatible).
//
// onDelta(textChunk) is called for every streamed token chunk.
// Returns the full assistant text once the stream completes.
export async function streamOpenAICompatible({ messages, onDelta, signal }) {
  const { baseUrl, apiKey, model, temperature, maxTokens } = env.llm;
  if (!baseUrl) throw new Error('LLM_BASE_URL is not set');
  if (!apiKey) throw new Error('LLM_API_KEY is not set');

  const url = `${baseUrl.replace(/\/$/, '')}/chat/completions`;
  const res = await fetch(url, {
    method: 'POST',
    signal,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      messages,
      temperature,
      max_tokens: maxTokens,
      stream: true,
    }),
  });

  if (!res.ok || !res.body) {
    const errText = await res.text().catch(() => '');
    throw new Error(`LLM request failed (${res.status}): ${errText.slice(0, 500)}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let full = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    // SSE frames are separated by double newlines; lines start with "data: ".
    const lines = buffer.split('\n');
    buffer = lines.pop() ?? ''; // keep the last partial line in the buffer

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('data:')) continue;
      const data = trimmed.slice(5).trim();
      if (data === '[DONE]') continue;
      try {
        const json = JSON.parse(data);
        const delta = json.choices?.[0]?.delta?.content || '';
        if (delta) {
          full += delta;
          onDelta?.(delta);
        }
      } catch {
        // Ignore keep-alive / non-JSON lines.
      }
    }
  }

  return full;
}
