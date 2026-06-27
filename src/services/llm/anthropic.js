import { env } from '../../config/env.js';

// Streaming client for the Anthropic Messages API.
// Anthropic separates the system prompt from the messages array, so we split it out.
export async function streamAnthropic({ messages, onDelta, signal }) {
  const { baseUrl, apiKey, model, temperature, maxTokens } = env.llm;
  if (!apiKey) throw new Error('LLM_API_KEY is not set');

  const root = (baseUrl || 'https://api.anthropic.com/v1').replace(/\/$/, '');
  const url = `${root}/messages`;

  const systemMsg = messages.find((m) => m.role === 'system');
  const turns = messages
    .filter((m) => m.role === 'user' || m.role === 'assistant')
    .map((m) => ({ role: m.role, content: m.content }));

  const res = await fetch(url, {
    method: 'POST',
    signal,
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model,
      system: systemMsg?.content,
      messages: turns,
      temperature,
      max_tokens: maxTokens,
      stream: true,
    }),
  });

  if (!res.ok || !res.body) {
    const errText = await res.text().catch(() => '');
    throw new Error(`Anthropic request failed (${res.status}): ${errText.slice(0, 500)}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let full = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('data:')) continue;
      const data = trimmed.slice(5).trim();
      if (!data) continue;
      try {
        const json = JSON.parse(data);
        if (json.type === 'content_block_delta') {
          const delta = json.delta?.text || '';
          if (delta) {
            full += delta;
            onDelta?.(delta);
          }
        }
      } catch {
        // ignore non-JSON / event-name lines
      }
    }
  }

  return full;
}
