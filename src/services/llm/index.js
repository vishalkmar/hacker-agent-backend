import { env } from '../../config/env.js';
import { buildMessages } from './prompt.js';
import { streamOpenAICompatible } from './openaiCompatible.js';
import { streamAnthropic } from './anthropic.js';
import { streamMock } from './mock.js';

// Unified streaming entry point.
//   history: [{ role: 'user'|'assistant', content }]
//   onDelta: called with each streamed text chunk
// Returns: the full assistant reply text.
export async function streamChat({ history, onDelta, signal, system }) {
  const messages = buildMessages(history, system);
  const provider = env.llm.provider;

  switch (provider) {
    case 'openai':
    case 'nvidia':
      return streamOpenAICompatible({ messages, onDelta, signal });
    case 'anthropic':
      return streamAnthropic({ messages, onDelta, signal });
    case 'mock':
      return streamMock({ messages, onDelta, signal });
    default:
      throw new Error(`Unknown LLM_PROVIDER "${provider}" (use openai | nvidia | anthropic | mock)`);
  }
}

export const activeModel = () => (env.llm.provider === 'mock' ? 'mock' : env.llm.model);
