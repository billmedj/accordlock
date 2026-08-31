import { describe, expect, it } from 'vitest';

import { humanizeModelIdentifier } from './predefinedModelsUtils';

describe('humanizeModelIdentifier', () => {
  it.each([
    ['muse-spark-1.2-contributor-free', 'Muse Spark 1.2 Free'],
    ['openai/gpt-4o-mini', 'GPT 4o Mini'],
    ['gemini_3.7_flash', 'Gemini 3.7 Flash'],
    ['ox alpha', 'Ox Alpha'],
  ])('presents %s as readable product copy', (identifier, expected) => {
    expect(humanizeModelIdentifier(identifier)).toBe(expected);
  });

  it('keeps an empty identifier empty', () => {
    expect(humanizeModelIdentifier('')).toBe('');
  });
});
