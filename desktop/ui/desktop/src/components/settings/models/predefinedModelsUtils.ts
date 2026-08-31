// Modified by AccordLock contributors; see UPSTREAM.md.
import Model from './modelInterface';

// Helper functions for predefined models - shared across components
export function getPredefinedModelsFromEnv(): Model[] {
  try {
    const envModels = window.appConfig.get('GOOSE_PREDEFINED_MODELS'); // process.env.GOOSE_PREDEFINED_MODELS
    if (envModels && typeof envModels === 'string') {
      return JSON.parse(envModels) as Model[];
    }
  } catch (error) {
    console.warn('Failed to parse GOOSE_PREDEFINED_MODELS environment variable:', error);
  }
  return [];
}

export function shouldShowPredefinedModels(): boolean {
  return getPredefinedModelsFromEnv().length > 0;
}

export function getModelDisplayName(modelName: string): string {
  const predefinedModels = getPredefinedModelsFromEnv();
  const matchingModel = predefinedModels.find((model) => model.name === modelName);
  return matchingModel?.alias || humanizeModelIdentifier(modelName);
}

const MODEL_TOKEN_LABELS: Readonly<Record<string, string>> = {
  ai: 'AI',
  api: 'API',
  gpt: 'GPT',
  llm: 'LLM',
};

/**
 * Turns provider identifiers into readable labels without dropping identity
 * or inventing a marketing name. Catalog aliases still take precedence.
 */
export function humanizeModelIdentifier(modelName: string): string {
  const leaf = modelName.trim().split('/').filter(Boolean).pop() ?? '';
  const label = leaf
    .replace(/[-_]+/gu, ' ')
    .replace(/\s+/gu, ' ')
    .trim()
    .split(' ')
    .map((token) => {
      const knownLabel = MODEL_TOKEN_LABELS[token.toLowerCase()];
      if (knownLabel) return knownLabel;
      if (!token || /^\d/u.test(token) || /[A-Z]/u.test(token)) return token;
      return `${token[0].toUpperCase()}${token.slice(1)}`;
    })
    .join(' ');

  return label.replace(/\bContributor Free\b/gu, 'Free');
}

export function getProviderDisplayName(modelName: string): string {
  const predefinedModels = getPredefinedModelsFromEnv();
  const matchingModel = predefinedModels.find((model) => model.name === modelName);
  return matchingModel?.subtext || '';
}
