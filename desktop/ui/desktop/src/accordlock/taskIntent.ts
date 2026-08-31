import type { AccordLockTaskAuthorization, AccordLockTaskCapability } from './taskIpc';

export interface TaskIntentBrief {
  /** The exact user text already bound by task_objective_hash. */
  outcome: string;
  /** The trusted workspace selected by Electron main. */
  workspace: string;
  automatic: string[];
  requiresApproval: string[];
  unavailable: string[];
  /** Exact excerpts from the user request. Never model-generated paraphrases. */
  userLimits: string[];
}

export type IntentActionKind = 'write' | 'edit' | 'delete_file' | 'shell' | 'https_request';

const LIMIT_MARKER =
  /\b(?:do not|don't|never|must not|without|only|except|avoid|read[- ]only|offline|no\s+(?:file\s+changes?|commands?|terminal|shell|network|internet)|leave\s+.+?\s+unchanged|keep\s+.+?\s+unchanged)\b/iu;

const normalizeForDisplay = (value: string): string => value.replace(/\s+/gu, ' ').trim();

/**
 * Extract only literal user-written constraints. This is intentionally narrow:
 * missing a constraint here merely leaves it in the exact outcome text, while
 * inventing one would make the review misleading.
 */
export function extractUserLimits(objective: string, maximum = 3): string[] {
  if (maximum <= 0) return [];

  const candidates = objective
    .split(/(?:[\r\n]+|(?<=[.!?;])\s+)/u)
    .map(normalizeForDisplay)
    .filter(Boolean);

  const limits: string[] = [];
  for (const candidate of candidates) {
    if (!LIMIT_MARKER.test(candidate)) continue;
    limits.push(candidate);
    if (limits.length === maximum) break;
  }
  return limits;
}

const FILE_CHANGE_LIMIT =
  /\b(?:change|edit|modify|write|overwrite|delete|remove|rename|move|touch|only\s+(?:inspect|read|review|analyse|analyze|audit))\b/iu;
const COMMAND_LIMIT =
  /\b(?:run|execute|command|terminal|shell|script|install|build|test|only\s+(?:inspect|read|review|analyse|analyze|audit))\b/iu;

const DIRECTIVE_PREFIX = String.raw`(?:^|[,;:]\s*|\b(?:and|but|then)\s+)(?:please\s+)?(?:you\s+)?`;
const SCOPED_LIMIT_SUFFIX = String.raw`(?:to|in|inside|under|within|outside|from|for|on|matching|named|called|except|excluding|other\s+than|unless|that|which|whose|with)\b`;
const GENERIC_FILES = String.raw`(?:(?:any|all|the|these|those|my|our)\s+)?files?`;

const BROAD_FILE_CHANGE_BANS = [
  new RegExp(
    String.raw`${DIRECTIVE_PREFIX}(?:do\s+not|don't|never|must\s+not)\s+(?:change|edit|modify|write(?:\s+to)?|overwrite|delete|remove|rename|move|touch)\s+${GENERIC_FILES}\b(?!\s+${SCOPED_LIMIT_SUFFIX})`,
    'iu'
  ),
  new RegExp(
    String.raw`${DIRECTIVE_PREFIX}(?:(?:work|operate|proceed|review|inspect|analyse|analyze|audit)(?:\s+(?:this|the)\s+(?:folder|workspace|repository|repo|project|codebase))?\s+)?without\s+(?:changing|editing|modifying|writing(?:\s+to)?|overwriting|deleting|removing|renaming|moving|touching)\s+${GENERIC_FILES}\b(?!\s+${SCOPED_LIMIT_SUFFIX})`,
    'iu'
  ),
  new RegExp(
    String.raw`${DIRECTIVE_PREFIX}(?:do\s+not|don't|never|must\s+not)\s+make\s+(?:any\s+)?changes?(?:\s+to\s+${GENERIC_FILES})?\b(?!\s+${SCOPED_LIMIT_SUFFIX})`,
    'iu'
  ),
  new RegExp(
    String.raw`${DIRECTIVE_PREFIX}(?:do\s+not|don't|never|must\s+not)\s+change\s+(?:anything|anything\s+at\s+all)\b`,
    'iu'
  ),
  new RegExp(String.raw`${DIRECTIVE_PREFIX}(?:make\s+)?no\s+file\s+changes?\b`, 'iu'),
  new RegExp(
    String.raw`${DIRECTIVE_PREFIX}(?:this\s+(?:task|workspace|folder|repository|repo|project|codebase)\s+is|work|operate|proceed)\s+(?:in\s+)?read[- ]only(?:\s+mode)?\b`,
    'iu'
  ),
  new RegExp(
    String.raw`${DIRECTIVE_PREFIX}only\s+(?:read|inspect|review|analyse|analyze|audit)\s+(?:(?:the|this|these|those|my|our)\s+)?(?:files?|folder|workspace|repository|repo|project|codebase)\b(?!\s+${SCOPED_LIMIT_SUFFIX})`,
    'iu'
  ),
] as const;

const BROAD_COMMAND_BANS = [
  new RegExp(
    String.raw`${DIRECTIVE_PREFIX}(?:do\s+not|don't|never|must\s+not)\s+(?:run|execute|use)\s+(?:(?:any|all|the|these|those)\s+)?(?:commands?|terminal|shell|terminal\s+commands?|shell\s+commands?)\b(?!\s+${SCOPED_LIMIT_SUFFIX})`,
    'iu'
  ),
  new RegExp(
    String.raw`${DIRECTIVE_PREFIX}(?:(?:work|operate|proceed)\s+)?without\s+(?:running|executing|using)\s+(?:(?:any|all|the)\s+)?(?:commands?|terminal|shell|terminal\s+commands?|shell\s+commands?)\b(?!\s+${SCOPED_LIMIT_SUFFIX})`,
    'iu'
  ),
  new RegExp(
    String.raw`${DIRECTIVE_PREFIX}no\s+(?:commands?|terminal(?:\s+access)?|shell(?:\s+access)?|terminal\s+commands?|shell\s+commands?)\b`,
    'iu'
  ),
] as const;

const BROAD_NETWORK_BANS = [
  new RegExp(
    String.raw`${DIRECTIVE_PREFIX}(?:do\s+not|don't|never|must\s+not)\s+(?:use|access|connect\s+to)\s+(?:(?:any|the)\s+)?(?:network|internet)\b(?!\s+${SCOPED_LIMIT_SUFFIX})`,
    'iu'
  ),
  new RegExp(
    String.raw`${DIRECTIVE_PREFIX}(?:(?:work|operate|proceed|review|inspect|analyse|analyze|audit)(?:\s+(?:this|the)\s+(?:task|folder|workspace|repository|repo|project|codebase|release))?\s+)?(?:no|without)\s+(?:network|internet)(?:\s+access)?\b`,
    'iu'
  ),
  new RegExp(String.raw`${DIRECTIVE_PREFIX}(?:stay|work|operate|proceed)\s+offline\b`, 'iu'),
  new RegExp(String.raw`${DIRECTIVE_PREFIX}offline\s+only\b`, 'iu'),
] as const;

function matchesAny(value: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(value));
}

/**
 * Returns the exact user-written sentence that categorically blocks an action.
 *
 * This deliberately recognizes only broad, unambiguous English bans. Scoped
 * wording such as "Do not change package files" remains a review reminder: it
 * cannot safely be promoted into a global machine rule without knowing the targeted paths.
 * A file-change ban also blocks direct process execution because AccordLock's
 * terminal boundary does not claim filesystem sandboxing.
 */
export function literalBlockingUserLimit(
  objective: string,
  action: IntentActionKind
): string | null {
  for (const limit of extractUserLimits(objective, Number.MAX_SAFE_INTEGER)) {
    const blocksFileChanges = matchesAny(limit, BROAD_FILE_CHANGE_BANS);
    if (
      (action === 'shell' && (blocksFileChanges || matchesAny(limit, BROAD_COMMAND_BANS))) ||
      (action === 'https_request' && matchesAny(limit, BROAD_NETWORK_BANS)) ||
      (action !== 'shell' && action !== 'https_request' && blocksFileChanges)
    ) {
      return limit;
    }
  }
  return null;
}

/**
 * Returns literal constraints worth resurfacing at an exact action review.
 * The result is a reminder, not a machine verdict: wording can be ambiguous.
 */
export function relevantUserLimits(
  objective: string,
  action: IntentActionKind,
  maximum = 2
): string[] {
  const actionPattern =
    action === 'shell'
      ? COMMAND_LIMIT
      : action === 'https_request'
        ? /\b(?:network|internet|website|domain|url|request|download|upload|fetch|api|contact|send\s+data|outside|external|only\s+(?:inspect|read|review|analyse|analyze|audit))\b/iu
        : FILE_CHANGE_LIMIT;
  return extractUserLimits(objective, 12)
    .filter((limit) => actionPattern.test(limit))
    .slice(0, Math.max(0, maximum));
}

function capabilityLabel(capability: AccordLockTaskCapability): string {
  return normalizeForDisplay(capability.display_name);
}

/**
 * Builds a deterministic view of the authority that is about to be granted.
 * It does not infer intent with an LLM and does not grant any new permission.
 */
export function buildTaskIntentBrief(authorization: AccordLockTaskAuthorization): TaskIntentBrief {
  const automaticKeys = new Set(
    authorization.task_policy.preauthorized_capabilities.map(
      ({ extension_id, tool_name }) => `${extension_id}\u0000${tool_name}`
    )
  );

  const automatic: string[] = [];
  const requiresApproval: string[] = [];
  for (const capability of authorization.capabilities) {
    const key = `${capability.extension_id}\u0000${capability.tool_name}`;
    const target = automaticKeys.has(key) ? automatic : requiresApproval;
    const label = capabilityLabel(capability);
    if (!target.includes(label)) target.push(label);
  }

  const hasGovernedNetwork = authorization.capabilities.some(
    ({ extension_id, tool_name }) =>
      extension_id === 'accordlock_network' && tool_name === 'https_request'
  );
  return {
    outcome: authorization.objective,
    workspace: authorization.workspace_root,
    automatic,
    requiresApproval,
    unavailable: [
      ...(hasGovernedNetwork ? [] : ['Network access']),
      'Administrator access',
      'Protected settings and credentials',
    ],
    userLimits: extractUserLimits(authorization.objective),
  };
}
