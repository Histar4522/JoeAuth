import type { Bindings, RegistrationRuleRow } from '../types';

export interface RuleTemplate {
  id: string;
  label: string;
  ruleType: 'allow' | 'deny';
  pattern: string;
  priority: number;
  description: string;
}

export const REGISTRATION_RULE_TEMPLATES: RuleTemplate[] = [
  {
    id: 'specific-email',
    label: 'Specific Email (Allow)',
    ruleType: 'allow',
    pattern: '^joe@example\\.com$',
    priority: 50,
    description: 'Allow one specific email address',
  },
  {
    id: 'specific-domain',
    label: 'Specific Domain (Allow)',
    ruleType: 'allow',
    pattern: '^[^@]+@example\\.com$',
    priority: 100,
    description: 'Allow any user @example.com',
  },
  {
    id: 'domain-subdomains',
    label: 'Domain + Subdomains (Allow)',
    ruleType: 'allow',
    pattern: '^[^@]+@([a-z0-9-]+\\.)?example\\.com$',
    priority: 110,
    description: 'Allow domain and any subdomain',
  },
  {
    id: 'deny-plus-alias',
    label: 'Block +Aliases (Deny)',
    ruleType: 'deny',
    pattern: '\\+[^@]*@',
    priority: 10,
    description: 'Deny email plus-addressing aliases',
  },
  {
    id: 'allow-all',
    label: 'Allow All Valid Emails (Override)',
    ruleType: 'allow',
    pattern: '^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$',
    priority: 999,
    description: 'Open registration fallback when enabled',
  },
];

const RULES_CACHE_KEY = 'rules:active';

/**
 * Validates regex syntax and rejects obvious nested-quantifier ReDoS patterns
 * so evaluation stays well inside Cloudflare Workers' 10 ms CPU budget.
 */
export function validateRulePattern(pattern: string): { valid: boolean; error?: string } {
  const trimmed = pattern.trim();
  if (!trimmed || trimmed.length > 256) {
    return { valid: false, error: 'Regex pattern must be 1 to 256 characters.' };
  }
  // Reject nested quantifiers such as (a+)+, (.*)*, ([a-z]+){2,}
  if (/\([^)]*([+*]|\{\d+,?\d*\})[^)]*\)\s*([+*?]|\{\d+,?\d*\})/.test(trimmed)) {
    return { valid: false, error: 'Pattern rejected for ReDoS safety (nested quantifiers).' };
  }
  try {
    new RegExp(trimmed, 'i');
    return { valid: true };
  } catch (err) {
    return { valid: false, error: err instanceof Error ? err.message : 'Invalid regular expression.' };
  }
}

export async function getActiveRules(env: Bindings): Promise<RegistrationRuleRow[]> {
  const cached = await env.AUTH_CACHE.get(RULES_CACHE_KEY, 'json').catch(() => null);
  if (Array.isArray(cached)) {
    return cached as RegistrationRuleRow[];
  }
  const { results } = await env.DB.prepare(
    'SELECT * FROM registration_rules WHERE is_active = 1 ORDER BY priority ASC, created_at ASC'
  ).all<RegistrationRuleRow>();

  const rows = results || [];
  await env.AUTH_CACHE.put(RULES_CACHE_KEY, JSON.stringify(rows), { expirationTtl: 3600 }).catch(() => {});
  return rows;
}

export async function invalidateRulesCache(env: Bindings): Promise<void> {
  await env.AUTH_CACHE.delete(RULES_CACHE_KEY).catch(() => {});
}

export interface EmailRuleEvaluation {
  allowed: boolean;
  matchedRule: RegistrationRuleRow | null;
  reason: string;
}

/**
 * Approve-nothing by default:
 * Evaluates active rules ordered by `priority ASC`.
 * First matching rule decides ('allow' -> true, 'deny' -> false).
 * If no rule matches -> denied by default.
 */
export function evaluateRegistrationEmail(
  email: string,
  rules: RegistrationRuleRow[]
): EmailRuleEvaluation {
  const normalized = email.trim().toLowerCase();
  if (!normalized || normalized.length > 254 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalized)) {
    return { allowed: false, matchedRule: null, reason: 'Invalid email address format.' };
  }

  for (const rule of rules) {
    if (!rule.is_active) continue;
    try {
      const re = new RegExp(rule.pattern, 'i');
      if (re.test(normalized)) {
        return {
          allowed: rule.rule_type === 'allow',
          matchedRule: rule,
          reason:
            rule.rule_type === 'allow'
              ? `Allowed by rule "${rule.description || rule.pattern}"`
              : `Blocked by deny rule "${rule.description || rule.pattern}"`,
        };
      }
    } catch {
      // Skip malformed stored patterns safely
    }
  }

  return {
    allowed: false,
    matchedRule: null,
    reason: 'Registration is closed: email did not match any allow rule (default deny).',
  };
}
