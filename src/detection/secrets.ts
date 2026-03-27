/**
 * Secret and credential detection patterns for mcp-fence.
 *
 * Detects API keys, tokens, passwords, private keys, and other credentials
 * that should not appear in MCP tool responses. Targets OWASP MCP01 (Token/Secret Exposure).
 *
 * Most secret leaks happen in the RESPONSE direction — a tool reads a file
 * or queries a database, and the result contains credentials. The AI agent
 * then has those credentials in its context, creating an exfiltration risk.
 */

import type { DetectionPattern } from './patterns.js';

const secretPatterns: DetectionPattern[] = [
  // ─── Cloud Provider Keys ───
  {
    id: 'SEC-001',
    name: 'aws_access_key',
    description: 'AWS Access Key ID detected',
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.95,
    direction: 'both',
  },
  {
    id: 'SEC-002',
    name: 'aws_secret_key',
    description: 'AWS Secret Access Key detected',
    pattern: /\b[0-9a-zA-Z/+]{40}\b(?=.*(?:aws|secret|key))/i,
    category: 'secret',
    severity: 'critical',
    confidence: 0.7,
    direction: 'both',
  },
  {
    id: 'SEC-003',
    name: 'gcp_service_account',
    description: 'GCP service account key detected',
    pattern: /"type"\s*:\s*"service_account"/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.9,
    direction: 'response',
  },
  {
    id: 'SEC-004',
    name: 'azure_connection_string',
    description: 'Azure connection string detected',
    pattern: /(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/]{20,}={0,3}/i,
    category: 'secret',
    severity: 'critical',
    confidence: 0.9,
    direction: 'both',
  },

  // ─── API Tokens ───
  {
    id: 'SEC-010',
    name: 'github_token',
    description: 'GitHub personal access token detected',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.95,
    direction: 'both',
  },
  {
    id: 'SEC-011',
    name: 'gitlab_token',
    description: 'GitLab token detected',
    pattern: /\bglpat-[A-Za-z0-9\-_]{20,}\b/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.95,
    direction: 'both',
  },
  {
    id: 'SEC-012',
    name: 'slack_token',
    description: 'Slack API token detected',
    pattern: /\bxox[bporas]-[0-9a-zA-Z\-]{10,}\b/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.95,
    direction: 'both',
  },
  {
    id: 'SEC-013',
    name: 'stripe_key',
    description: 'Stripe API key detected',
    pattern: /\b[sr]k_(?:live|test)_[0-9a-zA-Z]{20,}\b/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.95,
    direction: 'both',
  },
  {
    id: 'SEC-014',
    name: 'openai_key',
    description: 'OpenAI API key detected',
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9]{2}[A-Za-z0-9\-_]{18,}(?=[^A-Za-z0-9\-_]|$)/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.85,
    direction: 'both',
  },
  {
    id: 'SEC-015',
    name: 'anthropic_key',
    description: 'Anthropic API key detected',
    pattern: /\bsk-ant-[A-Za-z0-9\-_]{20,}\b/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.95,
    direction: 'both',
  },

  // ─── Authentication Credentials ───
  {
    id: 'SEC-020',
    name: 'jwt_token',
    description: 'JSON Web Token detected',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
    category: 'secret',
    severity: 'high',
    confidence: 0.9,
    direction: 'both',
  },
  {
    id: 'SEC-021',
    name: 'private_key',
    description: 'Private key material detected',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.98,
    direction: 'both',
  },
  {
    id: 'SEC-022',
    name: 'password_in_url',
    description: 'Password embedded in URL or connection string',
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{4,}/i,
    category: 'secret',
    severity: 'high',
    confidence: 0.75,
    direction: 'both',
  },
  {
    id: 'SEC-023',
    name: 'database_url',
    description: 'Database connection string with credentials',
    pattern: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^:]+:[^@]+@/i,
    category: 'secret',
    severity: 'critical',
    confidence: 0.9,
    direction: 'both',
  },
  {
    id: 'SEC-024',
    name: 'bearer_token',
    description: 'Bearer authentication token detected',
    pattern: /\bBearer\s+[A-Za-z0-9\-._~+/]{20,}\b/,
    category: 'secret',
    severity: 'high',
    confidence: 0.8,
    direction: 'both',
  },

  // ─── Additional Provider Tokens ───
  {
    id: 'SEC-016',
    name: 'digitalocean_token',
    description: 'DigitalOcean personal access token detected',
    pattern: /\bdop_v1_[0-9a-f]{64}\b/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.95,
    direction: 'both',
  },
  {
    id: 'SEC-017',
    name: 'sendgrid_key',
    description: 'SendGrid API key detected',
    pattern: /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.95,
    direction: 'both',
  },
  {
    id: 'SEC-018',
    name: 'npm_token',
    description: 'NPM access token detected',
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.95,
    direction: 'both',
  },
  {
    id: 'SEC-019',
    name: 'pypi_token',
    description: 'PyPI API token detected',
    pattern: /\bpypi-[A-Za-z0-9\-_]{16,}\b/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.9,
    direction: 'both',
  },
  {
    id: 'SEC-025',
    name: 'vercel_token',
    description: 'Vercel authentication token detected',
    pattern: /\bvercel_[A-Za-z0-9]{24,}\b/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.9,
    direction: 'both',
  },
  {
    id: 'SEC-026',
    name: 'firebase_google_api_key',
    description: 'Firebase or Google API key detected',
    pattern: /\bAIza[A-Za-z0-9\-_]{35}\b/,
    category: 'secret',
    severity: 'high',
    confidence: 0.85,
    direction: 'both',
  },
  {
    id: 'SEC-027',
    name: 'ssh_connection_url',
    description: 'SSH connection URL that may contain credentials',
    pattern: /\bssh:\/\/[^\s]{4,}/i,
    category: 'secret',
    severity: 'high',
    confidence: 0.75,
    direction: 'both',
  },

  // ─── Generic Secrets ───
  {
    id: 'SEC-030',
    name: 'generic_api_key',
    description: 'Generic API key assignment detected',
    pattern: /(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9\-._]{16,}['"]?/i,
    category: 'secret',
    severity: 'high',
    confidence: 0.7,
    direction: 'both',
  },
  {
    id: 'SEC-031',
    name: 'env_variable_secret',
    description: 'Environment variable containing a secret value',
    pattern: /(?:SECRET|TOKEN|PASSWORD|CREDENTIAL|API_KEY)\s*=\s*['"]?[^\s'"]{8,}['"]?/,
    category: 'secret',
    severity: 'high',
    confidence: 0.75,
    direction: 'response',
  },
];

export const ALL_SECRET_PATTERNS: readonly DetectionPattern[] = secretPatterns;

/**
 * Get secret patterns applicable to a given direction.
 */
export function getSecretPatternsForDirection(
  direction: 'request' | 'response',
): DetectionPattern[] {
  return ALL_SECRET_PATTERNS.filter(
    (p) => p.direction === direction || p.direction === 'both',
  );
}
