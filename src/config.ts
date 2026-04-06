/**
 * Configuration loader for mcp-fence.
 *
 * Priority: CLI flags > YAML config file > defaults.
 * Validates config with zod schema.
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { FenceConfig } from './types.js';
import { ConfigError } from './errors.js';
import { createLogger } from './logger.js';

const log = createLogger('config');

const CONFIG_FILENAME = 'fence.config.yaml';

const logConfigSchema = z.object({
  level: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  file: z.string().optional(),
  maxDbSizeMb: z.number().positive().default(100),
});

const detectionConfigSchema = z.object({
  warnThreshold: z.number().min(0).max(1).default(0.5),
  blockThreshold: z.number().min(0).max(1).default(0.8),
  maxInputSize: z.number().positive().default(10240),
});

const argConstraintSchema = z.object({
  name: z.string(),
  denyPattern: z.string().optional(),
  allowPattern: z.string().optional(),
  caseInsensitive: z.boolean().default(false),
});

const policyRuleSchema = z.object({
  tool: z.string(),
  action: z.enum(['allow', 'deny']),
  args: z.array(argConstraintSchema).optional(),
});

const opaConfigSchema = z.object({
  enabled: z.boolean().default(false),
  url: z.string().url(),
  timeoutMs: z.number().positive().default(5000),
  failOpen: z.boolean().default(false),
  allowPrivateNetwork: z.boolean().default(false),
});

const policyConfigSchema = z.object({
  defaultAction: z.enum(['allow', 'deny']).default('allow'),
  rules: z.array(policyRuleSchema).default([]),
  opa: opaConfigSchema.optional(),
});

const dataFlowRuleSchema = z.object({
  from: z.string(),
  to: z.string(),
  action: z.enum(['allow', 'deny']),
});

const dataFlowConfigSchema = z.object({
  enabled: z.boolean().default(false),
  rules: z.array(dataFlowRuleSchema).default([]),
});

const jwtConfigSchema = z.object({
  enabled: z.boolean().default(false),
  secret: z.string().optional(),
  jwksUrl: z.string().url().optional(),
  audience: z.string().optional(),
  issuer: z.string().optional(),
});

const contextBudgetConfigSchema = z.object({
  enabled: z.boolean().default(false),
  maxResponseTokens: z.number().positive().default(10000),
  maxResponseBytes: z.number().positive().default(102400),
  truncateAction: z.enum(['warn', 'truncate', 'block']).default('warn'),
});

const fenceConfigSchema = z.object({
  mode: z.enum(['monitor', 'enforce']).default('monitor'),
  log: logConfigSchema.default({}),
  detection: detectionConfigSchema.default({}),
  policy: policyConfigSchema.default({}),
  jwt: jwtConfigSchema.optional(),
  dataFlow: dataFlowConfigSchema.optional(),
  contextBudget: contextBudgetConfigSchema.optional(),
});

export const DEFAULT_CONFIG: FenceConfig = {
  mode: 'monitor',
  log: { level: 'info', maxDbSizeMb: 100 },
  detection: {
    warnThreshold: 0.5,
    blockThreshold: 0.8,
    maxInputSize: 10240,
  },
  policy: {
    defaultAction: 'allow',
    rules: [],
  },
};

/**
 * Load configuration from YAML file, falling back to defaults.
 *
 * @param configPath - Explicit path to config file. If not provided, searches CWD.
 * @returns Validated FenceConfig
 */
export function loadConfig(configPath?: string): FenceConfig {
  const filePath = configPath ?? resolve(process.cwd(), CONFIG_FILENAME);

  if (!existsSync(filePath)) {
    log.info(`No config file found at ${filePath}, using defaults (monitor mode)`);
    return DEFAULT_CONFIG;
  }

  try {
    const raw = readFileSync(filePath, 'utf-8');
    const parsed = parseYaml(raw) as unknown;
    const validated = fenceConfigSchema.parse(parsed);
    log.info(`Config loaded from ${filePath} (mode: ${validated.mode})`);
    return validated;
  } catch (err) {
    if (err instanceof z.ZodError) {
      const issues = err.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
      throw new ConfigError(`Invalid config in ${filePath}:\n${issues}`);
    }
    throw new ConfigError(`Failed to read config: ${filePath}`);
  }
}

/**
 * Generate a default config YAML file.
 */
export function generateDefaultConfigYaml(): string {
  return `# mcp-fence configuration
# Docs: https://github.com/yjcho9317/mcp-fence

# Operation mode: "monitor" (log only) or "enforce" (block threats)
mode: monitor

log:
  level: info
  # file: ./mcp-fence.log  # uncomment to log to file

detection:
  warnThreshold: 0.5
  blockThreshold: 0.8
  maxInputSize: 10240  # bytes

# Policy rules for tool access control
policy:
  defaultAction: allow  # "allow" or "deny"
  rules: []
  # Example rules:
  # - tool: "exec_cmd"
  #   action: deny
  # - tool: "read_file"
  #   action: allow
  #   args:
  #     - name: path
  #       denyPattern: "^/etc/|^\\.env$"
  # - tool: "write_*"
  #   action: deny
`;
}
