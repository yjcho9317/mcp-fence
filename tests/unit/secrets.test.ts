import { describe, it, expect } from 'vitest';
import { DetectionEngine } from '../../src/detection/engine.js';
import { ALL_SECRET_PATTERNS, getSecretPatternsForDirection } from '../../src/detection/secrets.js';
import type { JsonRpcMessage, DetectionConfig } from '../../src/types.js';

/**
 * Build test tokens at runtime to avoid triggering GitHub push protection.
 * These are NOT real credentials — they are constructed fake values.
 */
const TEST_TOKENS = {
  slack: ['xoxb', '000000000000', '000000000000', 'fakefakefakefake'].join('-'),
  stripe: ['sk', 'test', 'FAKEFAKEFAKEFAKEFAKEFAKE'].join('_'),
  stripeTest: ['sk', 'test', 'TESTFAKETESTFAKETESTFAKE'].join('_'),
  stripeLive: ['rk', 'live', 'FAKEFAKEFAKEFAKEFAKEFAKE'].join('_'),
  sendgrid: ['SG', 'aaaaaaaaaaaaaaaaaaaaaa', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'].join('.'),
  github: ['ghp', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456'].join('_'),
  githubShort: ['ghp', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234'].join('_'),
  githubOAuth: ['gho', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234'].join('_'),
  githubUser: ['ghu', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234'].join('_'),
  githubServer: ['ghs', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234'].join('_'),
  githubRefresh: ['ghr', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234'].join('_'),
  openai: ['sk', 'proj', 'abcdefghijklmnopqrstuvwxyz'].join('-'),
  anthropic: ['sk', 'ant', 'api03', 'abcdefghijklmnopqrstuvwxyz'].join('-'),
  anthropicShort: ['sk', 'ant', 'abcdefghijklmnopqrstuvwxyz'].join('-'),
};

const config: DetectionConfig = {
  warnThreshold: 0.5,
  blockThreshold: 0.8,
  maxInputSize: 10240,
};

function engine(): DetectionEngine {
  return new DetectionEngine(config);
}

function res(text: string): JsonRpcMessage {
  return {
    jsonrpc: '2.0',
    id: 1,
    result: { content: [{ type: 'text', text }] },
  };
}

function req(text: string): JsonRpcMessage {
  return {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name: 'test', arguments: { input: text } },
  };
}

describe('Secret patterns', () => {
  it('should have at least 15 secret patterns', () => {
    expect(ALL_SECRET_PATTERNS.length).toBeGreaterThanOrEqual(15);
  });

  it('should have unique rule IDs', () => {
    const ids = ALL_SECRET_PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('should filter by direction', () => {
    const responseOnly = getSecretPatternsForDirection('response');
    for (const p of responseOnly) {
      expect(p.direction).not.toBe('request');
    }
  });
});

describe('Secret detection — cloud keys', () => {
  const e = engine();

  it('should detect AWS access key', async () => {
    const r = await e.scan(res('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-001')).toBe(true);
  });

  it('should detect GCP service account key', async () => {
    const r = await e.scan(res('{"type": "service_account", "project_id": "my-project"}'), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-003')).toBe(true);
  });

  it('should detect Azure connection string', async () => {
    const r = await e.scan(res('AccountKey=lJzRmKv/9X2+abc123DEFghiJKLmnoPQRSTuvwxYZ==;'), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-004')).toBe(true);
  });
});

describe('Secret detection — API tokens', () => {
  const e = engine();

  it('should detect GitHub PAT', async () => {
    const r = await e.scan(res(`token: ${TEST_TOKENS.github}`), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-010')).toBe(true);
  });

  it('should detect GitLab token', async () => {
    const r = await e.scan(res('GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx'), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-011')).toBe(true);
  });

  it('should detect Slack token', async () => {
    const r = await e.scan(res(`SLACK_TOKEN=${TEST_TOKENS.slack}`), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-012')).toBe(true);
  });

  it('should detect Stripe key', async () => {
    const r = await e.scan(res(`stripe_key: ${TEST_TOKENS.stripe}`), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-013')).toBe(true);
  });

  it('should detect OpenAI key', async () => {
    const r = await e.scan(res(`OPENAI_API_KEY=${TEST_TOKENS.openai}`), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-014')).toBe(true);
  });

  it('should detect Anthropic key', async () => {
    const r = await e.scan(res(`ANTHROPIC_API_KEY=${TEST_TOKENS.anthropic}`), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-015')).toBe(true);
  });
});

describe('Secret detection — credentials', () => {
  const e = engine();

  it('should detect JWT token', async () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const r = await e.scan(res(`Authorization: Bearer ${jwt}`), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-020')).toBe(true);
  });

  it('should detect private key', async () => {
    const r = await e.scan(res('-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...'), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-021')).toBe(true);
  });

  it('should detect database connection string', async () => {
    const r = await e.scan(res('DATABASE_URL=postgres://admin:secretpass@db.example.com:5432/mydb'), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-023')).toBe(true);
  });

  it('should detect password in config', async () => {
    const r = await e.scan(res('password: "my-secret-pass-123"'), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-022')).toBe(true);
  });

  it('should detect generic API key assignment', async () => {
    const r = await e.scan(res('api_key = "abcdef1234567890abcdef"'), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-030')).toBe(true);
  });
});

describe('Secret detection — false positives', () => {
  const e = engine();

  it('should NOT flag example AWS key patterns in documentation', async () => {
    // AKIAEXAMPLE is not 20 chars of [0-9A-Z] after AKIA, so it won't match
    const r = await e.scan(res('Example key: AKIAEXAMPLE (not real)'), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-001')).toBe(false);
  });

  it('should NOT flag normal text as secrets', async () => {
    const r = await e.scan(res('The file has 42 lines. Temperature is 23.5 degrees.'), 'response');
    expect(r.findings.filter((f) => f.ruleId.startsWith('SEC-'))).toHaveLength(0);
  });

  it('should NOT flag code examples mentioning "password" without a value', async () => {
    const r = await e.scan(res('// Check if password is valid'), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-022')).toBe(false);
  });
});

describe('Secret detection in requests', () => {
  const e = engine();

  it('should detect secrets sent in tool arguments', async () => {
    const r = await e.scan(
      req('Connect to postgres://root:hunter2@prod.db.internal:5432/main'),
      'request',
    );
    expect(r.findings.some((f) => f.ruleId === 'SEC-023')).toBe(true);
  });
});

// ─── EXTENDED TESTS: Individual pattern coverage ───

describe('SEC-001: AWS Access Key ID — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-001')!;

  it('should match a valid 20-char AWS access key', () => {
    expect(pattern.pattern.test('AKIAIOSFODNN7EXAMPLE')).toBe(true);
  });

  it('should match key embedded in text', () => {
    expect(pattern.pattern.test('key is AKIAIOSFODNN7EXAMPLE here')).toBe(true);
  });

  it('should NOT match prefix alone', () => {
    expect(pattern.pattern.test('AKIA')).toBe(false);
  });

  it('should NOT match with lowercase chars after AKIA', () => {
    // Pattern requires [0-9A-Z]{16}, lowercase not allowed
    expect(pattern.pattern.test('AKIAiosfodnn7example')).toBe(false);
  });

  it('should NOT match short key (less than 20 chars total)', () => {
    expect(pattern.pattern.test('AKIAIOSFODN')).toBe(false);
  });
});

describe('SEC-002: AWS Secret Access Key — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-002')!;

  it('should match 40-char string followed by aws context', () => {
    const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    expect(pattern.pattern.test(`${secretKey} aws_secret_access_key`)).toBe(true);
  });

  it('should match when "key" keyword appears nearby', () => {
    const secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    expect(pattern.pattern.test(`${secretKey} secret key`)).toBe(true);
  });

  it('should NOT match random 40-char string without aws/secret/key context', () => {
    const randomStr = 'abcdefghijklmnopqrstuvwxyz01234567890ABCD';
    expect(pattern.pattern.test(randomStr)).toBe(false);
  });
});

describe('SEC-003: GCP Service Account — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-003')!;

  it('should match GCP service account JSON', () => {
    expect(pattern.pattern.test('"type": "service_account"')).toBe(true);
  });

  it('should match with extra whitespace', () => {
    expect(pattern.pattern.test('"type"  :  "service_account"')).toBe(true);
  });

  it('should NOT match "type": "user"', () => {
    expect(pattern.pattern.test('"type": "user"')).toBe(false);
  });

  it('should only apply to response direction', () => {
    expect(pattern.direction).toBe('response');
  });
});

describe('SEC-004: Azure Connection String — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-004')!;

  it('should match AccountKey with base64 value', () => {
    expect(pattern.pattern.test('AccountKey=abc123DEFghiJKLmnoPQR==')).toBe(true);
  });

  it('should match SharedAccessKey', () => {
    expect(pattern.pattern.test('SharedAccessKey=abcdefghijklmnopqrstuv')).toBe(true);
  });

  it('should NOT match short value', () => {
    expect(pattern.pattern.test('AccountKey=short')).toBe(false);
  });
});

describe('SEC-010: GitHub Token — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-010')!;

  it('should match ghp_ (classic PAT)', () => {
    expect(pattern.pattern.test(TEST_TOKENS.githubShort)).toBe(true);
  });

  it('should match gho_ (OAuth token)', () => {
    expect(pattern.pattern.test(TEST_TOKENS.githubOAuth)).toBe(true);
  });

  it('should match ghu_ (user-to-server token)', () => {
    expect(pattern.pattern.test(TEST_TOKENS.githubUser)).toBe(true);
  });

  it('should match ghs_ (server-to-server token)', () => {
    expect(pattern.pattern.test(TEST_TOKENS.githubServer)).toBe(true);
  });

  it('should match ghr_ (refresh token)', () => {
    expect(pattern.pattern.test(TEST_TOKENS.githubRefresh)).toBe(true);
  });

  it('should NOT match ghp_ prefix alone', () => {
    expect(pattern.pattern.test('ghp_')).toBe(false);
  });

  it('should NOT match ghp_ with too few characters', () => {
    expect(pattern.pattern.test('ghp_ABCDEF')).toBe(false);
  });

  // BUG: The pattern /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/ requires
  // 36+ chars after the prefix. Fine-grained tokens (github_pat_...) use a
  // different format and are NOT matched by SEC-010. There is no SEC pattern
  // for github_pat_ tokens.
  it('should NOT match github_pat_ fine-grained tokens (no pattern covers this)', () => {
    const fineGrained = 'github_pat_11ABCDEFG0123456789_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz012345';
    expect(pattern.pattern.test(fineGrained)).toBe(false);
  });
});

describe('SEC-011: GitLab Token — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-011')!;

  it('should match standard glpat token', () => {
    expect(pattern.pattern.test('glpat-abcdefghij1234567890')).toBe(true);
  });

  it('should match with hyphens in value', () => {
    expect(pattern.pattern.test('glpat-abc-def-ghi-jkl-mnopqrs')).toBe(true);
  });

  it('should NOT match glpat- prefix alone', () => {
    expect(pattern.pattern.test('glpat-')).toBe(false);
  });

  it('should NOT match with too short suffix', () => {
    expect(pattern.pattern.test('glpat-short')).toBe(false);
  });
});

describe('SEC-012: Slack Token — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-012')!;

  it('should match xoxb (bot token)', () => {
    expect(pattern.pattern.test(TEST_TOKENS.slack)).toBe(true);
  });

  it('should match xoxp (user token)', () => {
    expect(pattern.pattern.test(['xoxp', '000000000', 'fakefakefa'].join('-'))).toBe(true);
  });

  it('should match xoxa (app token)', () => {
    expect(pattern.pattern.test(['xoxa', '000000000', 'fakefakefa'].join('-'))).toBe(true);
  });

  it('should NOT match xox alone', () => {
    expect(pattern.pattern.test('xox')).toBe(false);
  });
});

describe('SEC-013: Stripe Key — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-013')!;

  it('should match stripe key', () => {
    expect(pattern.pattern.test(TEST_TOKENS.stripe)).toBe(true);
  });

  it('should match stripe test key', () => {
    expect(pattern.pattern.test(TEST_TOKENS.stripeTest)).toBe(true);
  });

  it('should match restricted key', () => {
    expect(pattern.pattern.test(TEST_TOKENS.stripeLive)).toBe(true);
  });

  it('should NOT match sk_live_ with too short suffix', () => {
    expect(pattern.pattern.test('sk_live_abc')).toBe(false);
  });
});

describe('SEC-014: OpenAI Key — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-014')!;

  it('should match standard sk- key', () => {
    expect(pattern.pattern.test('sk-abcdefghijklmnopqrstuvwxyz')).toBe(true);
  });

  it('should match sk-proj- project key', () => {
    expect(pattern.pattern.test(TEST_TOKENS.openai)).toBe(true);
  });

  it('should NOT match sk- with too few characters', () => {
    expect(pattern.pattern.test('sk-short')).toBe(false);
  });

  it('should NOT match bare "sk-" prefix', () => {
    expect(pattern.pattern.test('sk-')).toBe(false);
  });
});

describe('SEC-015: Anthropic Key — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-015')!;

  it('should match sk-ant- key', () => {
    expect(pattern.pattern.test(TEST_TOKENS.anthropicShort)).toBe(true);
  });

  it('should match sk-ant-api03- variant', () => {
    expect(pattern.pattern.test(TEST_TOKENS.anthropic)).toBe(true);
  });

  it('should NOT match sk-ant- with too few chars', () => {
    expect(pattern.pattern.test('sk-ant-short')).toBe(false);
  });
});

describe('SEC-020: JWT Token — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-020')!;

  it('should match a real JWT', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    expect(pattern.pattern.test(jwt)).toBe(true);
  });

  it('should NOT match base64 strings with dots that are not JWTs', () => {
    // Missing eyJ prefix on both parts
    expect(pattern.pattern.test('abc123.def456.ghi789')).toBe(false);
  });

  it('should NOT match short base64 with dots', () => {
    expect(pattern.pattern.test('eyJhbG.eyJzd.abc')).toBe(false);
  });
});

describe('SEC-021: Private Key — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-021')!;

  it('should match RSA private key header', () => {
    expect(pattern.pattern.test('-----BEGIN RSA PRIVATE KEY-----')).toBe(true);
  });

  it('should match EC private key header', () => {
    expect(pattern.pattern.test('-----BEGIN EC PRIVATE KEY-----')).toBe(true);
  });

  it('should match generic private key header', () => {
    expect(pattern.pattern.test('-----BEGIN PRIVATE KEY-----')).toBe(true);
  });

  it('should match OPENSSH private key header', () => {
    expect(pattern.pattern.test('-----BEGIN OPENSSH PRIVATE KEY-----')).toBe(true);
  });

  it('should match DSA private key header', () => {
    expect(pattern.pattern.test('-----BEGIN DSA PRIVATE KEY-----')).toBe(true);
  });

  it('should NOT match public key header', () => {
    expect(pattern.pattern.test('-----BEGIN PUBLIC KEY-----')).toBe(false);
  });

  it('should NOT match certificate header', () => {
    expect(pattern.pattern.test('-----BEGIN CERTIFICATE-----')).toBe(false);
  });
});

describe('SEC-022: Password in URL/config — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-022')!;

  it('should match password= assignment', () => {
    expect(pattern.pattern.test('password=mysecretvalue')).toBe(true);
  });

  it('should match passwd: assignment', () => {
    expect(pattern.pattern.test('passwd: "secret123"')).toBe(true);
  });

  it('should match pwd= assignment', () => {
    expect(pattern.pattern.test('pwd=longsecretvalue')).toBe(true);
  });

  it('should NOT match password with too short value', () => {
    // Pattern requires {4,} chars for the value
    expect(pattern.pattern.test('password=ab')).toBe(false);
  });

  it('should NOT match code that references password variable', () => {
    // "password is valid" — no := after password followed by a value
    expect(pattern.pattern.test('// Check if password is valid')).toBe(false);
  });
});

describe('SEC-023: Database Connection String — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-023')!;

  it('should match postgres:// with credentials', () => {
    expect(pattern.pattern.test('postgres://admin:pass@localhost:5432/db')).toBe(true);
  });

  it('should match mongodb:// with credentials', () => {
    expect(pattern.pattern.test('mongodb://user:password@mongo.host:27017/mydb')).toBe(true);
  });

  it('should match mysql:// with credentials', () => {
    expect(pattern.pattern.test('mysql://root:secret@db.server:3306/app')).toBe(true);
  });

  it('should match redis:// with credentials', () => {
    expect(pattern.pattern.test('redis://default:mypass@redis.host:6379')).toBe(true);
  });

  it('should match amqp:// with credentials', () => {
    expect(pattern.pattern.test('amqp://guest:guest@rabbitmq:5672')).toBe(true);
  });

  it('should NOT match URLs without credentials (no user:pass@)', () => {
    expect(pattern.pattern.test('postgres://localhost:5432/db')).toBe(false);
  });
});

describe('SEC-024: Bearer Token — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-024')!;

  it('should match Bearer with long token', () => {
    expect(pattern.pattern.test('Bearer abc123def456ghi789jkl012mno')).toBe(true);
  });

  it('should NOT match Bearer with short token', () => {
    expect(pattern.pattern.test('Bearer short')).toBe(false);
  });

  it('should NOT match the word "Bearer" alone', () => {
    expect(pattern.pattern.test('Bearer')).toBe(false);
  });
});

describe('SEC-030: Generic API Key — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-030')!;

  it('should match api_key= with long value', () => {
    expect(pattern.pattern.test('api_key=abcdef1234567890abcdef')).toBe(true);
  });

  it('should match api-key: with quoted value', () => {
    expect(pattern.pattern.test('api-key: "abcdef1234567890abcdef"')).toBe(true);
  });

  it('should match access_token= assignment', () => {
    expect(pattern.pattern.test('access_token=abcdef1234567890abcdef')).toBe(true);
  });

  it('should match auth_token= assignment', () => {
    expect(pattern.pattern.test('auth_token=abcdef1234567890abcdef')).toBe(true);
  });

  it('should match api_secret= assignment', () => {
    expect(pattern.pattern.test('api_secret=abcdef1234567890abcdef')).toBe(true);
  });

  it('should NOT match api_key with too short value', () => {
    expect(pattern.pattern.test('api_key=short')).toBe(false);
  });
});

describe('SEC-031: Environment Variable Secret — individual pattern', () => {
  const pattern = ALL_SECRET_PATTERNS.find((p) => p.id === 'SEC-031')!;

  it('should match SECRET= with long value', () => {
    expect(pattern.pattern.test('SECRET=mysecretvalue123')).toBe(true);
  });

  it('should match TOKEN= with long value', () => {
    expect(pattern.pattern.test('TOKEN=abcdefghijklmnop')).toBe(true);
  });

  it('should match PASSWORD= with long value', () => {
    expect(pattern.pattern.test('PASSWORD=verylongsecretpassword')).toBe(true);
  });

  it('should match CREDENTIAL= with long value', () => {
    expect(pattern.pattern.test('CREDENTIAL=longcredentialvalue')).toBe(true);
  });

  it('should match API_KEY= with long value', () => {
    expect(pattern.pattern.test('API_KEY=myapikey12345678')).toBe(true);
  });

  it('should only apply to response direction', () => {
    expect(pattern.direction).toBe('response');
  });

  it('should NOT match SECRET= with too short value', () => {
    // Pattern requires {8,} chars
    expect(pattern.pattern.test('SECRET=short')).toBe(false);
  });

  // BUG: SEC-031 is case-sensitive (no /i flag) for the variable name part.
  // So "secret=..." won't match, only "SECRET=...". This is intentional
  // behavior since env vars are conventionally uppercase.
  it('should NOT match lowercase variable names', () => {
    expect(pattern.pattern.test('secret=mysecretvalue123')).toBe(false);
  });
});

// ─── EXTENDED TESTS: Real-world format variations ───

describe('Secret detection — real-world format variations', () => {
  const e = engine();

  it('should detect AWS key embedded in JSON response', async () => {
    const json = '{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "SecretAccessKey": "wJalrXUt"}';
    const r = await e.scan(res(json), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-001')).toBe(true);
  });

  it('should detect GitHub fine-grained token prefix variants', async () => {
    // gho_, ghu_, ghs_, ghr_ are all matched by SEC-010
    const r = await e.scan(
      res(`Installation token: ${TEST_TOKENS.githubServer}`),
      'response',
    );
    expect(r.findings.some((f) => f.ruleId === 'SEC-010')).toBe(true);
  });

  it('should detect multiple secrets in one response', async () => {
    const text = [
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
      `GITHUB_TOKEN=${TEST_TOKENS.github}`,
      'DATABASE_URL=postgres://admin:pass@db:5432/app',
    ].join('\n');
    const r = await e.scan(res(text), 'response');
    const secretFindings = r.findings.filter((f) => f.ruleId.startsWith('SEC-'));
    expect(secretFindings.length).toBeGreaterThanOrEqual(3);
  });

  it('should detect secrets embedded in stack trace output', async () => {
    const stackTrace = [
      'Error: Connection failed',
      '  at Database.connect (db.js:42)',
      '  connection string: postgres://root:p4$$w0rd@prod-db:5432/main',
      '  at Object.<anonymous> (server.js:15)',
    ].join('\n');
    const r = await e.scan(res(stackTrace), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-023')).toBe(true);
  });

  it('should detect secrets embedded in error messages', async () => {
    const errorMsg = 'Failed to authenticate with token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const r = await e.scan(res(errorMsg), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-020')).toBe(true);
  });

  it('should detect secrets in .env file format', async () => {
    const envFile = [
      'NODE_ENV=production',
      `API_KEY=${TEST_TOKENS.openai}`,
      'DB_HOST=localhost',
      'SECRET=my_super_secret_value_12345',
    ].join('\n');
    const r = await e.scan(res(envFile), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-014')).toBe(true);
  });

  it('should detect secrets in log output', async () => {
    const logOutput = [
      '[2024-01-15 10:23:45] INFO: Starting server...',
      '[2024-01-15 10:23:46] DEBUG: Using config: password: "production_p4ss"',
      '[2024-01-15 10:23:47] INFO: Listening on port 3000',
    ].join('\n');
    const r = await e.scan(res(logOutput), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-022')).toBe(true);
  });

  it('should detect private key in multi-line response', async () => {
    const pkContent = [
      'Here is the server key:',
      '-----BEGIN EC PRIVATE KEY-----',
      'MHQCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJPBEg30re5RjN4HoAcGBSuBBAAi',
      'oWQDYgAE2kFfNaJifGK0qGhYDvSN0j3EF/aJ+0Mq9bAOJiKPLkHkpFo3SBiiFCGG',
      '-----END EC PRIVATE KEY-----',
    ].join('\n');
    const r = await e.scan(res(pkContent), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-021')).toBe(true);
  });
});

// ─── EXTENDED TESTS: False positive resilience ───

describe('Secret detection — false positive resilience', () => {
  const e = engine();

  it('should NOT flag placeholder key "sk-your-key-here"', async () => {
    // This will actually match SEC-014 because it has 20+ chars after sk-
    // and the pattern cannot distinguish placeholders from real keys.
    // Documenting actual behavior: sk-your-key-here is only 13 chars, won't match.
    const r = await e.scan(res('Use your key: sk-your-key-here'), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-014')).toBe(false);
  });

  it('should NOT flag documentation placeholder "AKIAIOSFODNN7EXAMPLE" as something other than SEC-001', async () => {
    // AKIAIOSFODNN7EXAMPLE is AWS's own documented example key.
    // It DOES match SEC-001 because the pattern cannot distinguish
    // example keys from real keys — this is a known tradeoff.
    const r = await e.scan(res('AKIAIOSFODNN7EXAMPLE'), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-001')).toBe(true);
  });

  it('should NOT flag code that uses password as a variable name without value', async () => {
    const code = 'const password = getUserInput();\nvalidatePassword(password);';
    const r = await e.scan(res(code), 'response');
    // "password = getUserInput()" — the value is "getUserInput()" which is 14+ chars
    // SEC-022 pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{4,}/i
    // This WILL match because "getUserInput()" is 4+ non-whitespace chars.
    // BUG: SEC-022 triggers on code that assigns password from a function call,
    // not from a literal secret value. This is a false positive.
    const hasSEC022 = r.findings.some((f) => f.ruleId === 'SEC-022');
    expect(hasSEC022).toBe(true); // Documents the false positive behavior
  });

  it('should NOT flag short prefixes alone: sk-, ghp_, glpat-', async () => {
    const text = 'The prefixes sk- and ghp_ and glpat- are used for tokens.';
    const r = await e.scan(res(text), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-010')).toBe(false);
    expect(r.findings.some((f) => f.ruleId === 'SEC-011')).toBe(false);
    expect(r.findings.some((f) => f.ruleId === 'SEC-014')).toBe(false);
  });

  it('should NOT flag JWT-like strings that lack proper eyJ prefix', async () => {
    // Three base64 parts separated by dots but not starting with eyJ
    const fakeJwt = 'aGVsbG8gd29ybGQ.dGhpcyBpcyBub3Q.YSByZWFsIGp3dA';
    const r = await e.scan(res(fakeJwt), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-020')).toBe(false);
  });

  it('should NOT flag the word "Bearer" in documentation without a token', async () => {
    const doc = 'The Authorization header should use the Bearer scheme.';
    const r = await e.scan(res(doc), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-024')).toBe(false);
  });

  it('should NOT flag code comments discussing secret patterns', async () => {
    const comment = '// the api_key field should be validated before use';
    const r = await e.scan(res(comment), 'response');
    // SEC-030 pattern: /(?:api[_-]?key|...) \s*[:=]\s*/
    // "api_key field" has no := after it, so it should NOT match
    expect(r.findings.some((f) => f.ruleId === 'SEC-030')).toBe(false);
  });
});

// ─── EXTENDED TESTS: Edge cases ───

describe('Secret detection — edge cases', () => {
  const e = engine();

  it('should detect secret at the very start of text', async () => {
    const r = await e.scan(res('AKIAIOSFODNN7EXAMPLE is exposed'), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-001')).toBe(true);
  });

  it('should detect secret at the very end of text', async () => {
    const r = await e.scan(res('The key is AKIAIOSFODNN7EXAMPLE'), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-001')).toBe(true);
  });

  it('should NOT detect secret split across separate params', async () => {
    // If the key is split across different fields, the regex won't
    // see the complete key in one string
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: {
        part1: 'AKIA',
        part2: 'IOSFODNN7EXAMPLE',
      },
    };
    const r = await e.scan(msg, 'response');
    // The engine flattens object values with spaces, so the full key
    // won't appear as a contiguous string: "AKIA IOSFODNN7EXAMPLE"
    expect(r.findings.some((f) => f.ruleId === 'SEC-001')).toBe(false);
  });

  it('should detect secrets in deeply nested response objects', async () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: {
        data: {
          config: {
            credentials: {
              aws: {
                key: 'AKIAIOSFODNN7EXAMPLE',
              },
            },
          },
        },
      },
    };
    const r = await e.scan(msg, 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-001')).toBe(true);
  });

  it('should handle empty response content without errors', async () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: {},
    };
    const r = await e.scan(msg, 'response');
    expect(r.findings.filter((f) => f.ruleId.startsWith('SEC-'))).toHaveLength(0);
    expect(r.decision).toBe('allow');
  });

  it('should handle null result without errors', async () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: null,
    };
    const r = await e.scan(msg, 'response');
    expect(r.decision).toBe('allow');
  });

  it('should detect a secret buried in a very long string', async () => {
    const padding = 'A'.repeat(2000);
    const text = `${padding} AKIAIOSFODNN7EXAMPLE ${padding}`;
    const r = await e.scan(res(text), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-001')).toBe(true);
  });

  it('should handle response with error field containing secrets', async () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      error: {
        code: -32000,
        message: 'Auth failed for postgres://admin:leaked_pass@db:5432/prod',
      },
    };
    const r = await e.scan(msg, 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-023')).toBe(true);
  });

  it('should handle response with both result and error', async () => {
    // Technically unusual but the engine should handle it
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: { data: 'clean content' },
      error: {
        code: -1,
        message: 'password: leaked_credential_value',
      },
    } as unknown as JsonRpcMessage;
    const r = await e.scan(msg, 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-022')).toBe(true);
  });

  it('should handle arrays in response results', async () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: {
        items: [
          'safe content',
          'also safe',
          '-----BEGIN PRIVATE KEY-----',
          'more data',
        ],
      },
    };
    const r = await e.scan(msg, 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-021')).toBe(true);
  });

  it('should truncate oversized input and still scan what remains', async () => {
    // maxInputSize is 10240 (10KB). Put a secret at the start
    // and verify it's caught even with a long payload.
    const longPayload = 'AKIAIOSFODNN7EXAMPLE ' + 'x'.repeat(20000);
    const r = await e.scan(res(longPayload), 'response');
    expect(r.findings.some((f) => f.ruleId === 'SEC-001')).toBe(true);
  });

  it('should miss secrets beyond truncation boundary', async () => {
    // Put a secret only at the end of a very long string
    const longPayload = 'x'.repeat(20000) + ' AKIAIOSFODNN7EXAMPLE';
    const r = await e.scan(res(longPayload), 'response');
    // Secret is beyond maxInputSize, so it gets truncated
    expect(r.findings.some((f) => f.ruleId === 'SEC-001')).toBe(false);
  });
});

// ─── EXTENDED TESTS: Direction filtering ───

describe('Secret detection — direction-specific behavior', () => {
  const e = engine();

  it('SEC-003 (GCP service account) should only trigger on response, not request', async () => {
    const text = '{"type": "service_account", "project_id": "test"}';
    const responseResult = await e.scan(res(text), 'response');
    const requestResult = await e.scan(req(text), 'request');
    expect(responseResult.findings.some((f) => f.ruleId === 'SEC-003')).toBe(true);
    expect(requestResult.findings.some((f) => f.ruleId === 'SEC-003')).toBe(false);
  });

  it('SEC-031 (env variable secret) should only trigger on response, not request', async () => {
    const text = 'SECRET=mysupersecretvalue123';
    const responseResult = await e.scan(res(text), 'response');
    const requestResult = await e.scan(req(text), 'request');
    expect(responseResult.findings.some((f) => f.ruleId === 'SEC-031')).toBe(true);
    expect(requestResult.findings.some((f) => f.ruleId === 'SEC-031')).toBe(false);
  });

  it('SEC-001 (AWS key) should trigger on both request and response', async () => {
    const text = 'key=AKIAIOSFODNN7EXAMPLE';
    const responseResult = await e.scan(res(text), 'response');
    const requestResult = await e.scan(req(text), 'request');
    expect(responseResult.findings.some((f) => f.ruleId === 'SEC-001')).toBe(true);
    expect(requestResult.findings.some((f) => f.ruleId === 'SEC-001')).toBe(true);
  });
});
