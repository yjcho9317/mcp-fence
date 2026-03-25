import { describe, it, expect, afterEach } from 'vitest';
import { evaluatePolicy } from '../../src/policy/local.js';
import { PolicyEngine } from '../../src/policy/engine.js';
import { loadConfig, generateDefaultConfigYaml } from '../../src/config.js';
import type { JsonRpcMessage, PolicyConfig } from '../../src/types.js';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

function toolsCall(name: string, args?: Record<string, unknown>): JsonRpcMessage {
  return {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name, arguments: args },
  };
}

// ─── evaluatePolicy ───

describe('evaluatePolicy — basic matching', () => {
  it('should allow by default when no rules match', () => {
    const config: PolicyConfig = { defaultAction: 'allow', rules: [] };
    const result = evaluatePolicy('read_file', undefined, config);
    expect(result.action).toBe('allow');
  });

  it('should deny by default when configured', () => {
    const config: PolicyConfig = { defaultAction: 'deny', rules: [] };
    const result = evaluatePolicy('read_file', undefined, config);
    expect(result.action).toBe('deny');
  });

  it('should match exact tool name — deny', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: 'exec_cmd', action: 'deny' }],
    };
    expect(evaluatePolicy('exec_cmd', undefined, config).action).toBe('deny');
    expect(evaluatePolicy('read_file', undefined, config).action).toBe('allow');
  });

  it('should match exact tool name — allow', () => {
    const config: PolicyConfig = {
      defaultAction: 'deny',
      rules: [{ tool: 'read_file', action: 'allow' }],
    };
    expect(evaluatePolicy('read_file', undefined, config).action).toBe('allow');
    expect(evaluatePolicy('write_file', undefined, config).action).toBe('deny');
  });
});

describe('evaluatePolicy — glob patterns', () => {
  it('should match wildcard pattern: write_*', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: 'write_*', action: 'deny' }],
    };
    expect(evaluatePolicy('write_file', undefined, config).action).toBe('deny');
    expect(evaluatePolicy('write_config', undefined, config).action).toBe('deny');
    expect(evaluatePolicy('read_file', undefined, config).action).toBe('allow');
  });

  it('should match single char wildcard: tool_?', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: 'tool_?', action: 'deny' }],
    };
    expect(evaluatePolicy('tool_a', undefined, config).action).toBe('deny');
    expect(evaluatePolicy('tool_ab', undefined, config).action).toBe('allow');
  });

  it('should match star-only pattern: *', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: '*', action: 'deny' }],
    };
    expect(evaluatePolicy('anything', undefined, config).action).toBe('deny');
  });

  it('first matching rule wins', () => {
    const config: PolicyConfig = {
      defaultAction: 'deny',
      rules: [
        { tool: 'read_file', action: 'allow' },
        { tool: 'read_*', action: 'deny' },
      ],
    };
    // Exact match first
    expect(evaluatePolicy('read_file', undefined, config).action).toBe('allow');
    // Glob match second
    expect(evaluatePolicy('read_dir', undefined, config).action).toBe('deny');
  });
});

describe('evaluatePolicy — argument constraints', () => {
  it('should deny when denyPattern matches', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'read_file',
          action: 'allow',
          args: [{ name: 'path', denyPattern: '^/etc/' }],
        },
      ],
    };
    expect(evaluatePolicy('read_file', { path: '/etc/passwd' }, config).action).toBe('deny');
    expect(evaluatePolicy('read_file', { path: '/home/user/file.txt' }, config).action).toBe('allow');
  });

  it('should deny when allowPattern does not match', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'read_file',
          action: 'allow',
          args: [{ name: 'path', allowPattern: '^\\./' }],
        },
      ],
    };
    expect(evaluatePolicy('read_file', { path: './local.txt' }, config).action).toBe('allow');
    expect(evaluatePolicy('read_file', { path: '/etc/passwd' }, config).action).toBe('deny');
  });

  it('should allow when args are missing (no constraint check)', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'read_file',
          action: 'allow',
          args: [{ name: 'path', denyPattern: '/etc/' }],
        },
      ],
    };
    expect(evaluatePolicy('read_file', undefined, config).action).toBe('allow');
  });

  it('should allow when constrained arg is not present', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'read_file',
          action: 'allow',
          args: [{ name: 'path', denyPattern: '/etc/' }],
        },
      ],
    };
    expect(evaluatePolicy('read_file', { other: 'value' }, config).action).toBe('allow');
  });

  it('should handle multiple arg constraints', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'write_file',
          action: 'allow',
          args: [
            { name: 'path', denyPattern: '^\\.env$' },
            { name: 'content', denyPattern: 'password' },
          ],
        },
      ],
    };
    expect(evaluatePolicy('write_file', { path: '.env', content: 'safe' }, config).action).toBe('deny');
    expect(evaluatePolicy('write_file', { path: 'ok.txt', content: 'has password in it' }, config).action).toBe('deny');
    expect(evaluatePolicy('write_file', { path: 'ok.txt', content: 'safe content' }, config).action).toBe('allow');
  });

  it('should handle invalid regex in denyPattern gracefully', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'test',
          action: 'allow',
          args: [{ name: 'x', denyPattern: '[invalid' }],
        },
      ],
    };
    // Invalid regex should not crash — just skip the check
    expect(evaluatePolicy('test', { x: 'value' }, config).action).toBe('allow');
  });
});

// ─── PolicyEngine ───

describe('PolicyEngine', () => {
  it('should return no findings for allowed tools', () => {
    const engine = new PolicyEngine({
      defaultAction: 'allow',
      rules: [{ tool: 'exec_cmd', action: 'deny' }],
    });

    const msg = toolsCall('read_file');
    expect(engine.evaluate(msg)).toHaveLength(0);
  });

  it('should return finding for denied tools', () => {
    const engine = new PolicyEngine({
      defaultAction: 'allow',
      rules: [{ tool: 'exec_cmd', action: 'deny' }],
    });

    const findings = engine.evaluate(toolsCall('exec_cmd'));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('POL-001');
    expect(findings[0]!.category).toBe('policy-violation');
    expect(findings[0]!.confidence).toBe(1.0);
  });

  it('should ignore non-tools/call messages', () => {
    const engine = new PolicyEngine({
      defaultAction: 'deny',
      rules: [],
    });

    const listMsg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
    };
    expect(engine.evaluate(listMsg)).toHaveLength(0);

    const notification: JsonRpcMessage = {
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    };
    expect(engine.evaluate(notification)).toHaveLength(0);

    const response: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [] },
    };
    expect(engine.evaluate(response)).toHaveLength(0);
  });

  it('should include tool name and matched rule in metadata', () => {
    const engine = new PolicyEngine({
      defaultAction: 'allow',
      rules: [{ tool: 'danger_*', action: 'deny' }],
    });

    const findings = engine.evaluate(toolsCall('danger_cmd'));
    expect(findings[0]!.metadata?.['toolName']).toBe('danger_cmd');
    expect(findings[0]!.metadata?.['matchedRule']).toBe('danger_*');
  });

  it('should check argument constraints via engine', () => {
    const engine = new PolicyEngine({
      defaultAction: 'allow',
      rules: [
        {
          tool: 'read_file',
          action: 'allow',
          args: [{ name: 'path', denyPattern: '/etc/' }],
        },
      ],
    });

    expect(engine.evaluate(toolsCall('read_file', { path: '/etc/shadow' }))).toHaveLength(1);
    expect(engine.evaluate(toolsCall('read_file', { path: './readme.md' }))).toHaveLength(0);
  });
});

// ─── Edge cases ───

describe('Policy edge cases', () => {
  it('should handle tools/call with missing params.name', () => {
    const engine = new PolicyEngine({ defaultAction: 'deny', rules: [] });
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {},
    };
    expect(engine.evaluate(msg)).toHaveLength(0); // Can't extract tool name
  });

  it('should handle tools/call with numeric name', () => {
    const engine = new PolicyEngine({ defaultAction: 'deny', rules: [] });
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 123 },
    };
    expect(engine.evaluate(msg)).toHaveLength(0); // Non-string name ignored
  });

  it('should handle empty rules with default-deny', () => {
    const engine = new PolicyEngine({ defaultAction: 'deny', rules: [] });
    const findings = engine.evaluate(toolsCall('any_tool'));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('default: deny');
  });
});

// ─── evaluatePolicy — rule ordering ───

describe('evaluatePolicy — rule ordering', () => {
  it('first match wins even if later rule is more specific', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        { tool: 'read_*', action: 'allow' },
        { tool: 'read_secret', action: 'deny' },
      ],
    };
    // The glob rule matches first, so the more specific deny never fires
    const result = evaluatePolicy('read_secret', undefined, config);
    expect(result.action).toBe('allow');
    expect(result.rule?.tool).toBe('read_*');
  });

  it('10+ rules: verify linear scan order', () => {
    const rules = Array.from({ length: 12 }, (_, i) => ({
      tool: `tool_${i}`,
      action: (i % 2 === 0 ? 'allow' : 'deny') as 'allow' | 'deny',
    }));
    const config: PolicyConfig = { defaultAction: 'allow', rules };

    // Each tool matches its exact rule at the correct index
    for (let i = 0; i < 12; i++) {
      const result = evaluatePolicy(`tool_${i}`, undefined, config);
      expect(result.action).toBe(i % 2 === 0 ? 'allow' : 'deny');
      expect(result.rule?.tool).toBe(`tool_${i}`);
    }
  });

  it('duplicate rules for same tool: first one wins', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        { tool: 'exec_cmd', action: 'allow' },
        { tool: 'exec_cmd', action: 'deny' },
      ],
    };
    const result = evaluatePolicy('exec_cmd', undefined, config);
    expect(result.action).toBe('allow');
  });

  it('contradicting rules: allow then deny for same tool', () => {
    const config: PolicyConfig = {
      defaultAction: 'deny',
      rules: [
        { tool: 'danger', action: 'allow' },
        { tool: 'danger', action: 'deny' },
      ],
    };
    expect(evaluatePolicy('danger', undefined, config).action).toBe('allow');
  });
});

// ─── evaluatePolicy — glob edge cases ───

describe('evaluatePolicy — glob edge cases', () => {
  it('pattern with multiple wildcards: *_file_*', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: '*_file_*', action: 'deny' }],
    };
    expect(evaluatePolicy('read_file_sync', undefined, config).action).toBe('deny');
    expect(evaluatePolicy('write_file_async', undefined, config).action).toBe('deny');
    expect(evaluatePolicy('read_dir', undefined, config).action).toBe('allow');
  });

  it('pattern that is just * matches everything', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: '*', action: 'deny' }],
    };
    expect(evaluatePolicy('', undefined, config).action).toBe('deny');
    expect(evaluatePolicy('anything_at_all', undefined, config).action).toBe('deny');
    expect(evaluatePolicy('a.b.c', undefined, config).action).toBe('deny');
  });

  it('tool name with dots: my.namespace.tool', () => {
    // Dots are regex-special — globToRegex must escape them
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: 'my.namespace.tool', action: 'deny' }],
    };
    expect(evaluatePolicy('my.namespace.tool', undefined, config).action).toBe('deny');
    // A dot in the pattern should NOT match arbitrary char
    expect(evaluatePolicy('myXnamespaceXtool', undefined, config).action).toBe('allow');
  });

  it('tool name with special regex chars: tool.name', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: 'tool.name', action: 'deny' }],
    };
    expect(evaluatePolicy('tool.name', undefined, config).action).toBe('deny');
    expect(evaluatePolicy('toolXname', undefined, config).action).toBe('allow');
  });

  it('tool name with parentheses: tool(1)', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: 'tool(1)', action: 'deny' }],
    };
    expect(evaluatePolicy('tool(1)', undefined, config).action).toBe('deny');
  });

  it('tool name with brackets: tool[0]', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: 'tool[0]', action: 'deny' }],
    };
    expect(evaluatePolicy('tool[0]', undefined, config).action).toBe('deny');
  });

  it('empty tool name', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: 'exec_cmd', action: 'deny' }],
    };
    const result = evaluatePolicy('', undefined, config);
    expect(result.action).toBe('allow');
  });

  it('empty pattern in rule', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: '', action: 'deny' }],
    };
    // Empty pattern should match only empty tool name (exact match)
    expect(evaluatePolicy('', undefined, config).action).toBe('deny');
    expect(evaluatePolicy('something', undefined, config).action).toBe('allow');
  });

  it('pattern with no wildcard that does not match (exact miss)', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: 'specific_tool', action: 'deny' }],
    };
    expect(evaluatePolicy('other_tool', undefined, config).action).toBe('allow');
    expect(evaluatePolicy('specific_tool_extra', undefined, config).action).toBe('allow');
    expect(evaluatePolicy('specific_too', undefined, config).action).toBe('allow');
  });
});

// ─── evaluatePolicy — argument validation depth ───

describe('evaluatePolicy — argument validation depth', () => {
  it('denyPattern + allowPattern on same argument (both checked)', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'tool',
          action: 'allow',
          args: [{ name: 'x', denyPattern: 'bad', allowPattern: '^good' }],
        },
      ],
    };
    // "bad" matches denyPattern -> deny
    expect(evaluatePolicy('tool', { x: 'bad' }, config).action).toBe('deny');
    // "hello" doesn't match denyPattern but doesn't match allowPattern -> deny
    expect(evaluatePolicy('tool', { x: 'hello' }, config).action).toBe('deny');
    // "good_value" passes both checks
    expect(evaluatePolicy('tool', { x: 'good_value' }, config).action).toBe('allow');
    // "goodbad" matches denyPattern -> deny (denyPattern checked first)
    expect(evaluatePolicy('tool', { x: 'goodbad' }, config).action).toBe('deny');
  });

  it('argument value is a number (converted to string)', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'tool',
          action: 'allow',
          args: [{ name: 'count', denyPattern: '^0$' }],
        },
      ],
    };
    expect(evaluatePolicy('tool', { count: 0 }, config).action).toBe('deny');
    expect(evaluatePolicy('tool', { count: 42 }, config).action).toBe('allow');
  });

  it('argument value is boolean', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'tool',
          action: 'allow',
          args: [{ name: 'flag', denyPattern: '^true$' }],
        },
      ],
    };
    expect(evaluatePolicy('tool', { flag: true }, config).action).toBe('deny');
    expect(evaluatePolicy('tool', { flag: false }, config).action).toBe('allow');
  });

  it('argument value is null — constraint is skipped', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'tool',
          action: 'allow',
          args: [{ name: 'x', denyPattern: '.*' }],
        },
      ],
    };
    // null value causes checkArgConstraint to return null (skip)
    expect(evaluatePolicy('tool', { x: null }, config).action).toBe('allow');
  });

  it('argument value is undefined — constraint is skipped', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'tool',
          action: 'allow',
          args: [{ name: 'x', denyPattern: '.*' }],
        },
      ],
    };
    expect(evaluatePolicy('tool', { x: undefined }, config).action).toBe('allow');
  });

  it('argument value is an object (converted via JSON.stringify)', () => {
    // Objects are now serialized via JSON.stringify instead of String().
    // JSON.stringify({nested:true}) = '{"nested":true}', which does NOT
    // match the old \\[object pattern. Use a pattern that matches JSON output.
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'tool',
          action: 'allow',
          args: [{ name: 'data', denyPattern: 'nested' }],
        },
      ],
    };
    expect(evaluatePolicy('tool', { data: { nested: true } }, config).action).toBe('deny');
  });

  it('argument value is an array (converted to string)', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'tool',
          action: 'allow',
          args: [{ name: 'items', denyPattern: 'secret' }],
        },
      ],
    };
    // Array.toString() produces comma-separated values
    expect(evaluatePolicy('tool', { items: ['a', 'secret', 'b'] }, config).action).toBe('deny');
    expect(evaluatePolicy('tool', { items: ['a', 'b'] }, config).action).toBe('allow');
  });

  it('denyPattern that matches empty string', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'tool',
          action: 'allow',
          args: [{ name: 'x', denyPattern: '^$' }],
        },
      ],
    };
    expect(evaluatePolicy('tool', { x: '' }, config).action).toBe('deny');
    expect(evaluatePolicy('tool', { x: 'notempty' }, config).action).toBe('allow');
  });

  it('allowPattern that matches empty string', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'tool',
          action: 'allow',
          args: [{ name: 'x', allowPattern: '^$' }],
        },
      ],
    };
    expect(evaluatePolicy('tool', { x: '' }, config).action).toBe('allow');
    expect(evaluatePolicy('tool', { x: 'notempty' }, config).action).toBe('deny');
  });

  it('very long argument value (10KB+)', () => {
    const longValue = 'a'.repeat(10 * 1024) + 'EVIL';
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'tool',
          action: 'allow',
          args: [{ name: 'payload', denyPattern: 'EVIL' }],
        },
      ],
    };
    expect(evaluatePolicy('tool', { payload: longValue }, config).action).toBe('deny');
  });

  it('argument name with special characters', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'tool',
          action: 'allow',
          args: [{ name: 'my.arg[0]', denyPattern: 'bad' }],
        },
      ],
    };
    // The constraint.name is used as a key lookup on the args object
    expect(evaluatePolicy('tool', { 'my.arg[0]': 'bad_value' }, config).action).toBe('deny');
    expect(evaluatePolicy('tool', { 'my.arg[0]': 'ok' }, config).action).toBe('allow');
  });

  it('multiple constraints where first passes but second fails', () => {
    const config: PolicyConfig = {
      defaultAction: 'allow',
      rules: [
        {
          tool: 'tool',
          action: 'allow',
          args: [
            { name: 'a', denyPattern: 'bad' },
            { name: 'b', allowPattern: '^safe' },
          ],
        },
      ],
    };
    // a is fine, but b fails allowPattern
    expect(evaluatePolicy('tool', { a: 'ok', b: 'unsafe' }, config).action).toBe('deny');
    // Both pass
    expect(evaluatePolicy('tool', { a: 'ok', b: 'safe_data' }, config).action).toBe('allow');
  });
});

// ─── Config validation (zod schema) ───

describe('Config validation — policy rules via YAML', () => {
  let tmpDir: string;

  function writeConfigAndLoad(yamlContent: string) {
    tmpDir = mkdtempSync(join(tmpdir(), 'mcp-fence-test-'));
    const configPath = join(tmpDir, 'fence.config.yaml');
    writeFileSync(configPath, yamlContent, 'utf-8');
    return loadConfig(configPath);
  }

  afterEach(() => {
    if (tmpDir) {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('load config with policy rules from YAML string', () => {
    const yaml = `
mode: enforce
policy:
  defaultAction: deny
  rules:
    - tool: read_file
      action: allow
    - tool: exec_*
      action: deny
`;
    const config = writeConfigAndLoad(yaml);
    expect(config.policy.defaultAction).toBe('deny');
    expect(config.policy.rules).toHaveLength(2);
    expect(config.policy.rules[0]!.tool).toBe('read_file');
    expect(config.policy.rules[0]!.action).toBe('allow');
    expect(config.policy.rules[1]!.tool).toBe('exec_*');
    expect(config.policy.rules[1]!.action).toBe('deny');
  });

  it('invalid rule action (not allow/deny) throws ConfigError', () => {
    const yaml = `
policy:
  rules:
    - tool: bad_tool
      action: maybe
`;
    expect(() => writeConfigAndLoad(yaml)).toThrow();
  });

  it('missing tool field in rule throws ConfigError', () => {
    const yaml = `
policy:
  rules:
    - action: deny
`;
    expect(() => writeConfigAndLoad(yaml)).toThrow();
  });

  it('empty rules array is valid', () => {
    const yaml = `
policy:
  defaultAction: deny
  rules: []
`;
    const config = writeConfigAndLoad(yaml);
    expect(config.policy.rules).toHaveLength(0);
    expect(config.policy.defaultAction).toBe('deny');
  });

  it('policy with only defaultAction set uses empty rules', () => {
    const yaml = `
policy:
  defaultAction: deny
`;
    const config = writeConfigAndLoad(yaml);
    expect(config.policy.defaultAction).toBe('deny');
    expect(config.policy.rules).toHaveLength(0);
  });

  it('invalid defaultAction value throws ConfigError', () => {
    const yaml = `
policy:
  defaultAction: maybe
  rules: []
`;
    expect(() => writeConfigAndLoad(yaml)).toThrow();
  });
});

// ─── PolicyEngine — proxy integration logic ───

describe('PolicyEngine — proxy integration logic', () => {
  it('tools/call with params as array (not object)', () => {
    const engine = new PolicyEngine({ defaultAction: 'deny', rules: [] });
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: ['read_file', { path: '/etc/passwd' }],
    };
    // extractToolCall casts params to Record<string, unknown>,
    // then looks for params['name']. Array has no 'name' key.
    // BUG: When params is an array, extractToolCall does not handle it
    // and silently fails to extract tool info. This means array-form
    // params bypass policy entirely.
    expect(engine.evaluate(msg)).toHaveLength(0);
  });

  it('tools/call where params.arguments is a string (not object)', () => {
    const engine = new PolicyEngine({
      defaultAction: 'allow',
      rules: [
        {
          tool: 'read_file',
          action: 'allow',
          args: [{ name: 'path', denyPattern: '/etc/' }],
        },
      ],
    });
    // arguments is a string, not Record<string, unknown>
    // checkArgs receives it, but it's cast, so args['path'] is undefined
    const msg = toolsCall('read_file');
    (msg as any).params.arguments = '/etc/passwd';
    const findings = engine.evaluate(msg);
    // String arguments won't have keys, so constraint check is skipped
    expect(findings).toHaveLength(0);
  });

  it('tools/call where params.arguments is missing entirely', () => {
    const engine = new PolicyEngine({
      defaultAction: 'allow',
      rules: [
        {
          tool: 'read_file',
          action: 'allow',
          args: [{ name: 'path', denyPattern: '/etc/' }],
        },
      ],
    });
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'read_file' },
    };
    // args is undefined, checkArgs returns null
    expect(engine.evaluate(msg)).toHaveLength(0);
  });

  it('message with method "tools/call" but no params at all', () => {
    const engine = new PolicyEngine({ defaultAction: 'deny', rules: [] });
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
    };
    // extractToolCall returns null because params is missing
    expect(engine.evaluate(msg)).toHaveLength(0);
  });

  it('findings have correct severity, category, confidence values', () => {
    const engine = new PolicyEngine({
      defaultAction: 'allow',
      rules: [{ tool: 'bad_tool', action: 'deny' }],
    });
    const findings = engine.evaluate(toolsCall('bad_tool'));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('high');
    expect(findings[0]!.category).toBe('policy-violation');
    expect(findings[0]!.confidence).toBe(1.0);
    expect(findings[0]!.ruleId).toBe('POL-001');
  });

  it('metadata includes toolName and matchedRule', () => {
    const engine = new PolicyEngine({
      defaultAction: 'allow',
      rules: [{ tool: 'write_*', action: 'deny' }],
    });
    const findings = engine.evaluate(toolsCall('write_config'));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.metadata).toBeDefined();
    expect(findings[0]!.metadata!['toolName']).toBe('write_config');
    expect(findings[0]!.metadata!['matchedRule']).toBe('write_*');
  });

  it('metadata matchedRule is undefined when denied by default action', () => {
    const engine = new PolicyEngine({ defaultAction: 'deny', rules: [] });
    const findings = engine.evaluate(toolsCall('anything'));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.metadata!['matchedRule']).toBeUndefined();
  });
});

// ─── Config round-trip ───

describe('Config round-trip', () => {
  it('create config with policy rules -> loadConfig -> verify rules preserved', () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'mcp-fence-roundtrip-'));
    const configPath = join(tmpDir, 'fence.config.yaml');
    const yaml = `
mode: enforce
policy:
  defaultAction: deny
  rules:
    - tool: read_file
      action: allow
      args:
        - name: path
          denyPattern: "^/etc/"
          allowPattern: "^\\\\./"
    - tool: write_*
      action: deny
`;
    writeFileSync(configPath, yaml, 'utf-8');
    const config = loadConfig(configPath);

    expect(config.mode).toBe('enforce');
    expect(config.policy.defaultAction).toBe('deny');
    expect(config.policy.rules).toHaveLength(2);

    const rule0 = config.policy.rules[0]!;
    expect(rule0.tool).toBe('read_file');
    expect(rule0.action).toBe('allow');
    expect(rule0.args).toHaveLength(1);
    expect(rule0.args![0]!.name).toBe('path');
    expect(rule0.args![0]!.denyPattern).toBe('^/etc/');
    expect(rule0.args![0]!.allowPattern).toBe('^\\./');

    const rule1 = config.policy.rules[1]!;
    expect(rule1.tool).toBe('write_*');
    expect(rule1.action).toBe('deny');

    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('generateDefaultConfigYaml includes policy section', () => {
    const yaml = generateDefaultConfigYaml();
    expect(yaml).toContain('policy:');
    expect(yaml).toContain('defaultAction:');
    expect(yaml).toContain('rules:');
  });
});
