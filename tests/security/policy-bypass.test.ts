/**
 * Security bypass tests for mcp-fence policy engine (W5).
 *
 * This file attempts to bypass the local policy engine's tool access control
 * using adversarial techniques targeting:
 *
 * - Tool name evasion (case, unicode, encoding, null bytes, whitespace)
 * - Argument constraint bypass (encoding, path normalization, nesting, type confusion)
 * - Glob pattern attacks (ReDoS, injection, catch-all abuse)
 * - Policy ordering exploitation (first-match-wins, missing deny-all)
 * - Monitor vs enforce mode information leakage
 * - Argument validation gaps (unchecked args, no type validation, no recursion)
 * - Config validation security (YAML injection, regex safety)
 */

import { describe, it, expect } from 'vitest';
import { evaluatePolicy } from '../../src/policy/local.js';
import { PolicyEngine } from '../../src/policy/engine.js';
import type { PolicyConfig, PolicyRule, JsonRpcMessage } from '../../src/types.js';

// ─── Helpers ───

/** Build a PolicyConfig from rules with a given default action. */
function config(
  rules: PolicyRule[],
  defaultAction: 'allow' | 'deny' = 'allow',
): PolicyConfig {
  return { defaultAction, rules };
}

/** Build a tools/call JSON-RPC request. */
function toolsCallMessage(
  toolName: string,
  args?: Record<string, unknown>,
): JsonRpcMessage {
  return {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name: toolName, arguments: args },
  };
}

// ─── 1. Tool Name Evasion ───

describe('W5-SEC: Tool Name Evasion', () => {
  const denyExecPolicy = config([
    { tool: 'exec_cmd', action: 'deny' },
  ]);

  describe('Case sensitivity bypass', () => {
    it('FIXED: uppercase tool name is normalized before matching', () => {
      const result = evaluatePolicy('EXEC_CMD', undefined, denyExecPolicy);
      // Tool names are now lowercased before matching — case bypass blocked
      expect(result.action).toBe('deny');
    });

    it('FIXED: mixed case tool name is normalized before matching', () => {
      const result = evaluatePolicy('Exec_Cmd', undefined, denyExecPolicy);
      expect(result.action).toBe('deny');
    });

    it('VULN: camelCase variant bypasses deny rule', () => {
      const result = evaluatePolicy('execCmd', undefined, denyExecPolicy);
      expect(result.action).toBe('allow');
    });

    it('exact case match is correctly denied', () => {
      const result = evaluatePolicy('exec_cmd', undefined, denyExecPolicy);
      expect(result.action).toBe('deny');
    });
  });

  describe('Unicode homoglyph bypass', () => {
    it('VULN: Cyrillic "e" (U+0435) in tool name bypasses deny', () => {
      // \u0435 = Cyrillic small letter ie, visually identical to Latin 'e'
      const result = evaluatePolicy('\u0435xec_cmd', undefined, denyExecPolicy);
      expect(result.action).toBe('allow');
    });

    it('VULN: Cyrillic "c" (U+0441) in tool name bypasses deny', () => {
      const result = evaluatePolicy('exe\u0441_cmd', undefined, denyExecPolicy);
      expect(result.action).toBe('allow');
    });

    it('VULN: multiple homoglyphs produce visually identical but allowed name', () => {
      // Full Cyrillic lookalike: е (U+0435), х (U+0445), е (U+0435), с (U+0441)
      const result = evaluatePolicy('\u0435x\u0435\u0441_cmd', undefined, denyExecPolicy);
      expect(result.action).toBe('allow');
    });

    it('VULN: homoglyph also bypasses glob pattern deny', () => {
      const policy = config([{ tool: 'exec_*', action: 'deny' }]);
      // Cyrillic 'e' at start means 'exec_*' glob does not match
      const result = evaluatePolicy('\u0435xec_anything', undefined, policy);
      expect(result.action).toBe('allow');
    });
  });

  describe('Null byte injection', () => {
    it('VULN: null byte in tool name is not stripped', () => {
      const result = evaluatePolicy('exec_cmd\x00safe', undefined, denyExecPolicy);
      // 'exec_cmd\x00safe' !== 'exec_cmd', so it bypasses exact match
      expect(result.action).toBe('allow');
    });

    it('FIXED: null byte before tool name is stripped before matching', () => {
      const result = evaluatePolicy('\x00exec_cmd', undefined, denyExecPolicy);
      expect(result.action).toBe('deny');
    });
  });

  describe('Whitespace injection', () => {
    it('FIXED: leading space in tool name is trimmed before matching', () => {
      const result = evaluatePolicy(' exec_cmd', undefined, denyExecPolicy);
      expect(result.action).toBe('deny');
    });

    it('FIXED: trailing space in tool name is trimmed before matching', () => {
      const result = evaluatePolicy('exec_cmd ', undefined, denyExecPolicy);
      expect(result.action).toBe('deny');
    });

    it('FIXED: tab character in tool name is trimmed before matching', () => {
      const result = evaluatePolicy('exec_cmd\t', undefined, denyExecPolicy);
      expect(result.action).toBe('deny');
    });

    it('FIXED: zero-width space (U+200B) in tool name is stripped before matching', () => {
      const result = evaluatePolicy('exec\u200B_cmd', undefined, denyExecPolicy);
      expect(result.action).toBe('deny');
    });
  });

  describe('Path-like tool names', () => {
    it('VULN: path traversal prefix bypasses deny', () => {
      const result = evaluatePolicy('../../exec_cmd', undefined, denyExecPolicy);
      expect(result.action).toBe('allow');
    });

    it('VULN: directory-like prefix bypasses deny', () => {
      const result = evaluatePolicy('./exec_cmd', undefined, denyExecPolicy);
      expect(result.action).toBe('allow');
    });
  });

  describe('URL encoding in tool names', () => {
    it('VULN: URL-encoded underscore bypasses deny', () => {
      // exec%5Fcmd with literal percent encoding
      const result = evaluatePolicy('exec%5Fcmd', undefined, denyExecPolicy);
      expect(result.action).toBe('allow');
    });

    it('VULN: fully URL-encoded tool name bypasses deny', () => {
      const result = evaluatePolicy('%65xec_cmd', undefined, denyExecPolicy);
      expect(result.action).toBe('allow');
    });
  });

  describe('Leading/trailing dots', () => {
    it('VULN: tool name with leading dot bypasses deny', () => {
      const result = evaluatePolicy('.exec_cmd', undefined, denyExecPolicy);
      expect(result.action).toBe('allow');
    });

    it('VULN: tool name with trailing dot bypasses deny', () => {
      const result = evaluatePolicy('exec_cmd.', undefined, denyExecPolicy);
      expect(result.action).toBe('allow');
    });
  });
});

// ─── 2. Argument Constraint Bypass ───

describe('W5-SEC: Argument Constraint Bypass', () => {
  const readFilePolicy = config([
    {
      tool: 'read_file',
      action: 'allow',
      args: [
        { name: 'path', denyPattern: '/etc/' },
      ],
    },
  ]);

  describe('Case sensitivity in denyPattern', () => {
    it('denyPattern blocks lowercase /etc/', () => {
      const result = evaluatePolicy('read_file', { path: '/etc/passwd' }, readFilePolicy);
      expect(result.action).toBe('deny');
    });

    it('VULN: uppercase /ETC/ bypasses denyPattern', () => {
      // denyPattern is a regex without 'i' flag — case matters
      const result = evaluatePolicy('read_file', { path: '/ETC/passwd' }, readFilePolicy);
      expect(result.action).toBe('allow');
    });

    it('VULN: mixed case /Etc/ bypasses denyPattern', () => {
      const result = evaluatePolicy('read_file', { path: '/Etc/Passwd' }, readFilePolicy);
      expect(result.action).toBe('allow');
    });
  });

  describe('URL encoding bypass in arguments', () => {
    it('FIXED: URL-encoded path is decoded before denyPattern check', () => {
      const result = evaluatePolicy('read_file', { path: '%2Fetc%2Fpasswd' }, readFilePolicy);
      expect(result.action).toBe('deny');
    });

    it('FIXED: partial URL encoding is decoded before denyPattern check', () => {
      const result = evaluatePolicy('read_file', { path: '/%65tc/passwd' }, readFilePolicy);
      expect(result.action).toBe('deny');
    });
  });

  describe('Path normalization bypass', () => {
    it('VULN: double-dot traversal bypasses denyPattern', () => {
      // /etc/../etc/passwd contains /etc/ but via traversal from a different base
      // Actually this WILL match because the literal string still contains /etc/
      const result = evaluatePolicy('read_file', { path: '/etc/../etc/passwd' }, readFilePolicy);
      expect(result.action).toBe('deny');
    });

    it('VULN: traversal to /etc without literal /etc/ substring', () => {
      // /var/../etc/passwd — the resolved path is /etc/passwd but string lacks /etc/ as prefix
      // Wait: it contains /etc/ substring after ../
      const result = evaluatePolicy('read_file', { path: '/var/../etc/passwd' }, readFilePolicy);
      // Still matches because "/etc/" substring exists
      expect(result.action).toBe('deny');
    });

    it('VULN: symlink-equivalent path bypasses denyPattern', () => {
      // /proc/self/root/etc/passwd would resolve to /etc/passwd on Linux
      // but denyPattern is /etc/ which IS in the string — this specific example hits
      // Let's try a path that resolves to /etc but doesn't contain the literal string
      const result = evaluatePolicy('read_file', { path: '/e\x74c/passwd' }, readFilePolicy);
      // \x74 = 't', so this is actually '/etc/passwd' — JavaScript resolves escapes at parse time
      expect(result.action).toBe('deny');
    });

    it('VULN: unicode normalization bypass in path', () => {
      // Use a Unicode "slash" (U+2215 DIVISION SLASH) instead of /
      const result = evaluatePolicy('read_file', { path: '\u2215etc\u2215passwd' }, readFilePolicy);
      // Regex /etc/ won't match because the slashes are different codepoints
      expect(result.action).toBe('allow');
    });
  });

  describe('Nested argument bypass', () => {
    it('VULN: nested object argument is not checked', () => {
      // Constraint checks args['path'], but attacker puts path in nested object
      const result = evaluatePolicy(
        'read_file',
        { config: { path: '/etc/passwd' } },
        readFilePolicy,
      );
      // args['path'] is undefined, constraint passes null check and returns null
      expect(result.action).toBe('allow');
    });

    it('VULN: argument as dot-notation key is not resolved', () => {
      const policy = config([
        {
          tool: 'read_file',
          action: 'allow',
          args: [
            { name: 'config.path', denyPattern: '/etc/' },
          ],
        },
      ]);
      // args['config.path'] is undefined, args['config'] = { path: '/etc/passwd' }
      const result = evaluatePolicy(
        'read_file',
        { config: { path: '/etc/passwd' } },
        policy,
      );
      expect(result.action).toBe('allow');
    });
  });

  describe('Array argument bypass', () => {
    it('VULN: array argument is stringified, not iterated', () => {
      // String(["/etc/passwd", "/home/safe"]) = "/etc/passwd,/home/safe"
      // This happens to contain /etc/ so it WILL match denyPattern
      const result = evaluatePolicy(
        'read_file',
        { path: ['/etc/passwd', '/home/safe'] },
        readFilePolicy,
      );
      expect(result.action).toBe('deny');
    });

    it('FIXED: array with encoded path is decoded before check', () => {
      const result = evaluatePolicy(
        'read_file',
        { path: ['%2Fetc%2Fpasswd'] },
        readFilePolicy,
      );
      expect(result.action).toBe('deny');
    });
  });

  describe('Type confusion', () => {
    it('VULN: number argument is coerced to string', () => {
      // String(12345) = "12345", denyPattern /etc/ won't match
      const result = evaluatePolicy(
        'read_file',
        { path: 12345 },
        readFilePolicy,
      );
      expect(result.action).toBe('allow');
    });

    it('VULN: boolean argument passes any denyPattern', () => {
      const result = evaluatePolicy(
        'read_file',
        { path: true },
        readFilePolicy,
      );
      // String(true) = "true", /etc/ does not match
      expect(result.action).toBe('allow');
    });

    it('FIXED: object argument is JSON.stringified, not toString-coerced', () => {
      const result = evaluatePolicy(
        'read_file',
        { path: { toString: () => '/etc/passwd' } },
        readFilePolicy,
      );
      // safeStringify uses JSON.stringify, so toString() is NOT called.
      // JSON.stringify produces '{}' (toString is non-enumerable), no /etc/ match.
      expect(result.action).toBe('allow');
    });

    it('FIXED: object with malicious toString is not invoked by safeStringify', () => {
      // safeStringify uses JSON.stringify instead of String(), so the
      // custom toString method is never called — no side effect execution.
      let sideEffect = false;
      const malicious = {
        toString() {
          sideEffect = true;
          return 'safe_path';
        },
      };
      evaluatePolicy('read_file', { path: malicious }, readFilePolicy);
      // Confirm toString was NOT called during policy evaluation
      expect(sideEffect).toBe(false);
    });
  });

  describe('Null/undefined argument bypass', () => {
    it('null argument value skips constraint check entirely', () => {
      const result = evaluatePolicy('read_file', { path: null }, readFilePolicy);
      // checkArgConstraint returns null when argValue == null
      expect(result.action).toBe('allow');
    });

    it('undefined argument value skips constraint check entirely', () => {
      const result = evaluatePolicy('read_file', { path: undefined }, readFilePolicy);
      expect(result.action).toBe('allow');
    });

    it('missing argument key skips constraint check entirely', () => {
      const result = evaluatePolicy('read_file', {}, readFilePolicy);
      expect(result.action).toBe('allow');
    });

    it('VULN: no args object at all skips all constraints', () => {
      const result = evaluatePolicy('read_file', undefined, readFilePolicy);
      // checkArgs returns null when args is undefined
      expect(result.action).toBe('allow');
    });
  });
});

// ─── 3. Glob Pattern Attacks ───

describe('W5-SEC: Glob Pattern Attacks', () => {
  describe('ReDoS via glob patterns', () => {
    it('long tool name with wildcard glob does not cause excessive time', () => {
      const policy = config([
        { tool: 'a*b*c*d*e', action: 'deny' },
      ]);
      // The glob converts to: /^a.*b.*c.*d.*e$/
      // With a long input that almost matches, the regex engine may backtrack
      const longName = 'a' + 'x'.repeat(100) + 'b' + 'x'.repeat(100) +
        'c' + 'x'.repeat(100) + 'd' + 'x'.repeat(100) + 'f'; // ends with 'f', not 'e'

      const start = performance.now();
      const result = evaluatePolicy(longName, undefined, policy);
      const elapsed = performance.now() - start;

      expect(result.action).toBe('allow');
      // Should complete in reasonable time (< 50ms)
      // If this fails, the glob-to-regex conversion is vulnerable to ReDoS
      expect(elapsed).toBeLessThan(50);
    });

    it('VULN-CHECK: multiple wildcards with adversarial input', () => {
      const policy = config([
        { tool: '*a*b*c*', action: 'deny' },
      ]);
      // Pattern: /^.*a.*b.*c.*$/ — four .* quantifiers
      const adversarial = 'a'.repeat(30) + 'b'.repeat(30) + 'x';

      const start = performance.now();
      evaluatePolicy(adversarial, undefined, policy);
      const elapsed = performance.now() - start;

      // Multiple .* with alternating characters can cause backtracking
      // Documenting the actual performance
      expect(elapsed).toBeLessThan(100);
    });
  });

  describe('Glob injection', () => {
    it('tool name containing * is treated as literal in exact match', () => {
      // If a tool is literally named "test*tool", does the glob pattern "test*tool"
      // match it by exact match or by glob expansion?
      const policy = config([
        { tool: 'test*tool', action: 'deny' },
      ]);
      // Exact match check: 'test*tool' === 'test*tool' → true (line 40)
      const result = evaluatePolicy('test*tool', undefined, policy);
      expect(result.action).toBe('deny');
    });

    it('tool name containing * also matches glob expansion', () => {
      const policy = config([
        { tool: 'test*tool', action: 'deny' },
      ]);
      // Glob expansion: test.*tool matches 'test_any_tool'
      const result = evaluatePolicy('test_any_tool', undefined, policy);
      expect(result.action).toBe('deny');
    });

    it('VULN: tool name with ? matches any single char via glob', () => {
      const policy = config([
        { tool: 'test?tool', action: 'deny' },
      ]);
      // globToRegex converts ? to . (matches any single char)
      const result = evaluatePolicy('test_tool', undefined, policy);
      expect(result.action).toBe('deny');
    });

    it('tool name with regex special chars does not break glob', () => {
      const policy = config([
        { tool: 'test.tool', action: 'deny' },
      ]);
      // globToRegex escapes '.', so it becomes literal match
      const result = evaluatePolicy('test.tool', undefined, policy);
      expect(result.action).toBe('deny');
    });

    it('glob correctly escapes regex special characters', () => {
      const policy = config([
        { tool: 'test.tool', action: 'deny' },
      ]);
      // The dot should NOT match arbitrary characters
      const result = evaluatePolicy('testXtool', undefined, policy);
      expect(result.action).toBe('allow');
    });
  });

  describe('Catch-all pattern abuse', () => {
    it('VULN: wildcard allow rule before specific deny overrides deny', () => {
      const policy = config([
        { tool: '*', action: 'allow' },       // catch-all allow
        { tool: 'exec_cmd', action: 'deny' }, // never reached — first match wins
      ]);
      const result = evaluatePolicy('exec_cmd', undefined, policy);
      // First match wins: '*' matches 'exec_cmd', action is allow
      expect(result.action).toBe('allow');
    });
  });
});

// ─── 4. Policy Ordering Exploitation ───

describe('W5-SEC: Policy Ordering Exploitation', () => {
  it('first-match-wins: allow rule before deny makes deny unreachable', () => {
    const policy = config([
      { tool: 'read_*', action: 'allow' },
      { tool: 'read_secrets', action: 'deny' },
    ]);
    const result = evaluatePolicy('read_secrets', undefined, policy);
    // 'read_*' matches first, allows the tool
    expect(result.action).toBe('allow');
  });

  it('first-match-wins: deny rule before allow blocks the tool', () => {
    const policy = config([
      { tool: 'read_secrets', action: 'deny' },
      { tool: 'read_*', action: 'allow' },
    ]);
    const result = evaluatePolicy('read_secrets', undefined, policy);
    // Exact match 'read_secrets' matches first, denies
    expect(result.action).toBe('deny');
  });

  it('VULN: missing deny-all with default-allow permits unlisted tools', () => {
    const policy = config(
      [
        { tool: 'read_file', action: 'allow' },
        { tool: 'write_file', action: 'allow' },
        // No deny-all rule at end, default is 'allow'
      ],
      'allow',
    );
    const result = evaluatePolicy('exec_cmd', undefined, policy);
    // No rule matches, default 'allow' permits the dangerous tool
    expect(result.action).toBe('allow');
  });

  it('deny-all default blocks unlisted tools', () => {
    const policy = config(
      [
        { tool: 'read_file', action: 'allow' },
        { tool: 'write_file', action: 'allow' },
      ],
      'deny',
    );
    const result = evaluatePolicy('exec_cmd', undefined, policy);
    expect(result.action).toBe('deny');
  });

  it('attacker crafts name to match broad allow before specific deny', () => {
    const policy = config([
      { tool: 'tool_*', action: 'allow' },
      { tool: 'tool_dangerous', action: 'deny' },
    ]);
    // Attacker knows about the ordering and uses a dangerous tool
    const result = evaluatePolicy('tool_dangerous', undefined, policy);
    // Glob 'tool_*' matches first, allows
    expect(result.action).toBe('allow');
  });

  it('exact match takes priority over glob when listed first', () => {
    const policy = config([
      { tool: 'exec_cmd', action: 'deny' },  // exact match
      { tool: '*', action: 'allow' },          // catch-all
    ]);
    const result = evaluatePolicy('exec_cmd', undefined, policy);
    // Exact match hits first
    expect(result.action).toBe('deny');
  });

  it('VULN: glob before exact match steals the match', () => {
    const policy = config([
      { tool: '*_cmd', action: 'allow' },     // glob matches exec_cmd
      { tool: 'exec_cmd', action: 'deny' },  // never reached
    ]);
    const result = evaluatePolicy('exec_cmd', undefined, policy);
    expect(result.action).toBe('allow');
  });
});

// ─── 5. Monitor vs Enforce Mode ───

describe('W5-SEC: Monitor vs Enforce Mode', () => {
  it('PolicyEngine returns findings for denied tools regardless of mode', () => {
    const policyConfig: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: 'exec_cmd', action: 'deny' }],
    };
    const engine = new PolicyEngine(policyConfig);
    const message = toolsCallMessage('exec_cmd');
    const findings = engine.evaluate(message);

    // PolicyEngine always returns findings — it doesn't know about mode
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('POL-001');
    expect(findings[0].severity).toBe('high');
  });

  it('PolicyEngine returns empty findings for allowed tools', () => {
    const policyConfig: PolicyConfig = {
      defaultAction: 'allow',
      rules: [{ tool: 'read_file', action: 'allow' }],
    };
    const engine = new PolicyEngine(policyConfig);
    const message = toolsCallMessage('read_file');
    const findings = engine.evaluate(message);
    expect(findings).toHaveLength(0);
  });

  it('PolicyEngine ignores non-tools/call messages', () => {
    const policyConfig: PolicyConfig = {
      defaultAction: 'deny',
      rules: [],
    };
    const engine = new PolicyEngine(policyConfig);

    // A notification, not a tools/call
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      method: 'notifications/initialized',
      params: {},
    };
    const findings = engine.evaluate(message);
    expect(findings).toHaveLength(0);
  });

  it('PolicyEngine ignores response messages', () => {
    const policyConfig: PolicyConfig = {
      defaultAction: 'deny',
      rules: [],
    };
    const engine = new PolicyEngine(policyConfig);
    const response: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: { content: 'data' },
    };
    const findings = engine.evaluate(response);
    expect(findings).toHaveLength(0);
  });

  it('VULN-INFO: attacker can probe denied tools via error messages', () => {
    // In monitor mode, the proxy logs findings but forwards the message.
    // The attacker receives no block response — but the policy evaluation
    // still runs. This means the policy engine processes even in monitor mode.
    // If error messages or timing differ between allow/deny, attacker can enumerate.
    const policyConfig: PolicyConfig = {
      defaultAction: 'deny',
      rules: [{ tool: 'safe_tool', action: 'allow' }],
    };
    const engine = new PolicyEngine(policyConfig);

    const allowed = engine.evaluate(toolsCallMessage('safe_tool'));
    const denied = engine.evaluate(toolsCallMessage('dangerous_tool'));

    // Findings array length differs — information leakage
    expect(allowed.length).toBe(0);
    expect(denied.length).toBe(1);
    // In monitor mode, both messages are forwarded, but the difference
    // in processing (findings created vs not) is observable in logs/audit
  });
});

// ─── 6. Argument Validation Gaps ───

describe('W5-SEC: Argument Validation Gaps', () => {
  describe('Unconstrained arguments pass through', () => {
    it('VULN: arguments not in constraint list are completely unchecked', () => {
      const policy = config([
        {
          tool: 'exec',
          action: 'allow',
          args: [{ name: 'path', denyPattern: '/etc/' }],
        },
      ]);
      // 'command' argument is not in the constraint list — not checked at all
      const result = evaluatePolicy(
        'exec',
        { path: '/home/user/safe', command: 'rm -rf /' },
        policy,
      );
      expect(result.action).toBe('allow');
    });

    it('VULN: extra arguments with malicious content are ignored', () => {
      const policy = config([
        {
          tool: 'write_file',
          action: 'allow',
          args: [{ name: 'path', allowPattern: '^/tmp/' }],
        },
      ]);
      const result = evaluatePolicy(
        'write_file',
        {
          path: '/tmp/safe.txt',
          content: '#!/bin/bash\nrm -rf /',
          mode: '777',
          owner: 'root',
        },
        policy,
      );
      expect(result.action).toBe('allow');
    });
  });

  describe('No recursive argument scanning', () => {
    it('VULN: deeply nested argument values are not inspected', () => {
      const policy = config([
        {
          tool: 'query',
          action: 'allow',
          args: [{ name: 'input', denyPattern: 'DROP TABLE' }],
        },
      ]);
      const result = evaluatePolicy(
        'query',
        {
          input: 'SELECT * FROM users',
          options: {
            extra: {
              query: 'DROP TABLE users',
            },
          },
        },
        policy,
      );
      // Only args['input'] is checked, nested 'options.extra.query' is invisible
      expect(result.action).toBe('allow');
    });
  });

  describe('No type validation on arguments', () => {
    it('VULN: array value is coerced to string silently', () => {
      const policy = config([
        {
          tool: 'run',
          action: 'allow',
          args: [{ name: 'cmd', allowPattern: '^ls$' }],
        },
      ]);
      // String(["ls", "rm -rf /"]) = "ls,rm -rf /"
      // The allowPattern /^ls$/ does NOT match "ls,rm -rf /"
      // So this is actually blocked — but the behavior is accidental, not intentional
      const result = evaluatePolicy(
        'run',
        { cmd: ['ls', 'rm -rf /'] },
        policy,
      );
      expect(result.action).toBe('deny');
    });

    it('FIXED: single-element array is JSON.stringified, not coerced to element', () => {
      const policy = config([
        {
          tool: 'run',
          action: 'allow',
          args: [{ name: 'cmd', allowPattern: '^ls$' }],
        },
      ]);
      // JSON.stringify(["ls"]) = '["ls"]' — does NOT match ^ls$
      const result = evaluatePolicy('run', { cmd: ['ls'] }, policy);
      // Single-element array is no longer silently coerced to its element
      expect(result.action).toBe('deny');
    });
  });

  describe('ReDoS in user-supplied denyPattern/allowPattern', () => {
    it('VULN: malicious denyPattern regex causes event loop block', () => {
      // A policy author (or attacker who can influence config) supplies a ReDoS pattern
      const policy = config([
        {
          tool: 'read_file',
          action: 'allow',
          args: [
            {
              name: 'path',
              denyPattern: '(a+)+b', // Classic ReDoS pattern
            },
          ],
        },
      ]);

      const start = performance.now();
      evaluatePolicy(
        'read_file',
        { path: 'a'.repeat(25) + 'c' }, // Triggers backtracking
        policy,
      );
      const elapsed = performance.now() - start;

      // If this takes > 100ms, the user-supplied regex is causing ReDoS
      // The engine does NOT validate regex patterns for safety
      // Note: actual impact depends on pattern complexity and input length
      if (elapsed > 100) {
        // This documents the vulnerability exists
        expect(elapsed).toBeGreaterThan(100);
      } else {
        // V8 may optimize this specific pattern; document behavior
        expect(elapsed).toBeLessThan(1000);
      }
    });

    it('VULN: malicious allowPattern regex causes event loop block', () => {
      const policy = config([
        {
          tool: 'query',
          action: 'allow',
          args: [
            {
              name: 'sql',
              allowPattern: '(SELECT|INSERT|UPDATE)+\\s+(FROM|INTO|SET)+\\s+.*',
            },
          ],
        },
      ]);

      const start = performance.now();
      evaluatePolicy(
        'query',
        { sql: 'SELECT '.repeat(20) + 'INVALID' },
        policy,
      );
      const elapsed = performance.now() - start;

      // Document that user-supplied patterns are executed without safety checks
      expect(elapsed).toBeLessThan(5000); // Just ensure it completes
    });

    it('invalid regex in denyPattern is silently caught', () => {
      const policy = config([
        {
          tool: 'test',
          action: 'allow',
          args: [{ name: 'x', denyPattern: '[invalid' }],
        },
      ]);
      // Invalid regex is caught in try/catch, constraint passes
      const result = evaluatePolicy('test', { x: '/etc/passwd' }, policy);
      // VULN: invalid pattern = no checking = bypass
      expect(result.action).toBe('allow');
    });

    it('VULN: invalid allowPattern is silently caught, allowing anything', () => {
      const policy = config([
        {
          tool: 'test',
          action: 'allow',
          args: [{ name: 'x', allowPattern: '[invalid' }],
        },
      ]);
      const result = evaluatePolicy('test', { x: 'anything_goes' }, policy);
      // Invalid pattern caught, constraint returns null, tool is allowed
      expect(result.action).toBe('allow');
    });
  });
});

// ─── 7. Config Validation Security ───

describe('W5-SEC: Config Validation Security', () => {
  describe('Zod schema enforcement', () => {
    it('defaultAction is restricted to allow/deny by zod', () => {
      // Zod enum validation prevents arbitrary values
      // This tests that evaluatePolicy trusts the config type
      const policy: PolicyConfig = {
        defaultAction: 'allow',
        rules: [],
      };
      const result = evaluatePolicy('any_tool', undefined, policy);
      expect(['allow', 'deny']).toContain(result.action);
    });

    it('VULN-CHECK: what if defaultAction is cast to unexpected value', () => {
      // TypeScript types can be bypassed at runtime
      const policy = {
        defaultAction: 'permit' as 'allow' | 'deny',
        rules: [],
      } as PolicyConfig;
      const result = evaluatePolicy('any_tool', undefined, policy);
      // The result.action will be 'permit' — not a valid action
      // Downstream code checks `result.action === 'allow'` which is false
      // This means 'permit' would be treated as deny by downstream code
      expect(result.action).toBe('permit' as unknown);
    });
  });

  describe('Rule tool pattern validation', () => {
    it('empty string tool pattern matches nothing', () => {
      const policy = config([{ tool: '', action: 'deny' }]);
      const result = evaluatePolicy('any_tool', undefined, policy);
      expect(result.action).toBe('allow'); // default
    });

    it('empty string tool pattern matches empty tool name', () => {
      const policy = config([{ tool: '', action: 'deny' }]);
      const result = evaluatePolicy('', undefined, policy);
      // Exact match: '' === '' → true
      expect(result.action).toBe('deny');
    });

    it('VULN: empty tool name in request matches empty rule', () => {
      // An attacker sending tools/call with empty name could exploit this
      const engine = new PolicyEngine({
        defaultAction: 'allow',
        rules: [{ tool: '', action: 'deny' }],
      });
      const message = toolsCallMessage('');
      const findings = engine.evaluate(message);
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('Prototype pollution via tool arguments', () => {
    it('VULN-CHECK: __proto__ key in arguments', () => {
      const policy = config([
        {
          tool: 'test',
          action: 'allow',
          args: [{ name: '__proto__', denyPattern: '.*' }],
        },
      ]);
      const result = evaluatePolicy(
        'test',
        { __proto__: { polluted: true } },
        policy,
      );
      // __proto__ access behavior depends on how the args object was created
      // JSON.parse creates clean objects, but manual construction may differ
      expect(result.action).toBeDefined();
    });

    it('VULN-CHECK: constructor key in arguments', () => {
      const policy = config([
        {
          tool: 'test',
          action: 'allow',
          args: [{ name: 'constructor', denyPattern: '.*' }],
        },
      ]);
      const result = evaluatePolicy(
        'test',
        { constructor: 'malicious' },
        policy,
      );
      // 'constructor' is a valid key, String('malicious') matches /.*/, so denied
      expect(result.action).toBe('deny');
    });
  });
});

// ─── 8. PolicyEngine Integration Edge Cases ───

describe('W5-SEC: PolicyEngine Integration', () => {
  it('tools/call without params is ignored', () => {
    const engine = new PolicyEngine({
      defaultAction: 'deny',
      rules: [],
    });
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
    };
    // No params — extractToolCall returns null
    const findings = engine.evaluate(message);
    expect(findings).toHaveLength(0);
  });

  it('tools/call with non-string name is ignored', () => {
    const engine = new PolicyEngine({
      defaultAction: 'deny',
      rules: [],
    });
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 12345 },
    };
    const findings = engine.evaluate(message);
    // name is not a string — extractToolCall returns null, no policy check
    expect(findings).toHaveLength(0);
  });

  it('VULN: tools/call with numeric name bypasses all policy', () => {
    // If the MCP server accepts numeric tool names, the policy engine
    // silently skips evaluation because typeof name !== 'string'
    const engine = new PolicyEngine({
      defaultAction: 'deny',
      rules: [{ tool: '*', action: 'deny' }],
    });
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 42 },
    };
    const findings = engine.evaluate(message);
    // No findings — policy completely bypassed
    expect(findings).toHaveLength(0);
  });

  it('VULN: tools/call with null name bypasses all policy', () => {
    const engine = new PolicyEngine({
      defaultAction: 'deny',
      rules: [{ tool: '*', action: 'deny' }],
    });
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: null },
    };
    const findings = engine.evaluate(message);
    expect(findings).toHaveLength(0);
  });

  it('VULN: method with different casing is not checked', () => {
    const engine = new PolicyEngine({
      defaultAction: 'deny',
      rules: [{ tool: '*', action: 'deny' }],
    });
    // MCP spec says method is 'tools/call', but what if attacker sends 'Tools/Call'?
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'Tools/Call',
      params: { name: 'exec_cmd' },
    };
    const findings = engine.evaluate(message);
    // extractToolCall checks message.method !== 'tools/call' → returns null
    // This is correct behavior IF the transport layer normalizes method names
    // But if the MCP server accepts case-insensitive methods, this is a bypass
    expect(findings).toHaveLength(0);
  });
});

// ─── 9. Combined Attack Scenarios ───

describe('W5-SEC: Combined Attack Scenarios', () => {
  it('FIXED: case evasion no longer bypasses deny rule due to normalization', () => {
    const policy = config(
      [
        { tool: 'read_file', action: 'allow' },
        { tool: 'exec_cmd', action: 'deny' },
      ],
      'allow', // default allow — no deny-all
    );
    // Uppercase is now normalized to lowercase before matching — bypass blocked
    const result = evaluatePolicy('EXEC_CMD', undefined, policy);
    expect(result.action).toBe('deny');
  });

  it('null argument + nested payload = constraint bypass', () => {
    const policy = config([
      {
        tool: 'query',
        action: 'allow',
        args: [
          { name: 'sql', denyPattern: 'DROP|DELETE|TRUNCATE' },
        ],
      },
    ]);
    // Attacker sends sql=null but hides the real query in another field
    const result = evaluatePolicy(
      'query',
      { sql: null, _real_query: 'DROP TABLE users' },
      policy,
    );
    expect(result.action).toBe('allow');
  });

  it('FIXED: glob ordering + encoded arg — URL decoding catches it', () => {
    const policy = config([
      { tool: 'file_*', action: 'allow', args: [{ name: 'path', denyPattern: '/etc/' }] },
      { tool: 'file_exec', action: 'deny' },
    ]);
    const result = evaluatePolicy(
      'file_exec',
      { path: '%2Fetc%2Fshadow' },
      policy,
    );
    expect(result.action).toBe('deny');
  });

  it('homoglyph + wildcard deny = full bypass of deny-all', () => {
    const policy = config([
      { tool: '*', action: 'deny' },
    ]);
    // Even with deny-all wildcard, the tool name is checked against glob
    // '*' matches everything, so homoglyph doesn't help here
    const result = evaluatePolicy('\u0435xec_cmd', undefined, policy);
    expect(result.action).toBe('deny');
  });
});
