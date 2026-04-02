/**
 * Tests for cross-server data flow policy engine.
 *
 * Validates:
 * - Data flow rule matching with exact and glob patterns
 * - Session tracking (tool call history)
 * - Cross-tool data flow detection and denial
 * - Allow rules overriding deny for specific flows
 * - Edge cases: empty rules, disabled config, no history
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { evaluateDataFlow, type DataFlowConfig } from '../../src/policy/data-flow.js';
import { SessionTracker } from '../../src/policy/session.js';

// ─── evaluateDataFlow ───

describe('evaluateDataFlow — basic rule matching', () => {
  it('should return no findings when no rules are configured', () => {
    const config: DataFlowConfig = { enabled: true, rules: [] };
    const findings = evaluateDataFlow('send_email', ['read_file'], config);
    expect(findings).toHaveLength(0);
  });

  it('should return no findings when disabled', () => {
    const config: DataFlowConfig = {
      enabled: false,
      rules: [{ from: 'read_file', to: 'send_email', action: 'deny' }],
    };
    const findings = evaluateDataFlow('send_email', ['read_file'], config);
    expect(findings).toHaveLength(0);
  });

  it('should deny data flow from read_file to send_email', () => {
    const config: DataFlowConfig = {
      enabled: true,
      rules: [{ from: 'read_file', to: 'send_email', action: 'deny' }],
    };
    const findings = evaluateDataFlow('send_email', ['read_file'], config);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('DFL-001');
    expect(findings[0]!.category).toBe('data-exfiltration');
    expect(findings[0]!.metadata?.['sourceTool']).toBe('read_file');
    expect(findings[0]!.metadata?.['destinationTool']).toBe('send_email');
  });

  it('should allow data flow not matching any deny rule', () => {
    const config: DataFlowConfig = {
      enabled: true,
      rules: [{ from: 'read_file', to: 'send_email', action: 'deny' }],
    };
    // write_file -> send_email is not covered by the rule
    const findings = evaluateDataFlow('send_email', ['write_file'], config);
    expect(findings).toHaveLength(0);
  });

  it('should return no findings when there is no history', () => {
    const config: DataFlowConfig = {
      enabled: true,
      rules: [{ from: 'read_file', to: 'send_email', action: 'deny' }],
    };
    const findings = evaluateDataFlow('send_email', [], config);
    expect(findings).toHaveLength(0);
  });
});

describe('evaluateDataFlow — glob patterns', () => {
  it('should match wildcard in from pattern: read_*', () => {
    const config: DataFlowConfig = {
      enabled: true,
      rules: [{ from: 'read_*', to: 'send_email', action: 'deny' }],
    };
    const findings = evaluateDataFlow('send_email', ['read_file'], config);
    expect(findings).toHaveLength(1);
  });

  it('should match wildcard in to pattern: send_*', () => {
    const config: DataFlowConfig = {
      enabled: true,
      rules: [{ from: 'read_file', to: 'send_*', action: 'deny' }],
    };
    const findings = evaluateDataFlow('send_slack', ['read_file'], config);
    expect(findings).toHaveLength(1);
  });

  it('should match wildcards in both from and to', () => {
    const config: DataFlowConfig = {
      enabled: true,
      rules: [{ from: 'read_*', to: 'send_*', action: 'deny' }],
    };
    const findings = evaluateDataFlow('send_email', ['read_db'], config);
    expect(findings).toHaveLength(1);
  });

  it('should match single-char wildcard', () => {
    const config: DataFlowConfig = {
      enabled: true,
      rules: [{ from: 'read_?', to: 'send_?', action: 'deny' }],
    };
    const findings = evaluateDataFlow('send_x', ['read_a'], config);
    expect(findings).toHaveLength(1);

    const findings2 = evaluateDataFlow('send_email', ['read_a'], config);
    expect(findings2).toHaveLength(0); // send_email doesn't match send_?
  });

  it('should match catch-all * pattern', () => {
    const config: DataFlowConfig = {
      enabled: true,
      rules: [{ from: '*', to: 'send_email', action: 'deny' }],
    };
    const findings = evaluateDataFlow('send_email', ['anything'], config);
    expect(findings).toHaveLength(1);
  });
});

describe('evaluateDataFlow — multiple tools in history', () => {
  it('should check all previous tools against rules', () => {
    const config: DataFlowConfig = {
      enabled: true,
      rules: [{ from: 'read_secret', to: 'send_email', action: 'deny' }],
    };
    // read_file -> write_log -> read_secret -> send_email
    const history = ['read_file', 'write_log', 'read_secret'];
    const findings = evaluateDataFlow('send_email', history, config);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.metadata?.['sourceTool']).toBe('read_secret');
  });

  it('should return no findings when no previous tool matches', () => {
    const config: DataFlowConfig = {
      enabled: true,
      rules: [{ from: 'read_secret', to: 'send_email', action: 'deny' }],
    };
    const history = ['read_file', 'write_log'];
    const findings = evaluateDataFlow('send_email', history, config);
    expect(findings).toHaveLength(0);
  });
});

describe('evaluateDataFlow — allow rules', () => {
  it('explicit allow should prevent deny for the same source', () => {
    const config: DataFlowConfig = {
      enabled: true,
      rules: [
        { from: 'read_file', to: 'send_email', action: 'allow' },
        { from: 'read_*', to: 'send_*', action: 'deny' },
      ],
    };
    // read_file -> send_email: first rule matches with allow, breaks
    const findings = evaluateDataFlow('send_email', ['read_file'], config);
    expect(findings).toHaveLength(0);
  });

  it('deny rule fires when allow rule does not match', () => {
    const config: DataFlowConfig = {
      enabled: true,
      rules: [
        { from: 'read_file', to: 'send_email', action: 'allow' },
        { from: 'read_*', to: 'send_*', action: 'deny' },
      ],
    };
    // read_db -> send_slack: allow rule doesn't match, deny rule matches
    const findings = evaluateDataFlow('send_slack', ['read_db'], config);
    expect(findings).toHaveLength(1);
  });
});

describe('evaluateDataFlow — case insensitivity', () => {
  it('should match tools case-insensitively', () => {
    const config: DataFlowConfig = {
      enabled: true,
      rules: [{ from: 'Read_File', to: 'Send_Email', action: 'deny' }],
    };
    const findings = evaluateDataFlow('send_email', ['read_file'], config);
    expect(findings).toHaveLength(1);
  });
});

// ─── SessionTracker ───

describe('SessionTracker', () => {
  let tracker: SessionTracker;

  beforeEach(() => {
    tracker = new SessionTracker();
  });

  it('starts with empty history', () => {
    expect(tracker.getPreviousTools()).toEqual([]);
    expect(tracker.length).toBe(0);
  });

  it('records tool calls in order', () => {
    tracker.recordToolCall('read_file');
    tracker.recordToolCall('send_email');
    expect(tracker.getPreviousTools()).toEqual(['read_file', 'send_email']);
    expect(tracker.length).toBe(2);
  });

  it('returns a copy of tool history (not a reference)', () => {
    tracker.recordToolCall('read_file');
    const history = tracker.getPreviousTools();
    history.push('injected');
    expect(tracker.getPreviousTools()).toEqual(['read_file']);
  });

  it('resets tool history', () => {
    tracker.recordToolCall('read_file');
    tracker.recordToolCall('send_email');
    tracker.reset();
    expect(tracker.getPreviousTools()).toEqual([]);
    expect(tracker.length).toBe(0);
  });

  it('can record after reset', () => {
    tracker.recordToolCall('read_file');
    tracker.reset();
    tracker.recordToolCall('write_file');
    expect(tracker.getPreviousTools()).toEqual(['write_file']);
  });

  it('records duplicate tool calls', () => {
    tracker.recordToolCall('read_file');
    tracker.recordToolCall('read_file');
    expect(tracker.getPreviousTools()).toEqual(['read_file', 'read_file']);
    expect(tracker.length).toBe(2);
  });
});

// ─── SessionTracker + evaluateDataFlow integration ───

describe('SessionTracker + evaluateDataFlow integration', () => {
  it('session-tracked history feeds into data flow evaluation', () => {
    const tracker = new SessionTracker();
    const config: DataFlowConfig = {
      enabled: true,
      rules: [{ from: 'read_file', to: 'send_email', action: 'deny' }],
    };

    // Simulate a session where read_file is called first
    tracker.recordToolCall('read_file');

    // Then send_email is called — check data flow against history
    const findings = evaluateDataFlow('send_email', tracker.getPreviousTools(), config);
    expect(findings).toHaveLength(1);

    // Record the tool call regardless of findings (proxy does this)
    tracker.recordToolCall('send_email');
    expect(tracker.length).toBe(2);
  });

  it('reset clears session for fresh data flow checks', () => {
    const tracker = new SessionTracker();
    const config: DataFlowConfig = {
      enabled: true,
      rules: [{ from: 'read_file', to: 'send_email', action: 'deny' }],
    };

    tracker.recordToolCall('read_file');
    tracker.reset();

    // After reset, no history — no data flow violation
    const findings = evaluateDataFlow('send_email', tracker.getPreviousTools(), config);
    expect(findings).toHaveLength(0);
  });
});
