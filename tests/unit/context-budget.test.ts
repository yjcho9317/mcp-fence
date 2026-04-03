import { describe, it, expect } from 'vitest';
import { checkContextBudget } from '../../src/detection/context-budget.js';
import type { JsonRpcMessage, ContextBudgetConfig } from '../../src/types.js';

function makeResponse(textContent: string): JsonRpcMessage {
  return {
    jsonrpc: '2.0',
    id: 1,
    result: {
      content: [{ type: 'text', text: textContent }],
    },
  };
}

describe('Context budget — checkContextBudget', () => {
  it('should pass when response is under budget', () => {
    const config: ContextBudgetConfig = {
      enabled: true,
      maxResponseBytes: 10000,
      truncateAction: 'warn',
    };

    const msg = makeResponse('Short response');
    const result = checkContextBudget(msg, config);

    expect(result.exceeded).toBe(false);
    expect(result.finding).toBeUndefined();
  });

  it('should warn when response exceeds budget with warn action', () => {
    const config: ContextBudgetConfig = {
      enabled: true,
      maxResponseBytes: 50, // very small limit
      truncateAction: 'warn',
    };

    const msg = makeResponse('A'.repeat(200));
    const result = checkContextBudget(msg, config);

    expect(result.exceeded).toBe(true);
    expect(result.finding).toBeDefined();
    expect(result.finding!.ruleId).toBe('CTX-001');
    expect(result.finding!.severity).toBe('medium');
    expect(result.finding!.category).toBe('policy-violation');
    expect(result.finding!.metadata?.['action']).toBe('warn');
    expect(result.truncatedMessage).toBeUndefined();
  });

  it('should truncate response when action is truncate', () => {
    const config: ContextBudgetConfig = {
      enabled: true,
      maxResponseBytes: 200,
      truncateAction: 'truncate',
    };

    const msg = makeResponse('B'.repeat(500));
    const result = checkContextBudget(msg, config);

    expect(result.exceeded).toBe(true);
    expect(result.finding).toBeDefined();
    expect(result.finding!.severity).toBe('medium');
    expect(result.truncatedMessage).toBeDefined();

    // Truncated message should be within budget
    const truncatedSize = JSON.stringify(result.truncatedMessage).length;
    expect(truncatedSize).toBeLessThanOrEqual(config.maxResponseBytes!);

    // Should contain truncation marker
    const truncResult = result.truncatedMessage!.result as Record<string, unknown>;
    const content = truncResult['content'] as Array<Record<string, unknown>>;
    const text = content[0]!['text'] as string;
    expect(text).toContain('[truncated by mcp-fence');
  });

  it('should block when response exceeds budget with block action', () => {
    const config: ContextBudgetConfig = {
      enabled: true,
      maxResponseBytes: 50,
      truncateAction: 'block',
    };

    const msg = makeResponse('C'.repeat(200));
    const result = checkContextBudget(msg, config);

    expect(result.exceeded).toBe(true);
    expect(result.finding).toBeDefined();
    expect(result.finding!.ruleId).toBe('CTX-001');
    expect(result.finding!.severity).toBe('high');
    expect(result.finding!.metadata?.['action']).toBe('block');
    expect(result.truncatedMessage).toBeUndefined();
  });

  it('should skip check when budget is disabled', () => {
    const config: ContextBudgetConfig = {
      enabled: false,
      maxResponseBytes: 10,
      truncateAction: 'block',
    };

    const msg = makeResponse('D'.repeat(1000));
    const result = checkContextBudget(msg, config);

    expect(result.exceeded).toBe(false);
    expect(result.finding).toBeUndefined();
    expect(result.actualBytes).toBe(0);
  });

  it('should use default maxResponseBytes (102400) when not specified', () => {
    const config: ContextBudgetConfig = {
      enabled: true,
      truncateAction: 'warn',
    };

    // Under 100KB — should pass
    const smallMsg = makeResponse('E'.repeat(1000));
    const result = checkContextBudget(smallMsg, config);
    expect(result.exceeded).toBe(false);
  });

  it('should report correct actual and limit bytes', () => {
    const config: ContextBudgetConfig = {
      enabled: true,
      maxResponseBytes: 100,
      truncateAction: 'warn',
    };

    const msg = makeResponse('F'.repeat(500));
    const result = checkContextBudget(msg, config);

    expect(result.actualBytes).toBe(JSON.stringify(msg).length);
    expect(result.limitBytes).toBe(100);
    expect(result.actualBytes).toBeGreaterThan(100);
  });

  it('should handle response exactly at the limit', () => {
    const msg = makeResponse('G');
    const serialized = JSON.stringify(msg);
    const config: ContextBudgetConfig = {
      enabled: true,
      maxResponseBytes: serialized.length, // exactly at limit
      truncateAction: 'warn',
    };

    const result = checkContextBudget(msg, config);
    expect(result.exceeded).toBe(false);
  });

  it('should handle non-content responses gracefully during truncation', () => {
    const config: ContextBudgetConfig = {
      enabled: true,
      maxResponseBytes: 10,
      truncateAction: 'truncate',
    };

    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: { data: 'H'.repeat(100) },
    };
    const result = checkContextBudget(msg, config);

    expect(result.exceeded).toBe(true);
    // truncatedMessage is returned even if content array is absent
    expect(result.truncatedMessage).toBeDefined();
  });
});
