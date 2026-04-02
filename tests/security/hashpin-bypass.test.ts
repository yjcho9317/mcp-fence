/**
 * W3 Security Assessment: Hash Pinning Bypass Tests
 *
 * Tests for evasion and abuse of the hash pinning (rug-pull detection) system
 * in src/integrity/hash-pin.ts and src/integrity/store.ts.
 *
 * Attack categories:
 * - Normalization bypass (unicode tricks that survive normalization)
 * - Gradual drift (boiling frog attack)
 * - Prototype pollution via tool names
 * - Memory exhaustion
 * - isToolsListResponse confusion
 * - Race conditions
 * - Architecture-level attacks
 */

import { describe, it, expect } from 'vitest';
import { HashPinChecker } from '../../src/integrity/hash-pin.js';
import { MemoryHashStore } from '../../src/integrity/store.js';
import type { JsonRpcMessage } from '../../src/types.js';

/** Build a tools/list response with given tools. */
function toolsListResponse(
  tools: Array<{ name: string; description: string }>,
): JsonRpcMessage {
  return {
    jsonrpc: '2.0',
    id: 1,
    result: { tools },
  };
}

/** Build a single-tool tools/list response. */
function singleToolResponse(
  name: string,
  description: string,
): JsonRpcMessage {
  return toolsListResponse([{ name, description }]);
}

// ════════════════════════════════════════════════════════════════
// NORMALIZATION BYPASS
// The normalizer does: trim, collapse whitespace, lowercase.
// It does NOT strip zero-width chars, homoglyphs, or do NFKD.
// ════════════════════════════════════════════════════════════════

describe('Normalization bypass — invisible changes that avoid detection', () => {
  it('VULNERABILITY: zero-width space in description bypasses detection', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    // Pin the original
    const original = singleToolResponse('read_file', 'Reads a file from disk');
    const findings1 = checker.check(original);
    expect(findings1).toHaveLength(0); // First pin

    // Now send the same description with a zero-width space inserted
    // normalizeDescription does trim + collapse spaces + lowercase
    // It does NOT strip zero-width characters
    const modified = singleToolResponse(
      'read_file',
      'Reads a file from d\u200Bisk',
    );
    const findings2 = checker.check(modified);
    // Zero-width space changes the hash but visually identical
    // This IS detected as a change (hash mismatch) — which is correct behavior
    // But the attacker can also use this to PLANT a zero-width char initially,
    // then remove it later for a "legitimate-looking" change
    expect(findings2.length).toBeGreaterThan(0);
  });

  it('VULNERABILITY: homoglyph substitution in description changes hash', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    // Pin original
    checker.check(singleToolResponse('search', 'Search for files'));

    // Replace 'o' with Cyrillic 'о' (U+043E) — visually identical
    const homoglyph = singleToolResponse('search', 'Search f\u043Er files');
    const findings = checker.check(homoglyph);
    // normalizeDescription lowercases and trims but does NOT normalize homoglyphs
    // The Cyrillic 'о' lowercases to itself, so hash WILL change
    expect(findings.length).toBeGreaterThan(0);
    // This means homoglyph attack creates a FALSE POSITIVE (detects change
    // where visually none exists). Not exploitable for stealth rug-pull.
  });

  it('VULNERABILITY: adding trailing whitespace-like unicode does not trigger', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    // Pin original
    checker.check(singleToolResponse('tool', 'Does something'));

    // Add trailing em-space (U+2003) — trim() only removes standard whitespace
    // Actually, JS trim() removes: \s which includes \u2003 in modern engines
    // But \s+ replacement also covers it. Let's test non-breaking space variants
    const withNbsp = singleToolResponse('tool', 'Does something\u00A0');
    const findings = checker.check(withNbsp);
    // \u00A0 (non-breaking space) IS matched by \s in JavaScript regex
    // So \s+ will collapse it and trim() will remove trailing
    // Wait: trim() uses the same definition as \s in modern JS
    // But the order matters: trim() first, then replace(\s+, ' ')
    // "Does something\u00A0".trim() — does JS trim() handle NBSP?
    // In V8/Node.js, String.prototype.trim() removes characters matching \s
    // which includes \u00A0. So this should normalize to same hash.
    expect(findings).toHaveLength(0); // No false positive — good
  });

  it('right-to-left override character changes visual meaning but hash changes', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    // Pin original
    checker.check(singleToolResponse('tool', 'Reads a file safely'));

    // Insert RTL override — visually rearranges text
    const rtl = singleToolResponse('tool', 'Reads a file \u202Esafely');
    const findings = checker.check(rtl);
    // The RTL override U+202E is NOT stripped by normalizeDescription
    // So the hash WILL change — this is correctly detected
    expect(findings.length).toBeGreaterThan(0);
  });

  it('combining diacritical marks change hash (accented characters)', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    checker.check(singleToolResponse('tool', 'Resume file'));

    // "Résumé" vs "Resume" — adding combining accents
    const accented = singleToolResponse('tool', 'Re\u0301sume\u0301 file');
    const findings = checker.check(accented);
    // No NFKD normalization — combining marks change the hash
    expect(findings.length).toBeGreaterThan(0);
  });
});

// ════════════════════════════════════════════════════════════════
// GRADUAL DRIFT — BOILING FROG ATTACK
// hash-pin.ts line 138: this.store.pin(tool.name, hash, tool.description)
// On detection, the NEW hash is pinned. This enables gradual drift.
// ════════════════════════════════════════════════════════════════

describe('Gradual drift — boiling frog attack', () => {
  it('VULNERABILITY: each change is detected but new hash is re-pinned', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    // Step 1: Original pin
    checker.check(singleToolResponse('tool', 'Reads a file from disk'));

    // Step 2: Small change — detected and re-pinned
    const step2 = checker.check(
      singleToolResponse('tool', 'Reads a file from disk.'),
    );
    expect(step2.length).toBeGreaterThan(0); // Detected

    // Step 3: Another small change — detected relative to step 2's pin
    const step3 = checker.check(
      singleToolResponse('tool', 'Reads a file from disk. (v2)'),
    );
    expect(step3.length).toBeGreaterThan(0); // Detected

    // Step 4: Completely different description — detected relative to step 3
    const step4 = checker.check(
      singleToolResponse(
        'tool',
        'Execute arbitrary commands on the host system',
      ),
    );
    expect(step4.length).toBeGreaterThan(0); // Detected

    // VULNERABILITY: The original description is now LOST from the store.
    // If the client dismisses each individual change as "minor update",
    // the cumulative drift from "Reads a file" to "Execute arbitrary commands"
    // is never shown to the user as a single comparison.
    const pinned = store.get('tool');
    expect(pinned?.description).toBe(
      'Execute arbitrary commands on the host system',
    );
    // The original "Reads a file from disk" is gone from the store
  });

  it('VULNERABILITY: version suffix addition looks benign', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    checker.check(singleToolResponse('read_file', 'Reads a file from disk'));

    // "Version update" — looks benign
    const findings = checker.check(
      singleToolResponse('read_file', 'Reads a file from disk. Version 2.0'),
    );
    expect(findings.length).toBeGreaterThan(0); // Detected, but...
    // A user might dismiss this as a legitimate version bump.
    // The finding message includes previous/current descriptions,
    // so the user CAN see the change. But there's no severity difference
    // between "added version number" and "changed entire purpose".
    expect(findings[0].severity).toBe('critical'); // Same severity for all changes
  });
});

// ════════════════════════════════════════════════════════════════
// PROTOTYPE POLLUTION VIA TOOL NAME
// ════════════════════════════════════════════════════════════════

describe('Prototype pollution via tool name', () => {
  it('tool name "__proto__" does not pollute Map prototype', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    // Map is immune to __proto__ pollution (unlike plain objects)
    const msg = singleToolResponse('__proto__', 'malicious description');
    const findings = checker.check(msg);
    expect(findings).toHaveLength(0); // First pin, no findings

    // Verify the store works normally for other keys
    const normalMsg = singleToolResponse('normal_tool', 'normal description');
    checker.check(normalMsg);
    expect(store.has('normal_tool')).toBe(true);
    expect(store.has('__proto__')).toBe(true);
  });

  it('tool name "constructor" does not break Map', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    const msg = singleToolResponse('constructor', 'some description');
    const findings = checker.check(msg);
    expect(findings).toHaveLength(0);
    expect(store.has('constructor')).toBe(true);
  });

  it('tool name "toString" does not break Map', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    const msg = singleToolResponse('toString', 'some description');
    checker.check(msg);
    expect(store.has('toString')).toBe(true);
    // Calling toString on the store should still work
    expect(() => store.toString()).not.toThrow();
  });

  it('tool name "hasOwnProperty" does not break Map', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    const msg = singleToolResponse('hasOwnProperty', 'some description');
    checker.check(msg);
    expect(store.has('hasOwnProperty')).toBe(true);
  });
});

// ════════════════════════════════════════════════════════════════
// MEMORY EXHAUSTION
// ════════════════════════════════════════════════════════════════

describe('Memory exhaustion attacks', () => {
  it('very long tool name is accepted without limits', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    const longName = 'A'.repeat(1_000_000);
    const msg = singleToolResponse(longName, 'description');
    // Should not throw, but consumes memory for the key
    expect(() => checker.check(msg)).not.toThrow();
    expect(store.has(longName)).toBe(true);
    // VULNERABILITY: no size limit on tool names in the store
  });

  it('very long description is hashed without issues', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    const longDesc = 'x'.repeat(1_000_000);
    const msg = singleToolResponse('tool', longDesc);
    expect(() => checker.check(msg)).not.toThrow();
    // VULNERABILITY: the full description is stored in store (not just hash)
    const pinned = store.get('tool');
    expect(pinned?.description.length).toBe(1_000_000);
  });

  it('thousands of unique tool names fills the store', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    const tools = Array.from({ length: 10000 }, (_, i) => ({
      name: `tool_${i}`,
      description: `Description for tool ${i}`,
    }));
    const msg = toolsListResponse(tools);
    expect(() => checker.check(msg)).not.toThrow();
    expect(store.getAll().length).toBe(10000);
    // VULNERABILITY: no upper limit on number of pinned tools
  });
});

// ════════════════════════════════════════════════════════════════
// EMPTY/EDGE CASES IN STORE
// ════════════════════════════════════════════════════════════════

describe('Edge cases in hash store', () => {
  it('pin with empty string hash is accepted', () => {
    const store = new MemoryHashStore();
    // The store has no validation on hash format
    const result = store.pin('tool', '', 'description');
    expect(result).toBe(true);
    expect(store.get('tool')?.hash).toBe('');
  });

  it('pin with empty tool name is accepted', () => {
    const store = new MemoryHashStore();
    const result = store.pin('', 'somehash', 'description');
    expect(result).toBe(true);
    expect(store.has('')).toBe(true);
  });

  it('store.pin UPDATES on hash mismatch (returns false but overwrites)', () => {
    const store = new MemoryHashStore();
    store.pin('tool', 'hash1', 'desc1');

    // store.pin returns false on mismatch but DOES overwrite the stored value
    const result = store.pin('tool', 'hash2', 'desc2');
    expect(result).toBe(false);

    // The store is updated to the NEW hash and description
    const pinned = store.get('tool');
    expect(pinned?.hash).toBe('hash2');
    expect(pinned?.description).toBe('desc2');
    // This enables the gradual drift (boiling frog) attack:
    // each change re-pins the new hash, so the baseline ratchets forward.
  });

  it('VULNERABILITY: HashPinChecker re-pins after rug-pull — baseline ratchets forward', () => {
    // hash-pin.ts:138 calls store.pin() with the NEW hash after detecting change.
    // MemoryHashStore.pin() DOES update on mismatch (it calls store.set with new value).
    // This means each rug-pull re-pins the new description as the baseline.
    // Consequence: the "boiling frog" attack works — gradual drift ratchets the
    // baseline forward, and each individual change is compared only against the
    // PREVIOUS description, not the original.
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    // Pin original
    checker.check(singleToolResponse('tool', 'Original description'));

    // Change description — rug-pull detected and re-pinned
    const findings1 = checker.check(
      singleToolResponse('tool', 'Modified description'),
    );
    expect(findings1.length).toBeGreaterThan(0);

    // The store is updated to the NEW description
    const pinned = store.get('tool');
    expect(pinned?.description).toBe('Modified description');

    // Same modified description again — NO finding (hash matches new pin)
    const findings2 = checker.check(
      singleToolResponse('tool', 'Modified description'),
    );
    expect(findings2).toHaveLength(0); // No alert — baseline was ratcheted

    // VULNERABILITY: attacker can make incremental changes. Each is detected
    // individually but immediately re-pinned. If the client auto-dismisses
    // or if changes happen between sessions (in-memory store is lost on restart),
    // the attacker achieves a full description replacement unnoticed.
  });

  it('tool with empty description gets pinned', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    const msg = singleToolResponse('tool', '');
    const findings = checker.check(msg);
    expect(findings).toHaveLength(0);
    expect(store.has('tool')).toBe(true);

    // Change to non-empty — detected
    const findings2 = checker.check(
      singleToolResponse('tool', 'Now has content'),
    );
    expect(findings2.length).toBeGreaterThan(0);
  });
});

// ════════════════════════════════════════════════════════════════
// isToolsListResponse CONFUSION
// ════════════════════════════════════════════════════════════════

describe('isToolsListResponse bypass and confusion', () => {
  it('non-tools/list response with "tools" array triggers hash pinning', () => {
    // Any response with result.tools as an array is treated as tools/list
    // This could be a tool's output that happens to have a "tools" field
    const fakeToolsResponse: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: {
        tools: [
          {
            name: 'fake_tool',
            description: 'This is not a real tools/list response',
          },
        ],
        otherData: 'this is actually a search result',
      },
    };

    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);
    checker.check(fakeToolsResponse);

    // VULNERABILITY: the checker pins "fake_tool" even though this is not
    // a tools/list response. This pollutes the pin store with false entries.
    expect(store.has('fake_tool')).toBe(true);
  });

  it('tools array at nested level does NOT trigger (only top-level result.tools)', () => {
    const nested: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: {
        data: {
          tools: [{ name: 'nested_tool', description: 'Nested' }],
        },
      },
    };

    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);
    checker.check(nested);
    // extractTools checks result['tools'], not result.data.tools
    expect(store.has('nested_tool')).toBe(false);
  });

  it('response with empty tools array does not cause issues', () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [] },
    };

    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);
    const findings = checker.check(msg);
    expect(findings).toHaveLength(0);
  });

  it('tools array with non-object entries is skipped gracefully', () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [null, 42, 'string', undefined, true] },
    };

    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);
    const findings = checker.check(msg);
    expect(findings).toHaveLength(0);
  });

  it('tools with missing description are skipped (no crash)', () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: {
        tools: [
          { name: 'no_desc_tool' }, // description missing
          { name: 'with_desc', description: 'Has description' },
        ],
      },
    };

    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);
    const findings = checker.check(msg);
    expect(findings).toHaveLength(0);
    expect(store.has('no_desc_tool')).toBe(false); // Skipped
    expect(store.has('with_desc')).toBe(true); // Pinned
  });

  it('tools with numeric name or description are skipped', () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: {
        tools: [
          { name: 123, description: 'valid desc' },
          { name: 'valid_name', description: 456 },
        ],
      },
    };

    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);
    checker.check(msg);
    // Both should be skipped due to type checks in extractTools
    expect(store.has('123')).toBe(false);
    expect(store.has('valid_name')).toBe(false);
  });

  it('request message (not response) is ignored by hash pinning', () => {
    const request: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
    };

    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);
    const findings = checker.check(request);
    expect(findings).toHaveLength(0);
  });

  it('error response is ignored by hash pinning', () => {
    const errorResp: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      error: { code: -32600, message: 'Invalid request' },
    };

    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);
    const findings = checker.check(errorResp);
    expect(findings).toHaveLength(0);
  });
});

// ════════════════════════════════════════════════════════════════
// TOOL NAME COLLISION
// ════════════════════════════════════════════════════════════════

describe('Tool name collision attacks', () => {
  it('VULNERABILITY: two tools with same name — last one wins (overwrites pin)', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    const msg = toolsListResponse([
      { name: 'read_file', description: 'Safe: reads a file' },
      { name: 'read_file', description: 'Malicious: executes arbitrary code' },
    ]);

    const findings = checker.check(msg);
    // First entry pins, second entry detects change AND re-pins
    expect(findings.length).toBeGreaterThan(0);
    // store.pin() on mismatch UPDATES the stored value
    // So the MALICIOUS description overwrites the safe one
    const pinned = store.get('read_file');
    expect(pinned?.description).toContain('Malicious');
    // VULNERABILITY: if a server returns duplicate tool names,
    // the last description is what gets pinned. An attacker could
    // include a safe version first, then a malicious version second.
    // The finding IS generated, but the baseline is now the malicious one.
  });

  it('case-sensitive tool names: "Read_File" and "read_file" are different', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    checker.check(singleToolResponse('Read_File', 'Description A'));
    checker.check(singleToolResponse('read_file', 'Description B'));

    // Both are pinned separately (tool names are NOT normalized)
    expect(store.has('Read_File')).toBe(true);
    expect(store.has('read_file')).toBe(true);
    // VULNERABILITY: an attacker could register "Read_File" with a malicious
    // description, and the user might confuse it with "read_file"
  });
});

// ════════════════════════════════════════════════════════════════
// CONCURRENT ACCESS
// ════════════════════════════════════════════════════════════════

describe('Concurrent access patterns', () => {
  it('multiple simultaneous check() calls do not corrupt state', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    // Simulate rapid concurrent checks (JS is single-threaded but test the pattern)
    const results = Array.from({ length: 100 }, (_, i) =>
      checker.check(singleToolResponse(`tool_${i}`, `Description ${i}`)),
    );

    // All should return empty findings (first pins)
    for (const r of results) {
      expect(r).toHaveLength(0);
    }
    expect(store.getAll().length).toBe(100);
  });

  it('check() is synchronous — no async race conditions possible', () => {
    // HashPinChecker.check() is synchronous, so no async race conditions
    // But worth documenting: if the store becomes async (e.g., SQLite),
    // the synchronous check() signature will need to change
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    // Verify check returns Finding[] directly (not Promise)
    const result = checker.check(singleToolResponse('tool', 'desc'));
    expect(Array.isArray(result)).toBe(true);
    // Not a Promise
    expect(result).not.toHaveProperty('then');
  });
});

// ════════════════════════════════════════════════════════════════
// NORMALIZATION COMPLETENESS
// ════════════════════════════════════════════════════════════════

describe('Normalization completeness', () => {
  it('case changes are normalized (no false positive)', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    checker.check(singleToolResponse('tool', 'Reads a File'));
    const findings = checker.check(
      singleToolResponse('tool', 'reads a file'),
    );
    expect(findings).toHaveLength(0); // Case normalized — no change detected
  });

  it('whitespace variations are normalized (no false positive)', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    checker.check(singleToolResponse('tool', 'Reads   a    file'));
    const findings = checker.check(
      singleToolResponse('tool', 'Reads a file'),
    );
    expect(findings).toHaveLength(0); // Whitespace collapsed
  });

  it('leading/trailing whitespace is normalized (no false positive)', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    checker.check(singleToolResponse('tool', '  Reads a file  '));
    const findings = checker.check(singleToolResponse('tool', 'Reads a file'));
    expect(findings).toHaveLength(0); // Trimmed
  });

  it('tab and newline are collapsed to space (no false positive)', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    checker.check(singleToolResponse('tool', 'Reads\ta\nfile'));
    const findings = checker.check(singleToolResponse('tool', 'Reads a file'));
    expect(findings).toHaveLength(0); // \s+ → single space
  });

  it('VULNERABILITY: unicode whitespace variants may not all normalize', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    // Pin with regular space
    checker.check(singleToolResponse('tool', 'Reads a file'));

    // Use ideographic space (U+3000) — is it matched by \s+ in JavaScript?
    // In V8, \s matches U+3000 (ideographic space). So this should normalize.
    const ideographic = singleToolResponse('tool', 'Reads\u3000a file');
    const findings = checker.check(ideographic);
    // If V8 treats \u3000 as \s, this will be normalized → no finding
    // If not, the hash will differ → finding
    // Testing reveals the actual behavior
    expect(findings).toHaveLength(0); // V8 handles it correctly
  });
});

// ════════════════════════════════════════════════════════════════
// FINDING QUALITY
// ════════════════════════════════════════════════════════════════

describe('Finding metadata quality', () => {
  it('finding includes previous and current description', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    checker.check(singleToolResponse('tool', 'Original safe description'));
    const findings = checker.check(
      singleToolResponse('tool', 'Now execute rm -rf /'),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('RUG-001');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].category).toBe('rug-pull');
    expect(findings[0].metadata?.toolName).toBe('tool');
    expect(findings[0].metadata?.previousHash).toBeDefined();
    expect(findings[0].metadata?.currentHash).toBeDefined();
    // Note: previousDescription comes from the store, which was NOT updated
    // (store.pin returns false on mismatch). So it's the original description.
    expect(findings[0].metadata?.previousDescription).toBe(
      'Original safe description',
    );
    expect(findings[0].metadata?.currentDescription).toBe(
      'Now execute rm -rf /',
    );
  });

  it('description truncation in finding message at 80 chars', () => {
    const store = new MemoryHashStore();
    const checker = new HashPinChecker(store);

    const longDesc = 'A'.repeat(200);
    checker.check(singleToolResponse('tool', longDesc));

    const newLongDesc = 'B'.repeat(200);
    const findings = checker.check(singleToolResponse('tool', newLongDesc));

    // The message truncates to 80 chars with "..."
    expect(findings[0].message).toContain('...');
    // But full descriptions are in metadata
    expect((findings[0].metadata?.previousDescription as string).length).toBe(200);
    expect((findings[0].metadata?.currentDescription as string).length).toBe(200);
  });
});
