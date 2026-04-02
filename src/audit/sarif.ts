/**
 * SARIF (Static Analysis Results Interchange Format) output for mcp-fence.
 *
 * Converts audit events into SARIF 2.1.0 format for GitHub Security tab integration.
 * Upload the output to GitHub via:
 *   mcp-fence logs --format sarif > results.sarif
 *   gh code-scanning upload-sarif -r owner/repo -f results.sarif
 *
 * SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import type { EventRow } from './schema.js';
import type { Finding } from '../types.js';

/** SARIF severity level mapping from mcp-fence severity. */
const SARIF_LEVEL: Record<string, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  properties: Record<string, unknown>;
}

interface SarifRule {
  id: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: string };
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifDocument {
  version: string;
  $schema: string;
  runs: SarifRun[];
}

/**
 * Convert audit event rows into a SARIF 2.1.0 document.
 *
 * Only events with findings (decision != 'allow') produce SARIF results.
 */
export function toSarif(events: EventRow[]): SarifDocument {
  const results: SarifResult[] = [];
  const rulesMap = new Map<string, SarifRule>();

  for (const event of events) {
    if (event.decision === 'allow') continue;

    let findings: Finding[];
    try {
      findings = JSON.parse(event.findings) as Finding[];
    } catch {
      continue;
    }

    for (const finding of findings) {
      // Register rule if not seen
      if (!rulesMap.has(finding.ruleId)) {
        rulesMap.set(finding.ruleId, {
          id: finding.ruleId,
          shortDescription: { text: finding.message },
          defaultConfiguration: {
            level: SARIF_LEVEL[finding.severity] ?? 'warning',
          },
        });
      }

      results.push({
        ruleId: finding.ruleId,
        level: SARIF_LEVEL[finding.severity] ?? 'warning',
        message: {
          text: `[${event.direction.toUpperCase()}] ${finding.message}` +
            (event.tool_name ? ` (tool: ${event.tool_name})` : '') +
            (event.method ? ` [${event.method}]` : ''),
        },
        properties: {
          direction: event.direction,
          method: event.method,
          toolName: event.tool_name,
          decision: event.decision,
          score: event.score,
          confidence: finding.confidence,
          category: finding.category,
          timestamp: new Date(event.timestamp).toISOString(),
        },
      });
    }
  }

  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcp-fence',
            version: '0.3.0',
            informationUri: 'https://github.com/user/mcp-fence',
            rules: Array.from(rulesMap.values()),
          },
        },
        results,
      },
    ],
  };
}

/**
 * Serialize a SARIF document to a JSON string.
 */
export function sarifToJson(document: SarifDocument): string {
  return JSON.stringify(document, null, 2);
}
