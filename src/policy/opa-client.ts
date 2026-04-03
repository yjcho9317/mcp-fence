/**
 * OPA (Open Policy Agent) client for mcp-fence.
 *
 * Queries an external OPA server over HTTP for policy decisions.
 * OPA acts as the authoritative policy engine when enabled,
 * overriding local policy evaluation results.
 */

import * as http from 'node:http';
import * as https from 'node:https';
import { createLogger } from '../logger.js';

const log = createLogger('opa');

export interface OpaConfig {
  /** Whether OPA integration is enabled */
  enabled: boolean;
  /** OPA query endpoint (e.g., "http://localhost:8181/v1/data/mcp/allow") */
  url: string;
  /** Request timeout in milliseconds (default: 5000) */
  timeoutMs?: number;
  /** If OPA is unreachable, allow or deny? (default: false = deny) */
  failOpen?: boolean;
  /** Allow OPA URLs pointing to private/loopback addresses. Defaults to false. */
  allowPrivateNetwork?: boolean;
}

export interface OpaInput {
  tool: string;
  args?: Record<string, unknown>;
  direction: string;
}

export interface OpaDecision {
  allow: boolean;
  reason?: string;
}

/**
 * Query OPA for a policy decision.
 *
 * Sends a POST request to the configured OPA endpoint with the tool call
 * context as input. Handles timeouts, connection errors, and non-200 responses.
 *
 * OPA response formats supported:
 *   { "result": true }
 *   { "result": false }
 *   { "result": { "allow": true, "reason": "..." } }
 *   { "result": { "allow": false, "reason": "..." } }
 */
export async function queryOpa(
  config: OpaConfig,
  input: OpaInput,
): Promise<OpaDecision> {
  const timeout = config.timeoutMs ?? 5000;
  const failOpen = config.failOpen ?? false;
  const body = JSON.stringify({ input });

  const parsedUrl = new URL(config.url);

  if (!config.allowPrivateNetwork && isPrivateUrl(parsedUrl)) {
    log.warn(`OPA URL rejected — resolves to private/internal address: ${config.url}`);
    return { allow: false, reason: 'OPA URL points to private/internal network' };
  }

  const isHttps = parsedUrl.protocol === 'https:';
  const transport = isHttps ? https : http;

  const requestOptions: http.RequestOptions = {
    hostname: parsedUrl.hostname,
    port: parsedUrl.port || (isHttps ? 443 : 80),
    path: parsedUrl.pathname + parsedUrl.search,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    },
    timeout,
  };

  return new Promise<OpaDecision>((resolve) => {
    const req = transport.request(requestOptions, (res) => {
      const chunks: Buffer[] = [];

      res.on('data', (chunk: Buffer) => {
        chunks.push(chunk);
      });

      res.on('end', () => {
        const responseBody = Buffer.concat(chunks).toString('utf-8');

        if (res.statusCode !== 200) {
          log.warn(`OPA returned status ${res.statusCode}: ${responseBody.slice(0, 200)}`);
          resolve(failOpenDecision(failOpen, `OPA returned status ${res.statusCode}`));
          return;
        }

        try {
          const parsed = JSON.parse(responseBody) as Record<string, unknown>;
          const decision = parseOpaResponse(parsed);
          log.debug(`OPA decision: allow=${decision.allow}${decision.reason ? ` reason="${decision.reason}"` : ''}`);
          resolve(decision);
        } catch (err) {
          log.warn(`Failed to parse OPA response: ${(err as Error).message}`);
          resolve(failOpenDecision(failOpen, 'Failed to parse OPA response'));
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      log.warn(`OPA request timed out after ${timeout}ms`);
      resolve(failOpenDecision(failOpen, `OPA request timed out after ${timeout}ms`));
    });

    req.on('error', (err: Error) => {
      log.warn(`OPA connection error: ${err.message}`);
      resolve(failOpenDecision(failOpen, `OPA connection error: ${err.message}`));
    });

    req.write(body);
    req.end();
  });
}

/**
 * Check whether a URL points to a private, loopback, or link-local address.
 * Blocks SSRF attempts targeting internal services.
 */
function isPrivateUrl(url: URL): boolean {
  const hostname = url.hostname.toLowerCase();

  if (hostname === 'localhost' || hostname === '[::1]') {
    return true;
  }

  // Strip IPv6 brackets if present
  const bare = hostname.replace(/^\[|\]$/g, '');

  // IPv6 loopback
  if (bare === '::1') return true;

  // IPv6 unique-local (fc00::/7)
  if (/^f[cd][0-9a-f]{2}:/i.test(bare)) return true;

  // IPv4 private/reserved ranges
  const ipv4Match = bare.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [, a, b] = ipv4Match.map(Number);
    // 127.0.0.0/8
    if (a === 127) return true;
    // 10.0.0.0/8
    if (a === 10) return true;
    // 172.16.0.0/12
    if (a === 172 && b! >= 16 && b! <= 31) return true;
    // 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // 169.254.0.0/16 (link-local)
    if (a === 169 && b === 254) return true;
  }

  return false;
}

/**
 * Parse the OPA response into a decision.
 *
 * Supports:
 *   { "result": true }
 *   { "result": { "allow": true, "reason": "..." } }
 */
function parseOpaResponse(response: Record<string, unknown>): OpaDecision {
  const result = response['result'];

  if (typeof result === 'boolean') {
    return { allow: result };
  }

  if (result != null && typeof result === 'object' && !Array.isArray(result)) {
    const obj = result as Record<string, unknown>;
    const allow = obj['allow'];
    if (typeof allow === 'boolean') {
      return {
        allow,
        reason: typeof obj['reason'] === 'string' ? obj['reason'] : undefined,
      };
    }
  }

  // Undefined result means the OPA policy path doesn't exist or returned nothing
  return { allow: false, reason: 'OPA returned no decision' };
}

/**
 * Build a fail-open or fail-closed decision when OPA is unreachable.
 */
function failOpenDecision(failOpen: boolean, errorDetail: string): OpaDecision {
  if (failOpen) {
    log.info(`OPA unreachable, fail-open: allowing (${errorDetail})`);
    return { allow: true, reason: `fail-open: ${errorDetail}` };
  }
  log.warn(`OPA unreachable, fail-closed: denying (${errorDetail})`);
  return { allow: false, reason: `fail-closed: ${errorDetail}` };
}
