/**
 * HTTP authentication middleware.
 *
 * Extracts Bearer tokens from the Authorization header and verifies
 * them using the JWT module. Only applies to HTTP transports.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { verifyToken, type JwtConfig } from './jwt.js';
import { createLogger } from '../logger.js';

const log = createLogger('auth:middleware');

export interface AuthResult {
  authenticated: boolean;
  payload?: Record<string, unknown>;
  error?: string;
}

/**
 * Extract the Bearer token from an Authorization header value.
 * Returns null if the header is missing or not a Bearer token.
 */
export function extractBearerToken(authHeader: string | undefined): string | null {
  if (!authHeader) return null;
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return null;
  return parts[1] ?? null;
}

/**
 * Authenticate an HTTP request using JWT.
 * Returns an AuthResult indicating success or failure with error detail.
 */
export async function authenticateRequest(
  req: IncomingMessage,
  config: JwtConfig,
): Promise<AuthResult> {
  const authHeader = req.headers['authorization'];
  const token = extractBearerToken(authHeader);

  if (!token) {
    return { authenticated: false, error: 'missing_token' };
  }

  try {
    const payload = await verifyToken(token, config);
    return { authenticated: true, payload: payload as Record<string, unknown> };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    log.warn(`JWT verification failed: ${message}`);

    if (message.includes('expired') || message.includes('"exp" claim')) {
      return { authenticated: false, error: 'token_expired' };
    }
    if (message.includes('signature')) {
      return { authenticated: false, error: 'invalid_signature' };
    }
    if (message.includes('kid') || message.includes('key')) {
      return { authenticated: false, error: 'unknown_key' };
    }

    return { authenticated: false, error: 'invalid_token' };
  }
}

/**
 * Send a 401 Unauthorized JSON response.
 */
export function sendUnauthorized(res: ServerResponse, error: string): void {
  res.writeHead(401, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error }));
}

/**
 * JWT authentication guard for HTTP handlers.
 * Returns true if the request is authenticated (or JWT is disabled).
 * Returns false and sends 401 if authentication fails.
 */
export async function jwtGuard(
  req: IncomingMessage,
  res: ServerResponse,
  jwtConfig: JwtConfig | undefined,
): Promise<boolean> {
  if (!jwtConfig?.enabled) return true;

  const result = await authenticateRequest(req, jwtConfig);
  if (!result.authenticated) {
    sendUnauthorized(res, result.error ?? 'invalid_token');
    return false;
  }

  return true;
}
