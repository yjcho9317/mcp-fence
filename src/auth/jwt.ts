/**
 * JWT token verification for HTTP transports.
 *
 * Supports HS256 (shared secret) and RS256 (JWKS URL) algorithms.
 * Uses the `jose` library for standards-compliant JWT verification.
 */

import * as jose from 'jose';
import { createLogger } from '../logger.js';

const log = createLogger('auth:jwt');

export interface JwtConfig {
  enabled: boolean;
  /** Shared secret for HS256 */
  secret?: string;
  /** JWKS endpoint URL for RS256 key rotation */
  jwksUrl?: string;
  /** Expected audience claim */
  audience?: string;
  /** Expected issuer claim */
  issuer?: string;
}

export interface JwtPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  [key: string]: unknown;
}

let cachedJwksUrl: string | null = null;
let cachedJwks: ReturnType<typeof jose.createRemoteJWKSet> | null = null;

/**
 * Verify a JWT token against the provided configuration.
 * Determines algorithm based on which config fields are present:
 * - secret -> HS256
 * - jwksUrl -> RS256 via JWKS
 */
export async function verifyToken(token: string, config: JwtConfig): Promise<JwtPayload> {
  const verifyOptions: jose.JWTVerifyOptions = {};

  if (config.audience) {
    verifyOptions.audience = config.audience;
  }
  if (config.issuer) {
    verifyOptions.issuer = config.issuer;
  }

  if (config.secret) {
    return verifyWithSecret(token, config.secret, verifyOptions);
  }

  if (config.jwksUrl) {
    return verifyWithJwks(token, config.jwksUrl, verifyOptions);
  }

  throw new Error('JWT config must specify either secret (HS256) or jwksUrl (RS256)');
}

async function verifyWithSecret(
  token: string,
  secret: string,
  options: jose.JWTVerifyOptions,
): Promise<JwtPayload> {
  const key = new TextEncoder().encode(secret);
  const { payload } = await jose.jwtVerify(token, key, {
    ...options,
    algorithms: ['HS256'],
  });
  return payload as JwtPayload;
}

async function verifyWithJwks(
  token: string,
  jwksUrl: string,
  options: jose.JWTVerifyOptions,
): Promise<JwtPayload> {
  if (cachedJwksUrl !== jwksUrl) {
    cachedJwks = jose.createRemoteJWKSet(new URL(jwksUrl));
    cachedJwksUrl = jwksUrl;
  }
  const { payload } = await jose.jwtVerify(token, cachedJwks!, {
    ...options,
    algorithms: ['RS256'],
  });
  return payload as JwtPayload;
}

export function resetJwksCache(): void {
  cachedJwks = null;
  cachedJwksUrl = null;
}
