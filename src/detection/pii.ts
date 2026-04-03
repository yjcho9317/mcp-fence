/**
 * PII (Personally Identifiable Information) detection patterns.
 * Catches personal data that should not appear in MCP tool responses.
 */

import type { DetectionPattern } from './patterns.js';

const piiPatterns: DetectionPattern[] = [
  {
    id: 'PII-001',
    name: 'email_address',
    description: 'Email address detected in response',
    pattern: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/,
    category: 'secret',
    severity: 'medium',
    confidence: 0.65,
    direction: 'response',
    remediation: 'Configure the MCP server to redact email addresses from tool output.',
  },
  {
    id: 'PII-002',
    name: 'phone_number_intl',
    description: 'Phone number detected (international format)',
    pattern: /(?:\+\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}\b/,
    category: 'secret',
    severity: 'medium',
    confidence: 0.55,
    direction: 'response',
    remediation: 'Mask phone numbers in tool responses. Return only the last 4 digits if needed.',
  },
  {
    id: 'PII-003',
    name: 'us_ssn',
    description: 'US Social Security Number detected',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.8,
    direction: 'response',
    remediation: 'SSNs must never appear in tool output. Mask or remove them at the data source.',
  },
  {
    id: 'PII-004',
    name: 'credit_card',
    description: 'Credit card number pattern detected',
    pattern: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}\b/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.8,
    direction: 'response',
    remediation: 'Credit card numbers must be fully redacted. Show only the last 4 digits if needed.',
  },
  {
    id: 'PII-005',
    name: 'ipv4_address',
    description: 'IPv4 address detected in response',
    pattern: /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/,
    category: 'secret',
    severity: 'low',
    confidence: 0.5,
    direction: 'response',
    remediation: 'Avoid exposing internal IP addresses. Use hostnames or redact IPs in tool responses.',
  },
  {
    id: 'PII-006',
    name: 'kr_resident_number',
    description: 'Korean resident registration number (주민등록번호) detected',
    pattern: /\b\d{6}-[1-4]\d{6}\b/,
    category: 'secret',
    severity: 'critical',
    confidence: 0.85,
    direction: 'response',
    remediation: '주민등록번호는 절대 노출되면 안 됩니다. 데이터 소스에서 마스킹 처리하세요.',
  },
  {
    id: 'PII-007',
    name: 'kr_phone_number',
    description: 'Korean phone number detected',
    pattern: /\b01[016789]-?\d{3,4}-?\d{4}\b/,
    category: 'secret',
    severity: 'medium',
    confidence: 0.7,
    direction: 'response',
    remediation: '전화번호는 마스킹 후 노출하세요 (예: 010-****-1234).',
  },
];

export const ALL_PII_PATTERNS: readonly DetectionPattern[] = piiPatterns;

export function getPiiPatternsForDirection(
  direction: 'request' | 'response',
): DetectionPattern[] {
  return ALL_PII_PATTERNS.filter(
    (p) => p.direction === direction || p.direction === 'both',
  );
}
