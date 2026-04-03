/**
 * Injection detection patterns for mcp-fence.
 *
 * Each pattern targets a specific attack vector observed in MCP environments.
 * Patterns are grouped by category and assigned severity/confidence levels
 * based on false-positive likelihood.
 *
 * ReDoS defense: all regex patterns avoid nested quantifiers and unbounded repetition.
 * Input is truncated to maxInputSize (default 10KB) before matching.
 */

import type { FindingCategory } from '../types.js';

export interface DetectionPattern {
  /** Unique rule identifier (e.g., INJ-001) */
  id: string;
  /** Human-readable name */
  name: string;
  /** What this pattern catches */
  description: string;
  /** Regex to match against text content */
  pattern: RegExp;
  /** Finding category */
  category: FindingCategory;
  /** Severity when matched */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Base confidence score (0.0 ~ 1.0) */
  confidence: number;
  /** Which scan direction this pattern applies to */
  direction: 'request' | 'response' | 'both';
  /** Guidance on how to fix the issue */
  remediation?: string;
}

// ─── Prompt Injection Patterns ───
//
// MCP에서 프롬프트 인젝션은 tool arguments나 tool output에 숨겨진 지시문으로 나타난다.
// AI 에이전트가 이 텍스트를 처리할 때, 원래 사용자의 의도와 다른 행동을 유도한다.

const injectionPatterns: DetectionPattern[] = [
  {
    id: 'INJ-001',
    name: 'instruction_override',
    description: 'Attempts to override system/user instructions',
    pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|guidelines?)/i,
    category: 'injection',
    severity: 'critical',
    confidence: 0.95,
    direction: 'both',
    remediation: 'Review the tool arguments for instruction override attempts. If legitimate, add the tool to the policy allowlist.',
  },
  {
    id: 'INJ-002',
    name: 'role_hijacking',
    description: 'Attempts to assume a different AI role',
    pattern: /you\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\s+/i,
    category: 'injection',
    severity: 'high',
    confidence: 0.8,
    direction: 'both',
    remediation: 'Inspect tool output for role reassignment language. Block the tool or sanitize its output before passing to the AI agent.',
  },
  {
    id: 'INJ-003',
    name: 'system_prompt_injection',
    description: 'Injects fake system-level instructions',
    pattern: /\[?\s{0,20}(?:SYSTEM|ADMIN|ASSISTANT)\s+(?:PROMPT|MESSAGE|INSTRUCTION|NOTE)\b/i,
    category: 'injection',
    severity: 'critical',
    confidence: 0.9,
    direction: 'both',
    remediation: 'Check for fake system prompt markers in tool arguments or responses. Block the message and audit the originating tool.',
  },
  {
    id: 'INJ-004',
    name: 'delimiter_escape',
    description: 'Uses common delimiters to break out of context',
    pattern: /(?:<\/?(?:system|user|assistant|human|ai|context|instruction)>)/i,
    category: 'injection',
    severity: 'high',
    confidence: 0.85,
    direction: 'both',
    remediation: 'Strip or escape XML-like role delimiters from tool arguments and responses before they reach the AI agent.',
  },
  {
    id: 'INJ-013',
    name: 'llm_chat_template_markers',
    description: 'LLM chat template markers used to inject system-level instructions',
    pattern: /(?:<\|im_start\|>|<\|im_end\|>|<\|begin_of_text\|>|<\|start_header_id\|>|\[INST\]|\[\/INST\]|<<SYS>>|<<\/SYS>>)/,
    category: 'injection',
    severity: 'high',
    confidence: 0.88,
    direction: 'both',
    remediation: 'Remove LLM chat template markers from tool content. These tokens can hijack model behavior when passed through as text.',
  },
  {
    id: 'INJ-005',
    name: 'instruction_boundary',
    description: 'Attempts to create fake instruction boundaries',
    pattern: /(?:={3,}|-{3,}|\*{3,})\s*(?:NEW|BEGIN|START|END)\s+(?:INSTRUCTION|SYSTEM|PROMPT|CONVERSATION)/i,
    category: 'injection',
    severity: 'high',
    confidence: 0.85,
    direction: 'both',
    remediation: 'Strip visual boundary markers from tool content. Attackers use these to simulate instruction resets.',
  },
  {
    id: 'INJ-006',
    name: 'do_anything_now',
    description: 'DAN-style jailbreak attempts',
    pattern: /(?:DAN|Do\s+Anything\s+Now|developer\s+mode|god\s+mode)\s*(?:enabled|activated|mode|:)/i,
    category: 'injection',
    severity: 'critical',
    confidence: 0.9,
    direction: 'both',
    remediation: 'Block the message immediately. DAN-style jailbreaks attempt to remove all safety guardrails from the AI agent.',
  },
  {
    id: 'INJ-007',
    name: 'output_manipulation',
    description: 'Attempts to control AI output format or behavior',
    pattern: /(?:respond|reply|answer|output)\s+(?:(?:only|exactly)\s+)?(?:with|as|exactly)\s+(?:the\s+following|"[^"]*"|yes|no|true|false)/i,
    category: 'injection',
    severity: 'medium',
    confidence: 0.7,
    direction: 'both',
    remediation: 'Review if the tool output is attempting to dictate AI responses. Consider adding the tool to a restricted policy group.',
  },
  {
    id: 'INJ-008',
    name: 'hidden_text_markers',
    description: 'Uses invisible or hidden text markers to smuggle instructions',
    pattern: /<!--[\s\S]{0,500}?(?:SYSTEM|ignore|instruction|execute|override)[\s\S]{0,500}?-->/i,
    category: 'injection',
    severity: 'critical',
    confidence: 0.92,
    direction: 'response',
    remediation: 'Strip HTML comments from tool responses before passing to the AI agent. Hidden comments are a common injection vector.',
  },
  {
    id: 'INJ-009',
    name: 'base64_encoded_instruction',
    description: 'Suspicious base64-encoded content that may hide instructions',
    pattern: /(?:decode|base64|atob)\s*\(\s*['"][A-Za-z0-9+/=]{40,}['"]\s*\)/i,
    category: 'injection',
    severity: 'medium',
    confidence: 0.65,
    direction: 'both',
    remediation: 'Decode and inspect base64 content before allowing it through. Base64 encoding is used to bypass text-based detection.',
  },
  {
    id: 'INJ-010',
    name: 'tool_call_injection',
    description: 'Attempts to make AI call specific tools through injected text',
    pattern: /(?:please\s+)?(?:use|call|invoke|execute|run)\s+(?:the\s+)?(?:tool|function|command)\s+['"`]?\w+['"`]?/i,
    category: 'injection',
    severity: 'high',
    confidence: 0.75,
    direction: 'response',
    remediation: 'Block tool responses that instruct the AI to invoke other tools. This is a tool-call injection targeting agent autonomy.',
  },
  {
    id: 'INJ-011',
    name: 'persona_switch',
    description: 'Attempts to switch AI persona or behavior mode',
    pattern: /(?:switch|change|enter|activate)\s+(?:to\s+)?(?:unrestricted|unfiltered|uncensored|jailbreak|evil)\s+mode/i,
    category: 'injection',
    severity: 'critical',
    confidence: 0.92,
    direction: 'both',
    remediation: 'Block immediately. Persona switch attempts try to disable safety mechanisms in the AI agent.',
  },
  {
    id: 'INJ-012',
    name: 'multi_language_evasion',
    description: 'Uses non-English instruction patterns to evade detection',
    pattern: /(?:忽略|忽略所有|无视|이전.*무시|指示を無視|ignorez|ignorieren|ignora las instrucciones anteriores|ignore as instrucoes anteriores|игнорируй предыдущие инструкции|ignora le istruzioni precedenti|önceki talimatları yoksay)(?:\s|$)/i,
    category: 'injection',
    severity: 'high',
    confidence: 0.8,
    direction: 'both',
    remediation: 'Non-English instruction override detected. Apply the same blocking policy as English-language injection attempts.',
  },
];

// ─── Command Injection Patterns ───
//
// MCP 서버가 tool arguments를 쉘 명령어로 실행하는 경우,
// arguments에 쉘 메타문자를 넣어 임의 명령 실행이 가능하다.
// OWASP MCP04: Command Injection.

const commandInjectionPatterns: DetectionPattern[] = [
  {
    id: 'CMD-001',
    name: 'shell_metachar',
    description: 'Shell metacharacters in tool arguments',
    pattern: /[;&|`$\n]\s*(?:\/[\w/]*\/)?(?:rm|cat|curl|wget|nc|ncat|bash|sh|python|perl|ruby|php|node|chmod|chown|dd|powershell|cmd\.exe|socat|tee|xargs)\b/i,
    category: 'command-injection',
    severity: 'critical',
    confidence: 0.9,
    direction: 'request',
    remediation: 'Sanitize tool arguments by escaping shell metacharacters. Use allowlists for permitted commands instead of blocklists.',
  },
  {
    id: 'CMD-002',
    name: 'command_substitution',
    description: 'Shell command substitution attempts',
    pattern: /\$\(\s*\w+|`\s*\w+\s*`/,
    category: 'command-injection',
    severity: 'critical',
    confidence: 0.85,
    direction: 'request',
    remediation: 'Reject arguments containing $() or backtick substitution. Pass arguments as array elements, not shell strings.',
  },
  {
    id: 'CMD-003',
    name: 'path_traversal',
    description: 'Directory traversal attempts',
    pattern: /(?:\.\.\/){2,}|\.\.\\(?:\.\.\\)+/,
    category: 'command-injection',
    severity: 'high',
    confidence: 0.85,
    direction: 'request',
    remediation: 'Resolve file paths to canonical form and verify they stay within the allowed directory. Use chroot or path allowlists.',
  },
  {
    id: 'CMD-004',
    name: 'sensitive_file_access',
    description: 'Attempts to access sensitive system files',
    pattern: /(?:\/etc\/(?:passwd|shadow|hosts|sudoers)|\/proc\/self|~\/\.ssh|~\/\.aws|~\/\.kube\/config|~\/\.docker\/config\.json|~\/\.npmrc|~\/\.gnupg\/|credentials\.json|service-account\.json|\.env\b)/i,
    category: 'command-injection',
    severity: 'critical',
    confidence: 0.9,
    direction: 'request',
    remediation: 'Deny access to sensitive system paths. Configure a file access allowlist in the MCP server and restrict to project directories.',
  },
  {
    id: 'CMD-005',
    name: 'pipe_chain',
    description: 'Suspicious pipe chains that may exfiltrate data',
    pattern: /\|\s*(?:\/[\w/]*\/)?(?:curl|wget|nc|ncat|bash|sh|python|perl|ruby|socat|tee|xargs)\b/i,
    category: 'command-injection',
    severity: 'critical',
    confidence: 0.88,
    direction: 'request',
    remediation: 'Block pipe chains to network tools. If the MCP server needs outbound access, use a network allowlist.',
  },
  {
    id: 'CMD-006',
    name: 'reverse_shell',
    description: 'Reverse shell patterns',
    pattern: /(?:\/dev\/tcp\/|mkfifo|nc\s+-[a-z]*e|bash\s+-i\s+>&)/i,
    category: 'command-injection',
    severity: 'critical',
    confidence: 0.95,
    direction: 'request',
    remediation: 'Block immediately and alert. Reverse shell attempts indicate active exploitation. Audit all recent tool calls.',
  },
];

// ─── Data Exfiltration Patterns ───
//
// AI 에이전트가 tool output(파일 내용, DB 결과 등)을 외부로 전송하도록
// 유도하는 패턴. 주로 응답에 숨겨진 인젝션이 트리거한다.

const exfiltrationPatterns: DetectionPattern[] = [
  {
    id: 'EXF-001',
    name: 'url_data_exfil',
    description: 'Data exfiltration via URL embedding',
    pattern: /(?:https?:\/\/)[^\s/]+\/[^\s]*(?:exfil|steal|leak|upload|collect)[^\s]*/i,
    category: 'data-exfiltration',
    severity: 'high',
    confidence: 0.75,
    direction: 'both',
    remediation: 'Block URLs containing exfiltration keywords. Configure an outbound domain allowlist for the MCP server.',
  },
  {
    id: 'EXF-002',
    name: 'markdown_image_exfil',
    description: 'Data exfiltration via markdown image tags with dynamic URLs',
    pattern: /!\[.*?\]\(https?:\/\/[^\s)]*\?[^\s)]*(?:data|token|key|secret|password|content)=[^\s)]*\)/i,
    category: 'data-exfiltration',
    severity: 'critical',
    confidence: 0.85,
    direction: 'response',
    remediation: 'Strip or block markdown images with query parameters in tool responses. These can exfiltrate data via image load requests.',
  },
  {
    id: 'EXF-003',
    name: 'send_to_external',
    description: 'Instructions to send data to external services',
    pattern: /(?:send|post|upload|transmit|forward)\s+(?:this|the|all|that)\s+(?:data|content|information|file|output|result)\s+to\s+/i,
    category: 'data-exfiltration',
    severity: 'high',
    confidence: 0.78,
    direction: 'both',
    remediation: 'Block instructions that direct the AI to transmit data externally. Review the originating tool for injection vulnerabilities.',
  },
  {
    id: 'EXF-005',
    name: 'html_image_exfil',
    description: 'Data exfiltration via HTML img tags with dynamic URLs',
    pattern: /<img\s[^>]*src\s*=\s*["']https?:\/\/[^"']*\?[^"']*(?:data|token|key|secret|password|content)=[^"']*["']/i,
    category: 'data-exfiltration',
    severity: 'critical',
    confidence: 0.85,
    direction: 'response',
    remediation: 'Sanitize HTML in tool responses. Remove img tags with query parameters that could encode sensitive data.',
  },
  {
    id: 'EXF-006',
    name: 'markdown_link_exfil',
    description: 'Data exfiltration via markdown links with query parameters',
    pattern: /\[[^\]]*\]\(https?:\/\/[^\s)]*\?[^\s)]*(?:data|token|key|secret|password|content)=[^\s)]*\)/i,
    category: 'data-exfiltration',
    severity: 'high',
    confidence: 0.8,
    direction: 'response',
    remediation: 'Strip markdown links with sensitive query parameters from tool responses before they reach the AI agent.',
  },
  {
    id: 'EXF-004',
    name: 'dns_exfil',
    description: 'DNS-based data exfiltration patterns',
    pattern: /(?:nslookup|dig|host)\s+[^\s]*\.\w+\.\w{2,}/i,
    category: 'data-exfiltration',
    severity: 'high',
    confidence: 0.82,
    direction: 'request',
    remediation: 'Block DNS lookup tool arguments. DNS exfiltration encodes data in subdomain queries to bypass network controls.',
  },
];

/** All detection patterns, combined. */
export const ALL_PATTERNS: readonly DetectionPattern[] = [
  ...injectionPatterns,
  ...commandInjectionPatterns,
  ...exfiltrationPatterns,
];

/**
 * Get patterns applicable to a given direction.
 */
export function getPatternsForDirection(
  direction: 'request' | 'response',
): DetectionPattern[] {
  return ALL_PATTERNS.filter(
    (p) => p.direction === direction || p.direction === 'both',
  );
}
