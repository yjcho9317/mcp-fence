# mcp-fence

**The bidirectional firewall for MCP** -- scans inputs AND outputs, detects rug-pulls at runtime, zero config.

[![npm version](https://img.shields.io/npm/v/mcp-fence)](https://www.npmjs.com/package/mcp-fence)
[![license](https://img.shields.io/npm/l/mcp-fence)](./LICENSE)
[![node](https://img.shields.io/node/v/mcp-fence)](https://nodejs.org/)
[![OWASP MCP](https://img.shields.io/badge/OWASP%20MCP%20Top%2010-9%2F10-blue)](#owasp-mcp-top-10-coverage)

---

## Why mcp-fence?

Most MCP security tools only inspect what goes **in** to a server. That misses half the attack surface.

- **Bidirectional scanning** -- Inspects both requests and responses. A compromised server can inject instructions in its output; mcp-fence catches that.
- **Rug-pull detection** -- Pins tool descriptions by hash at first approval. If a server silently changes what a tool does at runtime, mcp-fence flags it immediately.
- **Zero config** -- Works out of the box with secure defaults (monitor mode). No YAML required to get started.

---

## Quick Start

### stdio (default)

```bash
# Install globally
npm install -g mcp-fence

# Proxy any MCP server
mcp-fence start -- npx @anthropic/mcp-server-filesystem /tmp
```

Or run without installing:

```bash
npx mcp-fence start -- npx @anthropic/mcp-server-filesystem /tmp
```

### SSE / Streamable HTTP

```bash
# Proxy a remote MCP server over SSE
mcp-fence start --transport sse --upstream http://localhost:8080 --port 3000

# Streamable HTTP with JWT authentication
MCP_FENCE_JWT_SECRET=my-secret mcp-fence start \
  --transport http --upstream http://localhost:8080 --port 3000
```

That's it. mcp-fence sits between your MCP client and server, logging every suspicious finding to stderr and an SQLite audit trail at `~/.mcp-fence/audit.db`.

### Claude Desktop Integration

Add mcp-fence as a wrapper in your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "mcp-fence",
        "start",
        "--mode", "enforce",
        "--",
        "npx", "@anthropic/mcp-server-filesystem", "/tmp"
      ]
    }
  }
}
```

Your MCP server works exactly as before. mcp-fence just inspects traffic passing through.

---

## Features

| Feature | Description |
|---------|-------------|
| **Bidirectional scanning** | Scans both client requests and server responses for threats |
| **Prompt injection detection** | 20+ regex patterns covering instruction override, role hijacking, hidden instructions, multi-language attacks |
| **Secret leak detection** | 25+ patterns for AWS keys, GitHub tokens, private keys, connection strings, and more |
| **PII detection** | 7 patterns covering email, phone, SSN, credit card, IPv4, Korean resident ID (주민번호), Korean phone numbers |
| **Rug-pull detection** | SHA-256 hash pinning of tool descriptions, persisted to SQLite. Detects silent modification after initial approval |
| **Server schema pinning** | TOFU-based pinning of server tool schemas. Detects schema drift across restarts |
| **Context budget** | Configurable max response size (bytes) with warn/truncate/block actions to prevent context window flooding |
| **Policy engine** | Tool-level allow/deny rules with glob patterns and argument validation |
| **OPA integration** | External policy decisions via Open Policy Agent with SSRF protection and fail-closed defaults |
| **Data flow policies** | Cross-server session-level tool call tracking with from/to rules |
| **JWT authentication** | HS256, RS256, and JWKS key rotation for SSE/HTTP transports. Secret via `MCP_FENCE_JWT_SECRET` env var |
| **SSE + Streamable HTTP** | Full transport support beyond stdio -- proxy remote MCP servers over HTTP |
| **Audit logging** | SQLite-backed event log with queryable CLI |
| **Secret masking** | Secrets in audit logs are masked before storage -- the DB never contains plain-text credentials |
| **HMAC hash chain** | Audit log tamper detection via HMAC-SHA256 chain with `verify` CLI command |
| **DB size limits** | Automatic pruning when the audit database exceeds the configured size limit |
| **SARIF output** | Export findings in SARIF format for GitHub Security tab integration |
| **Remediation guidance** | Every finding includes actionable remediation advice |
| **Zero-config defaults** | Monitor mode out of the box -- logs threats without blocking, so you never break a working setup |

### Limitations

Detection is regex-based. It handles known patterns well but won't catch novel prompt injection via paraphrase or synonyms. ML-based semantic detection is planned for v1.x.

---

## OWASP MCP Top 10 Coverage

| ID | Risk | v1.0 | How |
|----|------|:----:|-----|
| MCP01 | Token/Secret Exposure | Yes | Secret pattern detection + audit log masking |
| MCP02 | Tool Poisoning | Yes | Tool description hash pinning (rug-pull detection) |
| MCP03 | Excessive Permissions | Yes | Policy engine with tool allow/deny + argument constraints |
| MCP04 | Command Injection | Yes | Command injection patterns in detection engine |
| MCP05 | Insecure Data Handling | Yes | Secret masking, HMAC integrity chain, DB size limits |
| MCP06 | Insufficient Logging | Yes | SQLite audit log + SARIF export + HMAC tamper detection |
| MCP07 | Insufficient Auth | Yes | JWT authentication (HS256/RS256/JWKS) for HTTP transports + policy enforcement |
| MCP08 | Server Spoofing | Yes | Server schema TOFU pinning (SRV-001, SRV-002, SRV-003) |
| MCP09 | Supply Chain Compromise | Partial | Runtime behavior inspection catches post-compromise exfiltration; no package-level verification |
| MCP10 | Context Injection | Yes | Context budget (maxResponseBytes, warn/truncate/block) + bidirectional injection scanning |

---

## Configuration

Generate a config file:

```bash
mcp-fence init
```

This creates `fence.config.yaml`:

```yaml
# Operation mode: "monitor" (log only) or "enforce" (block threats)
mode: monitor

log:
  level: info
  # file: ./mcp-fence.log  # uncomment to log to file

detection:
  warnThreshold: 0.5    # score >= 0.5 triggers a warning
  blockThreshold: 0.8   # score >= 0.8 triggers a block (enforce mode only)
  maxInputSize: 10240   # bytes — inputs larger than this are truncated

policy:
  defaultAction: allow
  rules:
    - tool: "exec_cmd"
      action: deny
    - tool: "read_file"
      action: allow
      args:
        - name: path
          denyPattern: "^\\.env$|^/etc/"
    - tool: "write_*"
      action: deny
  # opa:
  #   enabled: true
  #   url: "http://localhost:8181/v1/data/mcp/allow"
  #   timeoutMs: 5000
  #   failOpen: false

# jwt:
#   enabled: true
#   audience: "mcp-fence"
#   issuer: "my-auth-server"
#   # secret comes from MCP_FENCE_JWT_SECRET env var
#   # jwksUrl: "https://auth.example.com/.well-known/jwks.json"

# dataFlow:
#   enabled: true
#   rules:
#     - from: "read_file"
#       to: "send_email"
#       action: deny

# contextBudget:
#   enabled: true
#   maxResponseBytes: 102400
#   truncateAction: warn  # warn | truncate | block
```

Config priority: **CLI flags > environment variables > YAML file > defaults**.

Environment variables:

| Variable | Values | Description |
|----------|--------|-------------|
| `MCP_FENCE_MODE` | `monitor`, `enforce` | Operation mode |
| `MCP_FENCE_LOG_LEVEL` | `debug`, `info`, `warn`, `error` | Log verbosity |
| `MCP_FENCE_JWT_SECRET` | string | Shared secret for HS256 JWT authentication |

---

## CLI Commands

### `start` -- Run the security proxy

```bash
# stdio (default) — spawns server as child process
mcp-fence start -- npx @anthropic/mcp-server-filesystem /tmp

# With options
mcp-fence start --mode enforce --config ./fence.config.yaml -- node my-server.js

# SSE transport — proxy a remote server
mcp-fence start --transport sse --upstream http://localhost:8080 --port 3000

# Streamable HTTP with JWKS authentication
mcp-fence start --transport http --upstream http://localhost:8080 --jwks-url https://auth.example.com/.well-known/jwks.json
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config <path>` | | Path to config file |
| `-m, --mode <mode>` | `monitor` | Operation mode: `monitor` or `enforce` |
| `--log-level <level>` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `-t, --transport <type>` | `stdio` | Transport: `stdio`, `sse`, `http` |
| `-p, --port <port>` | `3000` | Listen port for SSE/HTTP transport |
| `-u, --upstream <url>` | | Upstream MCP server URL (required for `sse`/`http`) |
| `--jwks-url <url>` | | JWKS endpoint for RS256 JWT key rotation |

### `init` -- Generate default config

```bash
mcp-fence init
mcp-fence init --output ./custom-config.yaml
```

### `scan` -- Standalone threat scan (no proxy needed)

```bash
# Scan a file
mcp-fence scan ./suspicious-prompt.txt

# Scan inline text
mcp-fence scan --text "ignore all previous instructions"

# Scan server responses
mcp-fence scan ./response.json --direction response

# Output as JSON or SARIF
mcp-fence scan ./file.txt --format json
mcp-fence scan ./file.txt --format sarif > results.sarif
```

### `logs` -- Query the audit trail

```bash
# Recent warnings
mcp-fence logs --since 1h --level warn

# Export to SARIF for GitHub
mcp-fence logs --format sarif > audit.sarif

# Filter by direction
mcp-fence logs --direction response --limit 50
```

### `verify` -- Verify audit log integrity

```bash
mcp-fence verify
```

Checks the HMAC hash chain in the audit database. Reports whether the chain is intact or identifies the first tampered event.

### `status` -- Show config and capabilities

```bash
mcp-fence status
mcp-fence status --config ./fence.config.yaml
```

---

## Architecture

```
                        mcp-fence
                  ┌─────────────────────┐
[MCP Client] ──> │  1. Detection Engine │ ──> [MCP Server]
          stdio / │  2. Hash Pin Check   │ stdio / SSE /
          SSE /   │  3. Policy Engine    │ Streamable HTTP
          HTTP    │  4. Context Budget   │
[MCP Client] <── │  5. Audit Logger     │ <── [MCP Server]
                  └─────────────────────┘
                           │
                     [SQLite Audit DB]
```

Every message flows through the same pipeline:

1. **Intercept** -- Proxy captures the JSON-RPC message (request or response).
2. **Detect** -- Detection engine runs injection, secret, PII, and command-injection patterns against the message content.
3. **Pin check** -- For `tools/list` responses, hash-pins tool descriptions and schemas, flags any changes.
4. **Policy** -- Policy engine evaluates tool-level allow/deny rules, argument constraints, OPA decisions, and data flow rules.
5. **Context budget** -- For responses, checks size against configured limits and applies warn/truncate/block.
6. **Audit** -- Every scan result is logged to SQLite with timestamp, direction, decision, and findings.
7. **Forward or block** -- In monitor mode, everything passes through (findings are logged). In enforce mode, messages exceeding the block threshold are rejected.

Modules are decoupled: detection doesn't import policy, audit doesn't import detection. The proxy orchestrates all communication between them through the `ScanResult` contract.

---

## Programmatic Usage

mcp-fence can be used as a library in your own Node.js applications:

```typescript
import {
  McpProxy,
  DetectionEngine,
  HashPinChecker,
  MemoryHashStore,
  PolicyEngine,
  AuditLoggerImpl,
  SqliteAuditStore,
  loadConfig,
} from 'mcp-fence';

const config = loadConfig('./fence.config.yaml');

const proxy = new McpProxy({
  serverCommand: 'npx',
  serverArgs: ['@anthropic/mcp-server-filesystem', '/tmp'],
  config,
  scanner: new DetectionEngine(config.detection),
  hashPinChecker: new HashPinChecker(new MemoryHashStore()),
  policyEngine: new PolicyEngine(config.policy),
  auditLogger: new AuditLoggerImpl(new SqliteAuditStore('./audit.db')),
});

await proxy.start();
```

You can also use the detection engine standalone:

```typescript
import { DetectionEngine, DEFAULT_CONFIG } from 'mcp-fence';

const engine = new DetectionEngine(DEFAULT_CONFIG.detection);

const result = await engine.scan(
  { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { path: '/etc/passwd' } } },
  'request'
);

console.log(result.decision); // 'allow' | 'warn' | 'block'
console.log(result.findings); // Finding[]
```

---

## Roadmap

| Version | Focus | Status |
|---------|-------|--------|
| **v0.1** | stdio proxy, bidirectional scanning, secret detection, hash pinning, policy engine, SQLite audit, SARIF, CLI | Done |
| **v0.2** | Audit log hardening (secret masking, HMAC integrity, DB size limits, `verify` command), Unicode normalization | Done |
| **v0.3** | SSE + Streamable HTTP transport, JWT authentication, OPA integration, cross-server data flow policies | Done |
| **v0.4** | Server schema TOFU pinning, context budget (maxResponseBytes), SQLite-persisted hash pins | Done |
| **v1.0** | PII detection (7 patterns), remediation guidance, 9 security hardening fixes | Current |
| **v1.x** | ML-based semantic detection (embedding similarity), session-level multi-step analysis | Planned |

---

## Contributing

Contributions are welcome. Please open an issue before submitting large changes so we can discuss the approach.

```bash
git clone https://github.com/user/mcp-fence.git
cd mcp-fence
npm install
npm test          # run tests
npm run typecheck # type checking
npm run lint      # lint
```

Security-critical modules (`src/detection/`, `src/integrity/`, `src/policy/local.ts`) require manual review on every PR. No exceptions.

---

## License

[MIT](./LICENSE)
