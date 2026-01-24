# Changelog

All notable changes to the Agent Identity Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (Specification v1alpha2)
- **Agent Identity Tokens**: Cryptographic session binding for agent requests
  - `spec.identity.enabled`: Enable token generation
  - `spec.identity.token_ttl`: Configurable token lifetime (default: 5m)
  - `spec.identity.rotation_interval`: Automatic token rotation
  - `spec.identity.require_token`: Enforce token requirement
  - `spec.identity.session_binding`: Binding mode (process/policy/strict)

- **Server-Side Validation**: HTTP endpoints for distributed policy enforcement
  - `spec.server.enabled`: Enable HTTP server
  - `spec.server.listen`: Configurable address/port
  - `spec.server.tls`: TLS configuration for HTTPS
  - `POST /v1/validate`: Policy validation endpoint
  - `GET /health`: Health check endpoint
  - `GET /metrics`: Prometheus metrics export

- **Policy Signing**: Cryptographic integrity verification
  - `metadata.signature`: Ed25519/ECDSA signatures
  - Signature verification before policy application

- **New Error Codes**:
  - `-32008`: Token required but not provided
  - `-32009`: Token validation failed
  - `-32010`: Policy signature invalid

- **New Conformance Levels**:
  - `Identity`: Token lifecycle and validation tests
  - `Server`: HTTP endpoint behavior tests

- **Compatibility with Agentic JWT**: Alignment with IETF draft-goswami-agentic-jwt-00
  - Policy hash as agent checksum
  - Session binding for workflow support

### Changed
- Updated specification from v1alpha1 to v1alpha2
- Added policy hash computation (SHA-256, canonical JSON)
- Extended audit log format with session_id, token_id, policy_hash

### References
- [MCP Authorization (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [Agentic JWT (draft-goswami-agentic-jwt-00)](https://datatracker.ietf.org/doc/html/draft-goswami-agentic-jwt-00)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)

## [0.1.0] - 2026-01-20

### Added
- Comprehensive documentation (architecture, policy reference, integration guide)
- GitHub Actions CI/CD workflows
- GoReleaser configuration for cross-platform builds
- Issue templates (bug report, feature request, security concern)
- Pull request template
- Dependabot configuration for automated dependency updates
- GitHub Copilot instructions for AI-assisted development
- CODEOWNERS file for code review routing
- Labels script for GitHub project management
- Enhanced README with "Sudo for AI" demonstration
- **AIP Proxy**: Core policy enforcement proxy for MCP servers
  - stdin/stdout passthrough for JSON-RPC messages
  - Tool call interception and policy evaluation
  - Graceful subprocess management
  
- **Policy Engine**: Declarative YAML-based policy system
  - `allowed_tools`: Allowlist of permitted tools
  - `tool_rules`: Fine-grained per-tool rules
  - `action: allow | block | ask`: Control tool behavior
  - `allow_args`: Regex-based argument validation
  - `rate_limit`: Per-tool rate limiting
  - `mode: enforce | monitor`: Enforcement vs dry-run mode

- **Human-in-the-Loop**: Native OS prompts for sensitive operations
  - macOS: AppleScript dialogs via `osascript`
  - Linux: `zenity` / `kdialog` support
  - Configurable timeout (default 60s)
  - Fail-closed on timeout

- **DLP Scanner**: Data Loss Prevention for response filtering
  - Configurable regex patterns
  - Content redaction with `[REDACTED:<RuleName>]`
  - Support for MCP content arrays and full-string fallback

- **Audit Logger**: Immutable JSONL audit trail
  - All tool calls logged with decision and context
  - DLP event logging
  - Monitor mode violation tracking

- **CLI**: Command-line interface
  - `--target`: MCP server command
  - `--policy`: Policy file path
  - `--verbose`: Detailed logging
  - `--audit`: Audit log path
  - `--generate-cursor-config`: Cursor IDE integration

- **Example Policies**:
  - `agent.yaml`: Full-featured example
  - `read-only.yaml`: Read-only filesystem access
  - `monitor-mode.yaml`: Dry-run testing
  - `gemini-jack-defense.yaml`: Prompt injection defense
  - `agent-monitor.yaml`: Monitoring configuration

### Security
- Fail-closed design: Unknown tools denied by default
- Zero-trust: Every tool call evaluated
- Least privilege: Explicit capability declaration
- Audit trail: Immutable logging for compliance

---

## Versioning

- **Major version (X.0.0)**: Breaking changes to policy schema or CLI
- **Minor version (0.X.0)**: New features, backward-compatible
- **Patch version (0.0.X)**: Bug fixes, no API changes

## Links

- [GitHub Releases](https://github.com/ArangoGutierrez/agent-identity-protocol/releases)
- [Documentation](https://github.com/ArangoGutierrez/agent-identity-protocol#readme)
- [Contributing](CONTRIBUTING.md)
