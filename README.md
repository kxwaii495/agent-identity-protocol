# Agent Identity Protocol (AIP)

> **The open standard for AI agent authorization.**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/ArangoGutierrez/agent-identity-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/ArangoGutierrez/agent-identity-protocol/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ArangoGutierrez/agent-identity-protocol)](https://goreportcard.com/report/github.com/ArangoGutierrez/agent-identity-protocol)

---

## What is AIP?

AIP is a **protocol specification** for policy-based authorization of AI agent tool calls. It defines how to declare what an agent can do, enforce those policies at runtime, and audit every decision.

AIP works with the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) to add a security layer between AI agents and the tools they use.

---

## Quick Navigation

<table>
<tr>
<td width="50%" valign="top">

### I want to implement AIP in my product

You're building an MCP client (like Cursor, Claude Desktop, or a custom agent runtime) and want to add native AIP support.

**Start here:** [spec/](spec/)

- [AIP Specification v1alpha1](spec/aip-v1alpha1.md) — The protocol definition
- [JSON Schema](spec/schema/agent-policy.schema.json) — For policy validation
- [Conformance Tests](spec/conformance/) — Verify your implementation

</td>
<td width="50%" valign="top">

### I want to use AIP today

You want to protect your MCP servers with policy enforcement right now, using the reference implementation.

**Start here:** [implementations/go-proxy/](implementations/go-proxy/)

- [Go Proxy README](implementations/go-proxy/README.md) — Installation & usage
- [Quickstart](implementations/go-proxy/docs/quickstart.md) — 5-minute tutorial
- [Integration Guide](implementations/go-proxy/docs/integration-guide.md) — Cursor, Claude Desktop

</td>
</tr>
</table>

---

## The Problem

AI agents have **unrestricted access** to powerful tools. When you connect an LLM to your GitHub, database, or cloud infrastructure, there's no policy layer controlling what it can do.

| Threat | What Happens |
|--------|--------------|
| **Prompt Injection** | Malicious instructions in data hijack the agent |
| **Privilege Escalation** | Agent chains accumulate permissions |
| **Data Exfiltration** | Sensitive data leaves through tool calls |
| **Shadow AI** | Agents operate outside security boundaries |

**[Read more →](docs/why-aip.md)**

---

## How AIP Works

```
┌──────────┐     ┌─────────────────┐     ┌──────────────┐
│  Agent   │────▶│   AIP Policy    │────▶│  MCP Server  │
│  (LLM)   │◀────│     Engine      │◀────│   (Tools)    │
└──────────┘     └─────────────────┘     └──────────────┘
                        │
                        ▼
                 ┌─────────────┐
                 │ Audit Log   │
                 └─────────────┘
```

1. **Declare** what the agent can do in a YAML policy
2. **Enforce** policies on every `tools/call` request  
3. **Audit** all decisions in an immutable log

---

## Core Concepts

### Policy File (`agent.yaml`)

```yaml
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: my-agent
spec:
  mode: enforce
  allowed_tools:
    - read_file
    - list_directory
  tool_rules:
    - tool: write_file
      action: ask      # Human approval required
    - tool: exec_command
      action: block    # Never allowed
  dlp:
    patterns:
      - name: "AWS Key"
        regex: "AKIA[A-Z0-9]{16}"
```

### Key Features

| Feature | Description |
|---------|-------------|
| **Tool Allowlist** | Explicit list of permitted tools |
| **Argument Validation** | Regex patterns for tool parameters |
| **Human-in-the-Loop** | Native OS dialogs for approval |
| **DLP Scanning** | Redact secrets from responses |
| **Audit Logging** | Immutable JSONL trail |
| **Monitor Mode** | Test policies without enforcement |

**[Full Policy Reference →](docs/policy-reference.md)**

---

## Repository Structure

```
agent-identity-protocol/
├── spec/                        # THE PROTOCOL
│   ├── aip-v1alpha1.md          # Specification document
│   ├── schema/                  # JSON Schema for validation
│   └── conformance/             # Test suite for implementations
├── implementations/             # IMPLEMENTATIONS
│   └── go-proxy/                # Reference implementation (Go)
│       ├── cmd/aip-proxy/       # Main binary
│       ├── pkg/                 # Libraries
│       ├── examples/            # Example policies
│       └── docs/                # Implementation docs
├── docs/                        # GENERAL DOCS
│   ├── why-aip.md               # Problem statement
│   ├── policy-reference.md      # Policy YAML reference
│   └── faq.md                   # Common questions
└── .github/                     # CI/CD
```

---

## Roadmap

### Specification

- [x] v1alpha1 — Core policy schema, evaluation semantics, error codes
- [ ] v1beta1 — Network egress control, identity federation
- [ ] v1 — Stable release

### Reference Implementation (Go Proxy)

- [x] Tool allowlist enforcement
- [x] Argument validation with regex
- [x] Human-in-the-Loop (macOS, Linux)
- [x] DLP output scanning
- [x] JSONL audit logging
- [x] Monitor mode
- [ ] Kubernetes sidecar
- [ ] Helm chart

### Ecosystem

- [ ] Conformance test runner
- [ ] Policy linter / validator CLI
- [ ] VS Code extension

---

## Documentation

| Document | Description |
|----------|-------------|
| [Why AIP?](docs/why-aip.md) | The problem and threat model |
| [Policy Reference](docs/policy-reference.md) | Complete YAML schema |
| [FAQ](docs/faq.md) | Common questions |
| [AIP Specification](spec/aip-v1alpha1.md) | Formal protocol definition |
| [Go Proxy](implementations/go-proxy/README.md) | Reference implementation |

---

## Contributing

AIP is an open specification. We welcome:

- **Protocol feedback** — Issues and PRs to the spec
- **New implementations** — Build AIP in Rust, TypeScript, etc.
- **Security research** — Threat modeling, attack surface analysis
- **Documentation** — Tutorials, examples, translations

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

Apache 2.0 — See [LICENSE](LICENSE)

Enterprise-friendly. Use it, fork it, build on it.

---

## Security

For vulnerability reports, see [SECURITY.md](SECURITY.md).

---

<p align="center">
  <em>"Trust, but verify — automatically, at every tool call."</em>
</p>
