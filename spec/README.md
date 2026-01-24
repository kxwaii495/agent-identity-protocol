# AIP Specification

This directory contains the formal specification for the Agent Identity Protocol (AIP).

## Documents

| Document | Description |
|----------|-------------|
| [aip-v1alpha2.md](aip-v1alpha2.md) | **Current** - Full protocol specification (v1alpha2) |
| [aip-v1alpha1.md](aip-v1alpha1.md) | Previous version (v1alpha1) |
| [schema/agent-policy-v1alpha2.schema.json](schema/agent-policy-v1alpha2.schema.json) | JSON Schema for v1alpha2 policy validation |
| [schema/agent-policy.schema.json](schema/agent-policy.schema.json) | JSON Schema for v1alpha1 (deprecated) |
| [conformance/](conformance/) | Conformance test suite |

## Version

**Current Version:** `aip.io/v1alpha2` (Draft)

This is an alpha specification. Breaking changes may occur before v1.

### Version History

| Version | Date | Changes |
|---------|------|---------|
| v1alpha2 | 2026-01-24 | Agent identity tokens, server-side validation, policy signing |
| v1alpha1 | 2026-01-20 | Initial specification |

### New in v1alpha2

- **Agent Identity**: Token-based session management with automatic rotation
- **Server-Side Validation**: HTTP endpoints for distributed policy enforcement
- **Policy Signing**: Cryptographic integrity verification
- **Compatibility**: Alignment with MCP Authorization (2025-06-18) and Agentic JWT

## For Implementers

If you are implementing AIP in a new runtime:

1. **Read the spec**: Start with [aip-v1alpha2.md](aip-v1alpha2.md)
2. **Validate schemas**: Use the JSON Schema to validate policy files
3. **Pass conformance tests**: Run the [conformance suite](conformance/) against your implementation
4. **Report issues**: File issues if you find ambiguities or errors

### Implementation Guidance

- **Start with Basic+Full**: Implement core authorization first
- **Add Identity**: Token management is recommended for production
- **Server is optional**: HTTP endpoints for distributed deployments

## Conformance Levels

| Level | Description | Required Tests | API Version |
|-------|-------------|----------------|-------------|
| **Basic** | Minimum viable implementation | `conformance/basic/*` | v1alpha1+ |
| **Full** | Complete feature support | Basic + `conformance/full/*` | v1alpha1+ |
| **Extended** | Human-in-the-loop support | Full + `conformance/extended/*` | v1alpha1+ |
| **Identity** | Token lifecycle management | Extended + `conformance/identity/*` | v1alpha2+ |
| **Server** | HTTP validation endpoints | Identity + `conformance/server/*` | v1alpha2+ |

## Schema Validation

Validate a policy file against the JSON Schema:

```bash
# Using ajv-cli (v1alpha2)
npm install -g ajv-cli
ajv validate -s spec/schema/agent-policy-v1alpha2.schema.json -d your-policy.yaml

# Using Python jsonschema (v1alpha2)
pip install jsonschema pyyaml
python -c "
import yaml, jsonschema, json
schema = json.load(open('spec/schema/agent-policy-v1alpha2.schema.json'))
policy = yaml.safe_load(open('your-policy.yaml'))
jsonschema.validate(policy, schema)
print('Valid!')
"
```

For v1alpha1 policies, use `agent-policy.schema.json` instead.

## Contributing

To propose changes to the specification:

1. Open an issue describing the change
2. Submit a PR with spec updates
3. Include test vectors for new behavior
4. Update the changelog in the spec document

## Reference Implementation

The Go proxy in [`implementations/go-proxy/`](../implementations/go-proxy/) is the reference implementation of this specification. It demonstrates:

- Policy loading and evaluation
- Unicode normalization (NFKC)
- All error codes
- DLP scanning
- Audit logging

Use it as a guide when building your own implementation.

## Registered Implementations

| Implementation | Language | Conformance | Maintainer |
|----------------|----------|-------------|------------|
| [go-proxy](../implementations/go-proxy/) | Go | Full + Extended | @ArangoGutierrez |

*To register your implementation, submit a PR after passing the conformance suite.*

## License

The specification is licensed under Apache 2.0, same as the reference implementation.
