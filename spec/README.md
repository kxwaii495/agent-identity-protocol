# AIP Specification

This directory contains the formal specification for the Agent Identity Protocol (AIP).

## Documents

| Document | Description |
|----------|-------------|
| [aip-v1alpha1.md](aip-v1alpha1.md) | Full protocol specification |
| [schema/agent-policy.schema.json](schema/agent-policy.schema.json) | JSON Schema for policy validation |
| [conformance/](conformance/) | Conformance test suite |

## Version

**Current Version:** `aip.io/v1alpha1` (Draft)

This is an alpha specification. Breaking changes may occur before v1.

## For Implementers

If you are implementing AIP in a new runtime:

1. **Read the spec**: Start with [aip-v1alpha1.md](aip-v1alpha1.md)
2. **Validate schemas**: Use the JSON Schema to validate policy files
3. **Pass conformance tests**: Run the [conformance suite](conformance/) against your implementation
4. **Report issues**: File issues if you find ambiguities or errors

## Conformance Levels

| Level | Description | Required Tests |
|-------|-------------|----------------|
| **Basic** | Minimum viable implementation | `conformance/basic/*` |
| **Full** | Complete feature support | `conformance/basic/*` + `conformance/full/*` |
| **Extended** | Human-in-the-loop support | All tests |

## Schema Validation

Validate a policy file against the JSON Schema:

```bash
# Using ajv-cli
npm install -g ajv-cli
ajv validate -s spec/schema/agent-policy.schema.json -d your-policy.yaml

# Using Python jsonschema
pip install jsonschema pyyaml
python -c "
import yaml, jsonschema, json
schema = json.load(open('spec/schema/agent-policy.schema.json'))
policy = yaml.safe_load(open('your-policy.yaml'))
jsonschema.validate(policy, schema)
print('Valid!')
"
```

## Contributing

To propose changes to the specification:

1. Open an issue describing the change
2. Submit a PR with spec updates
3. Include test vectors for new behavior
4. Update the changelog in the spec document

## License

The specification is licensed under Apache 2.0, same as the reference implementation.
