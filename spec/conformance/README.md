# AIP Conformance Test Suite

This directory contains test vectors for validating AIP implementations.

## Overview

An implementation claiming AIP conformance MUST pass all tests at their claimed conformance level:

| Level | Test Files |
|-------|------------|
| Basic | `basic/*.yaml` |
| Full | `basic/*.yaml` + `full/*.yaml` |
| Extended | All test files |

## Test Vector Format

Each test file contains a list of test cases:

```yaml
name: "Test Suite Name"
description: "What this suite tests"
tests:
  - id: "test-001"
    description: "Human readable description"
    policy: |
      # Inline policy YAML
      apiVersion: aip.io/v1alpha1
      ...
    input:
      method: "tools/call"
      tool: "some_tool"
      args:
        key: "value"
    expected:
      decision: "ALLOW"  # or BLOCK, ASK, RATE_LIMITED, PROTECTED_PATH
      error_code: null   # or -32001, -32002, etc.
      violation: false   # Whether violation was detected
```

## Running Tests

### Using the Reference Validator

```bash
# Install the validator
go install github.com/ArangoGutierrez/agent-identity-protocol/tools/aip-conformance@latest

# Run tests against your implementation
aip-conformance --impl "your-binary" --level full
```

### Test Execution

For each test case:
1. Load the policy
2. Submit the input request
3. Verify the output matches `expected`

### Matching Rules

- `decision`: Exact string match
- `error_code`: Exact match (null means no error)
- `violation`: Boolean match
- DLP tests: Verify redaction occurred

## Test Categories

### basic/authorization.yaml
- Tool allowlist enforcement
- Tool blocking
- Default deny behavior

### basic/methods.yaml
- Method allowlist
- Method denylist
- Default methods

### basic/errors.yaml
- Error code correctness
- Error message format

### full/arguments.yaml
- Regex validation
- Strict args mode
- Type coercion

### full/normalization.yaml
- Unicode NFKC
- Case insensitivity
- Whitespace handling

### full/rate-limiting.yaml
- Rate limit parsing
- Limit enforcement

### full/dlp.yaml
- Pattern matching
- Redaction format

### extended/ask.yaml
- Human-in-the-loop behavior
- Timeout handling

## Contributing Tests

When adding tests:
1. Include positive AND negative cases
2. Test edge cases (empty strings, Unicode, etc.)
3. Document why the expected result is correct
4. Ensure tests are deterministic

## Versioning

Test vectors are versioned alongside the specification:
- `v1alpha1/` - Tests for aip.io/v1alpha1

Breaking changes to test vectors require a new version.
