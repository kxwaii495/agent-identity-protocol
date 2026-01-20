// Package policy tests for the AIP policy engine.
package policy

import (
	"testing"
)

// TestGeminiJackDefense tests the "GeminiJack" attack defense.
//
// Attack scenario: An attacker tricks an agent into calling fetch_url with
// a malicious URL like "https://attacker.com/steal" instead of the intended
// "https://github.com/..." URL.
//
// Defense: The policy engine validates the url argument against a regex
// that only allows GitHub URLs.
func TestGeminiJackDefense(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: gemini-jack-defense-test
spec:
  tool_rules:
    - tool: fetch_url
      allow_args:
        url: "^https://github\\.com/.*"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	tests := []struct {
		name        string
		tool        string
		args        map[string]any
		wantAllowed bool
		wantFailArg string
	}{
		{
			name:        "Valid GitHub URL should pass",
			tool:        "fetch_url",
			args:        map[string]any{"url": "https://github.com/my-repo"},
			wantAllowed: true,
		},
		{
			name:        "Attacker URL should fail",
			tool:        "fetch_url",
			args:        map[string]any{"url": "https://attacker.com/steal"},
			wantAllowed: false,
			wantFailArg: "url",
		},
		{
			name:        "HTTP GitHub URL should fail (not https)",
			tool:        "fetch_url",
			args:        map[string]any{"url": "http://github.com/my-repo"},
			wantAllowed: false,
			wantFailArg: "url",
		},
		{
			name:        "GitHub subdomain attack should fail",
			tool:        "fetch_url",
			args:        map[string]any{"url": "https://github.com.evil.com/my-repo"},
			wantAllowed: false,
			wantFailArg: "url",
		},
		{
			name:        "Missing url argument should fail",
			tool:        "fetch_url",
			args:        map[string]any{},
			wantAllowed: false,
			wantFailArg: "url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.IsAllowed(tt.tool, tt.args)

			if result.Allowed != tt.wantAllowed {
				t.Errorf("IsAllowed() = %v, want %v", result.Allowed, tt.wantAllowed)
			}

			if tt.wantFailArg != "" && result.FailedArg != tt.wantFailArg {
				t.Errorf("FailedArg = %q, want %q", result.FailedArg, tt.wantFailArg)
			}
		})
	}
}

// TestToolLevelDeny tests that tools not in allowed_tools are denied.
func TestToolLevelDeny(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: tool-level-test
spec:
  allowed_tools:
    - safe_tool
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	tests := []struct {
		name        string
		tool        string
		wantAllowed bool
	}{
		{"Allowed tool passes", "safe_tool", true},
		{"Allowed tool case-insensitive", "SAFE_TOOL", true},
		{"Unknown tool denied", "dangerous_tool", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.IsAllowed(tt.tool, nil)
			if result.Allowed != tt.wantAllowed {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.tool, result.Allowed, tt.wantAllowed)
			}
		})
	}
}

// TestToolWithNoArgRulesAllowsAllArgs tests that tools in tool_rules
// without allow_args allow all arguments.
func TestToolWithNoArgRulesAllowsAllArgs(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: no-arg-rules-test
spec:
  allowed_tools:
    - unrestricted_tool
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Tool is allowed, no arg rules = allow any args
	result := engine.IsAllowed("unrestricted_tool", map[string]any{
		"any_arg":    "any_value",
		"another":    12345,
		"dangerous":  "../../etc/passwd",
	})

	if !result.Allowed {
		t.Errorf("Expected unrestricted_tool to allow all args, got denied")
	}
}

// TestMultipleArgConstraints tests that multiple arguments are all validated.
func TestMultipleArgConstraints(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: multi-arg-test
spec:
  tool_rules:
    - tool: run_query
      allow_args:
        database: "^(prod|staging)$"
        query: "^SELECT\\s+.*"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	tests := []struct {
		name        string
		args        map[string]any
		wantAllowed bool
		wantFailArg string
	}{
		{
			name:        "Valid SELECT on prod",
			args:        map[string]any{"database": "prod", "query": "SELECT * FROM users"},
			wantAllowed: true,
		},
		{
			name:        "Valid SELECT on staging",
			args:        map[string]any{"database": "staging", "query": "SELECT id FROM orders"},
			wantAllowed: true,
		},
		{
			name:        "DROP query should fail",
			args:        map[string]any{"database": "prod", "query": "DROP TABLE users"},
			wantAllowed: false,
			wantFailArg: "query",
		},
		{
			name:        "Invalid database should fail",
			args:        map[string]any{"database": "master", "query": "SELECT * FROM users"},
			wantAllowed: false,
			wantFailArg: "database",
		},
		{
			name:        "DELETE query should fail",
			args:        map[string]any{"database": "prod", "query": "DELETE FROM users"},
			wantAllowed: false,
			wantFailArg: "query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.IsAllowed("run_query", tt.args)

			if result.Allowed != tt.wantAllowed {
				t.Errorf("IsAllowed() = %v, want %v", result.Allowed, tt.wantAllowed)
			}

			if !tt.wantAllowed && tt.wantFailArg != "" && result.FailedArg != tt.wantFailArg {
				t.Errorf("FailedArg = %q, want %q", result.FailedArg, tt.wantFailArg)
			}
		})
	}
}

// TestInvalidRegexReturnsError tests that invalid regex patterns cause Load() to fail.
func TestInvalidRegexReturnsError(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: invalid-regex-test
spec:
  tool_rules:
    - tool: bad_tool
      allow_args:
        pattern: "[invalid(regex"
`

	engine := NewEngine()
	err := engine.Load([]byte(policyYAML))

	if err == nil {
		t.Error("Expected Load() to fail with invalid regex, but it succeeded")
	}
}

// TestArgToString tests conversion of various types to strings.
func TestArgToString(t *testing.T) {
	tests := []struct {
		input any
		want  string
	}{
		{"hello", "hello"},
		{float64(42), "42"},
		{float64(3.14), "3.14"},
		{true, "true"},
		{false, "false"},
		{int(100), "100"},
	}

	for _, tt := range tests {
		got := argToString(tt.input)
		if got != tt.want {
			t.Errorf("argToString(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestToolRulesImplicitlyAllowTool tests that defining a tool_rule
// implicitly adds the tool to allowed_tools.
func TestToolRulesImplicitlyAllowTool(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: implicit-allow-test
spec:
  # Note: fetch_url NOT in allowed_tools, but has a tool_rule
  tool_rules:
    - tool: fetch_url
      allow_args:
        url: "^https://.*"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Tool should be allowed because it has a rule defined
	result := engine.IsAllowed("fetch_url", map[string]any{"url": "https://example.com"})
	if !result.Allowed {
		t.Error("Expected fetch_url to be implicitly allowed via tool_rules")
	}
}

// -----------------------------------------------------------------------------
// Monitor Mode Tests (Phase 4)
// -----------------------------------------------------------------------------

// TestMonitorModeAllowsViolations tests that monitor mode allows through
// requests that would otherwise be blocked, but flags ViolationDetected.
func TestMonitorModeAllowsViolations(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: monitor-mode-test
spec:
  mode: monitor
  allowed_tools:
    - safe_tool
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Verify mode is set correctly
	if engine.GetMode() != ModeMonitor {
		t.Errorf("GetMode() = %q, want %q", engine.GetMode(), ModeMonitor)
	}
	if !engine.IsMonitorMode() {
		t.Error("IsMonitorMode() = false, want true")
	}

	tests := []struct {
		name              string
		tool              string
		wantAllowed       bool
		wantViolation     bool
	}{
		{
			name:              "Allowed tool - no violation",
			tool:              "safe_tool",
			wantAllowed:       true,
			wantViolation:     false,
		},
		{
			name:              "Blocked tool - allowed in monitor mode with violation flag",
			tool:              "dangerous_tool",
			wantAllowed:       true,  // MONITOR: allowed through
			wantViolation:     true,  // but flagged as violation
		},
		{
			name:              "Another blocked tool - same behavior",
			tool:              "rm_rf_slash",
			wantAllowed:       true,
			wantViolation:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := engine.IsAllowed(tt.tool, nil)

			if decision.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllowed)
			}
			if decision.ViolationDetected != tt.wantViolation {
				t.Errorf("ViolationDetected = %v, want %v", decision.ViolationDetected, tt.wantViolation)
			}
		})
	}
}

// TestEnforceModeBlocksViolations tests that enforce mode (default) blocks
// violations and sets ViolationDetected appropriately.
func TestEnforceModeBlocksViolations(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: enforce-mode-test
spec:
  mode: enforce
  allowed_tools:
    - safe_tool
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Verify mode is set correctly
	if engine.GetMode() != ModeEnforce {
		t.Errorf("GetMode() = %q, want %q", engine.GetMode(), ModeEnforce)
	}
	if engine.IsMonitorMode() {
		t.Error("IsMonitorMode() = true, want false")
	}

	tests := []struct {
		name              string
		tool              string
		wantAllowed       bool
		wantViolation     bool
	}{
		{
			name:              "Allowed tool - no violation",
			tool:              "safe_tool",
			wantAllowed:       true,
			wantViolation:     false,
		},
		{
			name:              "Blocked tool - denied with violation flag",
			tool:              "dangerous_tool",
			wantAllowed:       false, // ENFORCE: blocked
			wantViolation:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := engine.IsAllowed(tt.tool, nil)

			if decision.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllowed)
			}
			if decision.ViolationDetected != tt.wantViolation {
				t.Errorf("ViolationDetected = %v, want %v", decision.ViolationDetected, tt.wantViolation)
			}
		})
	}
}

// TestDefaultModeIsEnforce tests that omitting mode defaults to enforce.
func TestDefaultModeIsEnforce(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: default-mode-test
spec:
  # mode not specified - should default to enforce
  allowed_tools:
    - safe_tool
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	if engine.GetMode() != ModeEnforce {
		t.Errorf("Default mode = %q, want %q", engine.GetMode(), ModeEnforce)
	}

	// Verify enforce behavior: blocked tool is denied
	decision := engine.IsAllowed("blocked_tool", nil)
	if decision.Allowed {
		t.Error("Default mode should block disallowed tools, but Allowed=true")
	}
	if !decision.ViolationDetected {
		t.Error("ViolationDetected should be true for blocked tool")
	}
}

// TestInvalidModeReturnsError tests that invalid mode values cause Load() to fail.
func TestInvalidModeReturnsError(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: invalid-mode-test
spec:
  mode: invalid_mode
  allowed_tools:
    - safe_tool
`

	engine := NewEngine()
	err := engine.Load([]byte(policyYAML))

	if err == nil {
		t.Error("Expected Load() to fail with invalid mode, but it succeeded")
	}
}

// TestMonitorModeWithArgValidation tests monitor mode with argument-level
// validation failures.
func TestMonitorModeWithArgValidation(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: monitor-args-test
spec:
  mode: monitor
  tool_rules:
    - tool: fetch_url
      allow_args:
        url: "^https://github\\.com/.*"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	tests := []struct {
		name              string
		args              map[string]any
		wantAllowed       bool
		wantViolation     bool
		wantFailedArg     string
	}{
		{
			name:              "Valid GitHub URL - no violation",
			args:              map[string]any{"url": "https://github.com/my-repo"},
			wantAllowed:       true,
			wantViolation:     false,
			wantFailedArg:     "",
		},
		{
			name:              "Attacker URL - allowed in monitor but flagged",
			args:              map[string]any{"url": "https://evil.com/steal"},
			wantAllowed:       true,  // MONITOR: allowed through
			wantViolation:     true,  // flagged as violation
			wantFailedArg:     "url",
		},
		{
			name:              "Missing URL - allowed in monitor but flagged",
			args:              map[string]any{},
			wantAllowed:       true,
			wantViolation:     true,
			wantFailedArg:     "url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := engine.IsAllowed("fetch_url", tt.args)

			if decision.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllowed)
			}
			if decision.ViolationDetected != tt.wantViolation {
				t.Errorf("ViolationDetected = %v, want %v", decision.ViolationDetected, tt.wantViolation)
			}
			if tt.wantFailedArg != "" && decision.FailedArg != tt.wantFailedArg {
				t.Errorf("FailedArg = %q, want %q", decision.FailedArg, tt.wantFailedArg)
			}
		})
	}
}

// TestDecisionReason tests that decisions include helpful reason strings.
func TestDecisionReason(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: reason-test
spec:
  mode: monitor
  allowed_tools:
    - allowed_tool
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Test that reason is populated
	decision := engine.IsAllowed("blocked_tool", nil)
	if decision.Reason == "" {
		t.Error("Decision.Reason should not be empty")
	}

	// Allowed tool should also have a reason
	decision = engine.IsAllowed("allowed_tool", nil)
	if decision.Reason == "" {
		t.Error("Decision.Reason should not be empty for allowed tools")
	}
}
