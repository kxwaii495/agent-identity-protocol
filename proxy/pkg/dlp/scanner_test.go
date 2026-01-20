package dlp

import (
	"testing"

	"github.com/ArangoGutierrez/agent-identity-protocol/proxy/pkg/policy"
)

func TestNewScanner(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *policy.DLPConfig
		wantNil bool
		wantErr bool
	}{
		{
			name:    "nil config returns nil scanner",
			cfg:     nil,
			wantNil: true,
			wantErr: false,
		},
		{
			name: "disabled config returns nil scanner",
			cfg: &policy.DLPConfig{
				Enabled:  boolPtr(false),
				Patterns: []policy.DLPPattern{{Name: "Test", Regex: "test"}},
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name: "valid patterns compile successfully",
			cfg: &policy.DLPConfig{
				Patterns: []policy.DLPPattern{
					{Name: "Email", Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`},
					{Name: "Secret", Regex: `(?i)secret`},
				},
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name: "invalid regex returns error",
			cfg: &policy.DLPConfig{
				Patterns: []policy.DLPPattern{
					{Name: "Bad", Regex: `[invalid`},
				},
			},
			wantNil: false,
			wantErr: true,
		},
		{
			name: "pattern missing name returns error",
			cfg: &policy.DLPConfig{
				Patterns: []policy.DLPPattern{
					{Name: "", Regex: `test`},
				},
			},
			wantNil: false,
			wantErr: true,
		},
		{
			name: "pattern missing regex returns error",
			cfg: &policy.DLPConfig{
				Patterns: []policy.DLPPattern{
					{Name: "Test", Regex: ""},
				},
			},
			wantNil: false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewScanner(tt.cfg)

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil && scanner != nil {
				t.Fatal("expected nil scanner")
			}
			if !tt.wantNil && !tt.wantErr && scanner == nil {
				t.Fatal("expected non-nil scanner")
			}
		})
	}
}

func TestScanner_Redact(t *testing.T) {
	// Set up scanner with common patterns
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "Email", Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`},
			{Name: "AWS Key", Regex: `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`},
			{Name: "Generic Secret", Regex: `(?i)(api_key|secret|password)\s*[:=]\s*['"]?([a-zA-Z0-9-_]+)['"]?`},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	tests := []struct {
		name       string
		input      string
		wantOutput string
		wantRules  []string
	}{
		{
			name:       "no sensitive data",
			input:      "Hello, this is a normal message",
			wantOutput: "Hello, this is a normal message",
			wantRules:  nil,
		},
		{
			name:       "email redaction",
			input:      "Contact me at user@example.com",
			wantOutput: "Contact me at [REDACTED:Email]",
			wantRules:  []string{"Email"},
		},
		{
			name:       "multiple emails",
			input:      "Email alice@test.org or bob@company.com",
			wantOutput: "Email [REDACTED:Email] or [REDACTED:Email]",
			wantRules:  []string{"Email"},
		},
		{
			name:       "AWS key redaction",
			input:      "The key is AKIAIOSFODNN7EXAMPLE",
			wantOutput: "The key is [REDACTED:AWS Key]",
			wantRules:  []string{"AWS Key"},
		},
		{
			name:       "generic secret redaction",
			input:      `api_key: "my-secret-key-123"`,
			wantOutput: `[REDACTED:Generic Secret]`,
			wantRules:  []string{"Generic Secret"},
		},
		{
			name:       "password redaction",
			input:      "password = supersecret123",
			wantOutput: "[REDACTED:Generic Secret]",
			wantRules:  []string{"Generic Secret"},
		},
		{
			name:       "multiple pattern types",
			input:      "Contact user@test.com with key AKIAIOSFODNN7EXAMPLE",
			wantOutput: "Contact [REDACTED:Email] with key [REDACTED:AWS Key]",
			wantRules:  []string{"Email", "AWS Key"},
		},
		{
			name:       "case insensitive secret",
			input:      "SECRET: myvalue",
			wantOutput: "[REDACTED:Generic Secret]",
			wantRules:  []string{"Generic Secret"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, events := scanner.Redact(tt.input)

			if output != tt.wantOutput {
				t.Errorf("Redact() output = %q, want %q", output, tt.wantOutput)
			}

			if len(events) != len(tt.wantRules) {
				t.Errorf("Redact() events count = %d, want %d", len(events), len(tt.wantRules))
			}

			for i, wantRule := range tt.wantRules {
				if i < len(events) && events[i].RuleName != wantRule {
					t.Errorf("Redact() events[%d].RuleName = %q, want %q", i, events[i].RuleName, wantRule)
				}
			}
		})
	}
}

func TestScanner_Redact_NilScanner(t *testing.T) {
	var scanner *Scanner
	input := "sensitive@email.com"

	output, events := scanner.Redact(input)

	if output != input {
		t.Errorf("nil scanner should return input unchanged, got %q", output)
	}
	if events != nil {
		t.Error("nil scanner should return nil events")
	}
}

func TestScanner_RedactJSON(t *testing.T) {
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "Email", Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`},
		},
	}
	scanner, _ := NewScanner(cfg)

	input := []byte(`{"text": "Contact user@example.com"}`)
	output, events := scanner.RedactJSON(input)

	expected := `{"text": "Contact [REDACTED:Email]"}`
	if string(output) != expected {
		t.Errorf("RedactJSON() = %s, want %s", output, expected)
	}
	if len(events) != 1 || events[0].RuleName != "Email" {
		t.Errorf("RedactJSON() events = %v, want [{Email, 1}]", events)
	}
}

func TestScanner_IsEnabled(t *testing.T) {
	tests := []struct {
		name    string
		scanner *Scanner
		want    bool
	}{
		{
			name:    "nil scanner",
			scanner: nil,
			want:    false,
		},
		{
			name:    "empty patterns",
			scanner: &Scanner{enabled: true, patterns: nil},
			want:    false,
		},
		{
			name: "enabled with patterns",
			scanner: &Scanner{
				enabled:  true,
				patterns: []compiledPattern{{name: "Test"}},
			},
			want: true,
		},
		{
			name: "disabled with patterns",
			scanner: &Scanner{
				enabled:  false,
				patterns: []compiledPattern{{name: "Test"}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.scanner.IsEnabled(); got != tt.want {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScanner_PatternCount(t *testing.T) {
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "P1", Regex: "a"},
			{Name: "P2", Regex: "b"},
			{Name: "P3", Regex: "c"},
		},
	}
	scanner, _ := NewScanner(cfg)

	if scanner.PatternCount() != 3 {
		t.Errorf("PatternCount() = %d, want 3", scanner.PatternCount())
	}

	var nilScanner *Scanner
	if nilScanner.PatternCount() != 0 {
		t.Error("nil scanner should have PatternCount() = 0")
	}
}

func TestScanner_PatternNames(t *testing.T) {
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "Email", Regex: "a"},
			{Name: "AWS Key", Regex: "b"},
		},
	}
	scanner, _ := NewScanner(cfg)

	names := scanner.PatternNames()
	if len(names) != 2 {
		t.Fatalf("PatternNames() len = %d, want 2", len(names))
	}
	if names[0] != "Email" || names[1] != "AWS Key" {
		t.Errorf("PatternNames() = %v, want [Email, AWS Key]", names)
	}
}

// Test case from the spec
func TestScanner_TestCase_FromSpec(t *testing.T) {
	// Configure DLP rule: regex: "SECRET"
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "Generic Secret", Regex: "SECRET"},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	// Mock Tool Output content text
	input := "This is a SECRET code"
	expected := "This is a [REDACTED:Generic Secret] code"

	output, events := scanner.Redact(input)

	if output != expected {
		t.Errorf("Redact() = %q, want %q", output, expected)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].RuleName != "Generic Secret" {
		t.Errorf("event.RuleName = %q, want %q", events[0].RuleName, "Generic Secret")
	}
	if events[0].MatchCount != 1 {
		t.Errorf("event.MatchCount = %d, want 1", events[0].MatchCount)
	}
}

// boolPtr is a helper to create *bool values
func boolPtr(b bool) *bool {
	return &b
}
