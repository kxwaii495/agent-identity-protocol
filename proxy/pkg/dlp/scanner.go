// Package dlp implements Data Loss Prevention (DLP) scanning and redaction.
//
// The DLP scanner inspects tool responses flowing downstream from the MCP server
// to the client and redacts sensitive information (PII, API keys, secrets) before
// forwarding. This prevents accidental data exfiltration through tool outputs.
//
// Architecture:
//
//	┌──────────────┐     ┌─────────────┐     ┌──────────────┐
//	│  MCP Server  │────▶│ DLP Scanner │────▶│    Client    │
//	│  (response)  │     │  (redact)   │     │ (sanitized)  │
//	└──────────────┘     └─────────────┘     └──────────────┘
//
// The scanner uses compiled regular expressions for performance, running all
// patterns against each response. Matches are replaced with [REDACTED:<RuleName>].
package dlp

import (
	"fmt"
	"regexp"
	"sync"

	"github.com/ArangoGutierrez/agent-identity-protocol/proxy/pkg/policy"
)

// RedactionEvent captures details of a single redaction for audit logging.
type RedactionEvent struct {
	// RuleName is the name of the DLP rule that matched
	RuleName string

	// MatchCount is the number of matches found for this rule
	MatchCount int
}

// Scanner provides DLP scanning and redaction capabilities.
//
// Thread-safety: Scanner is safe for concurrent use after initialization.
// The compiled patterns are read-only after Compile().
type Scanner struct {
	patterns []compiledPattern
	enabled  bool
	mu       sync.RWMutex
}

// compiledPattern holds a pre-compiled regex with its associated rule name.
type compiledPattern struct {
	name  string
	regex *regexp.Regexp
}

// NewScanner creates a new DLP scanner from policy configuration.
//
// Returns nil if DLP is not configured or disabled.
// Returns error if any pattern regex fails to compile.
func NewScanner(cfg *policy.DLPConfig) (*Scanner, error) {
	if cfg == nil || !cfg.IsEnabled() {
		return nil, nil
	}

	s := &Scanner{
		patterns: make([]compiledPattern, 0, len(cfg.Patterns)),
		enabled:  true,
	}

	for _, p := range cfg.Patterns {
		if p.Name == "" {
			return nil, fmt.Errorf("DLP pattern missing required 'name' field")
		}
		if p.Regex == "" {
			return nil, fmt.Errorf("DLP pattern %q missing required 'regex' field", p.Name)
		}

		compiled, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("DLP pattern %q has invalid regex: %w", p.Name, err)
		}

		s.patterns = append(s.patterns, compiledPattern{
			name:  p.Name,
			regex: compiled,
		})
	}

	return s, nil
}

// IsEnabled returns true if the scanner is active and has patterns configured.
func (s *Scanner) IsEnabled() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled && len(s.patterns) > 0
}

// Redact scans input string for sensitive data and replaces matches.
//
// Returns:
//   - output: The redacted string with matches replaced by [REDACTED:<RuleName>]
//   - events: List of RedactionEvent for each rule that matched (for audit logging)
//
// If the scanner is nil or disabled, returns the original input unchanged.
//
// Example:
//
//	input:  "API key is AKIAIOSFODNN7EXAMPLE"
//	output: "API key is [REDACTED:AWS Key]"
//	events: [{RuleName: "AWS Key", MatchCount: 1}]
func (s *Scanner) Redact(input string) (output string, events []RedactionEvent) {
	if s == nil || !s.IsEnabled() {
		return input, nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	output = input
	events = make([]RedactionEvent, 0)

	for _, p := range s.patterns {
		matches := p.regex.FindAllStringIndex(output, -1)
		if len(matches) > 0 {
			// Record the redaction event before modifying the string
			events = append(events, RedactionEvent{
				RuleName:   p.name,
				MatchCount: len(matches),
			})

			// Replace all matches with redaction placeholder
			replacement := fmt.Sprintf("[REDACTED:%s]", p.name)
			output = p.regex.ReplaceAllString(output, replacement)
		}
	}

	return output, events
}

// RedactJSON scans a JSON byte slice for sensitive data in string values.
// This is a convenience wrapper that converts to string, redacts, and returns bytes.
//
// Note: This performs string-level redaction. For structured JSON inspection,
// use the Scanner with the decoded JSON content fields.
func (s *Scanner) RedactJSON(input []byte) (output []byte, events []RedactionEvent) {
	if s == nil || !s.IsEnabled() {
		return input, nil
	}

	redacted, events := s.Redact(string(input))
	return []byte(redacted), events
}

// PatternCount returns the number of configured DLP patterns.
func (s *Scanner) PatternCount() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.patterns)
}

// PatternNames returns the names of all configured patterns (for logging).
func (s *Scanner) PatternNames() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, len(s.patterns))
	for i, p := range s.patterns {
		names[i] = p.name
	}
	return names
}
