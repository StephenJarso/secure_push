package detectors

import (
	"testing"
)

func TestIsDangerousFunction(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"exec", "exec", true},
		{"execcommand", "execcommand", true},
		{"readfile", "readfile", true},
		{"getenv", "getenv", true},
		{"httpget", "httpget", true},
		{"sqlopen", "sqlopen", true},
		{"eval", "eval", true},
		{"safe function", "fmt.Println", false},
		{"safe function 2", "log.Info", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDangerousFunction(tt.input)
			if got != tt.expected {
				t.Errorf("IsDangerousFunction(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsCredentialPattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"password", "password", true},
		{"passwd", "passwd", true},
		{"secret", "secret", true},
		{"token", "token", true},
		{"api_key", "api_key", true},
		{"apikey", "apikey", true},
		{"safe value", "hello", false},
		{"safe value 2", "world123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsCredentialPattern(tt.input)
			if got != tt.expected {
				t.Errorf("IsCredentialPattern(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
