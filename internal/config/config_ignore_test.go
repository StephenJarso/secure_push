package config

import (
	"testing"
)

func TestShouldIgnore_Allowlist(t *testing.T) {
	cfg := &Config{
		IgnorePaths: []string{"*.test.go"},
		Allowlist:   []string{"important.test.go"},
	}

	if cfg.ShouldIgnore("important.test.go") {
		t.Error("Expected allowlisted file to not be ignored")
	}
	if !cfg.ShouldIgnore("other.test.go") {
		t.Error("Expected non-allowlisted file to be ignored")
	}
}

func TestShouldIgnore_PathPatterns(t *testing.T) {
	cfg := &Config{
		IgnorePaths: []string{"vendor/**", "**/*_test.go"},
	}

	tests := []struct {
		path   string
		ignore bool
	}{
		{"vendor/lib.go", true},
		{"vendor/sub/lib.go", true},
		{"main_test.go", true},
		{"main.go", false},
		{"internal/main.go", false},
	}

	for _, tt := range tests {
		got := cfg.ShouldIgnore(tt.path)
		if got != tt.ignore {
			t.Errorf("ShouldIgnore(%q) = %v, want %v", tt.path, got, tt.ignore)
		}
	}
}

func TestMatchPath_GlobPatterns(t *testing.T) {
	tests := []struct {
		pattern string
		target  string
		want    bool
	}{
		{"*.go", "main.go", true},
		{"*.go", "main.txt", false},
		{"**/*.go", "dir/main.go", true},
		{"vendor/*", "vendor/lib.go", true},
		{"vendor/*", "vendor/sub/lib.go", false},
	}

	for _, tt := range tests {
		got := matchPath(tt.pattern, tt.target)
		if got != tt.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.target, got, tt.want)
		}
	}
}
