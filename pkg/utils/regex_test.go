package utils

import (
	"testing"
)

func TestCompileRegex(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"valid pattern", `[a-z]+`, false},
		{"valid email", `[^@]+@[^@]+\.[^@]+`, false},
		{"invalid pattern", `[a-z+`, true},
		{"empty pattern", ``, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CompileRegex(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompileRegex() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMatchString(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		want    bool
		wantErr bool
	}{
		{`[0-9]+`, "abc123def", true, false},
		{`[a-z]+`, "123", false, false},
		{`[a-z+`, "test", false, true},
	}

	for _, tt := range tests {
		got, err := MatchString(tt.pattern, tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("MatchString() error = %v, wantErr %v", err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("MatchString() = %v, want %v", got, tt.want)
		}
	}
}

func TestFindAllString(t *testing.T) {
	matches, err := FindAllString(`\d+`, "abc123def456")
	if err != nil {
		t.Fatalf("FindAllString() error = %v", err)
	}
	if len(matches) != 2 {
		t.Errorf("FindAllString() found %d matches, want 2", len(matches))
	}
}

func TestFindAllStringSubmatch(t *testing.T) {
	matches, err := FindAllStringSubmatch(`(\w+)@(\w+)\.(\w+)`, "test@example.com")
	if err != nil {
		t.Fatalf("FindAllStringSubmatch() error = %v", err)
	}
	if len(matches) != 1 || len(matches[0]) != 4 {
		t.Errorf("FindAllStringSubmatch() = %v, want 1 match with 4 groups", matches)
	}
}

func TestMustCompile(t *testing.T) {
	// This should not panic
	re := MustCompile(`[a-z]+`)
	if re == nil {
		t.Error("MustCompile() returned nil")
	}
}
