package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsHiddenFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"hidden file", ".env", true},
		{"hidden file in dir", "config/.env", true},
		{"regular file", "file.go", false},
		{"regular file in dir", "config/file.go", false},
		{"dot dir", ".", false},
		{"double dot", "..", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsHiddenFile(tt.path)
			if got != tt.expected {
				t.Errorf("IsHiddenFile(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestGetBaseName(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/path/to/file.go", "file.go"},
		{".env", ".env"},
		{"file", "file"},
		{"/path/to/dir/", "."},
	}

	for _, tt := range tests {
		got := GetBaseName(tt.path)
		if got != tt.expected {
			t.Errorf("GetBaseName(%q) = %q, want %q", tt.path, got, tt.expected)
		}
	}
}

func TestWalkDirWithFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	files := []string{"a.txt", "b.txt", "c.txt"}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(tmpDir, f), []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var count int
	err := WalkDir(tmpDir, func(path string, info os.FileInfo) error {
		count++
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir() error = %v", err)
	}
	if count != 3 {
		t.Errorf("WalkDir() visited %d files, want 3", count)
	}
}
