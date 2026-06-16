package scanner

import (
	"os"
	"testing"
)

func TestIsBinaryFile_WithBinary(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Write binary content
	if _, err := tmpFile.Write([]byte{0x00, 0x01, 0x02, 0x03}); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	isBinary, err := IsBinaryFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("IsBinaryFile() error = %v", err)
	}
	if !isBinary {
		t.Error("Expected binary file to be detected as binary")
	}
}

func TestIsBinaryFile_WithText(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString("Hello, World!"); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	isBinary, err := IsBinaryFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("IsBinaryFile() error = %v", err)
	}
	if isBinary {
		t.Error("Expected text file to be detected as non-binary")
	}
}

func TestGetFileExtension_VariousExtensions(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"file.go", ".go"},
		{"file.txt", ".txt"},
		{"file", ""},
		{"dir/file.go", ".go"},
		{".env", ""},
		{"file.tar.gz", ".gz"},
		{"file.min.js", ".js"},
	}

	for _, tt := range tests {
		got := GetFileExtension(tt.path)
		if got != tt.expected {
			t.Errorf("GetFileExtension(%q) = %q, want %q", tt.path, got, tt.expected)
		}
	}
}
