package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsBinaryFile(t *testing.T) {
	t.Run("text file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "test-*.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString("This is a text file\n"); err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		isBinary, err := IsBinaryFile(tmpFile.Name())
		if err != nil {
			t.Fatalf("IsBinaryFile() error = %v", err)
		}

		if isBinary {
			t.Error("IsBinaryFile() = true, want false for text file")
		}
	})

	t.Run("binary file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "test-*.bin")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		// Write binary content with null byte
		if _, err := tmpFile.Write([]byte{0x00, 0x01, 0x02, 0x03}); err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		isBinary, err := IsBinaryFile(tmpFile.Name())
		if err != nil {
			t.Fatalf("IsBinaryFile() error = %v", err)
		}

		if !isBinary {
			t.Error("IsBinaryFile() = false, want true for binary file")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := IsBinaryFile("/nonexistent/file")
		if err == nil {
			t.Error("IsBinaryFile() should return error for nonexistent file")
		}
	})
}

func TestIsBinary(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"text data", []byte("Hello, World!"), false},
		{"binary with null", []byte{0x00, 0x01, 0x02}, true},
		{"empty data", []byte{}, false},
		{"small text", []byte("test"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBinary(tt.data)
			if result != tt.expected {
				t.Errorf("IsBinary() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetFileExtension(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"file.go", ".go"},
		{"file.yaml", ".yaml"},
		{"file.JSON", ".JSON"},
		{"noextension", ""},
		{"path/to/file.txt", ".txt"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := GetFileExtension(tt.path)
			if result != tt.expected {
				t.Errorf("GetFileExtension() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestIsTextFile(t *testing.T) {
	t.Run("text file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "test-*.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString("text content"); err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		isText, err := IsTextFile(tmpFile.Name())
		if err != nil {
			t.Fatalf("IsTextFile() error = %v", err)
		}

		if !isText {
			t.Error("IsTextFile() = false, want true for text file")
		}
	})
}

func TestIsBinaryFileWithSmallFile(t *testing.T) {
	// Test that files smaller than 512 bytes are handled correctly
	tmpFile, err := os.CreateTemp("", "small-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Write less than 512 bytes
	if _, err := tmpFile.WriteString("small"); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	isBinary, err := IsBinaryFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("IsBinaryFile() error = %v", err)
	}

	if isBinary {
		t.Error("IsBinaryFile() = true, want false for small text file")
	}
}

func TestIsBinaryFileWithLargeFile(t *testing.T) {
	// Test that files larger than 512 bytes are handled correctly
	tmpFile, err := os.CreateTemp("", "large-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Write more than 512 bytes
	content := make([]byte, 600)
	for i := range content {
		content[i] = 'a'
	}
	if _, err := tmpFile.Write(content); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	isBinary, err := IsBinaryFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("IsBinaryFile() error = %v", err)
	}

	if isBinary {
		t.Error("IsBinaryFile() = true, want false for large text file")
	}
}

func TestIsBinaryFileInSubdir(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	tmpFile, err := os.CreateTemp(subDir, "test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString("text content"); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	isBinary, err := IsBinaryFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("IsBinaryFile() error = %v", err)
	}

	if isBinary {
		t.Error("IsBinaryFile() = true, want false for text file in subdir")
	}
}

func BenchmarkIsBinary(b *testing.B) {
	textData := make([]byte, 512)
	for i := range textData {
		textData[i] = 'a'
	}

	binaryData := make([]byte, 512)
	for i := range binaryData {
		binaryData[i] = byte(i % 256)
	}
	binaryData[100] = 0 // Add null byte

	b.Run("text data", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			IsBinary(textData)
		}
	})

	b.Run("binary data", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			IsBinary(binaryData)
		}
	})
}

func BenchmarkBufferPool(b *testing.B) {
	b.Run("get and put", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bufPtr := bufferPool.Get().(*[]byte)
			_ = (*bufPtr)[0]
			bufferPool.Put(bufPtr)
		}
	})
}
