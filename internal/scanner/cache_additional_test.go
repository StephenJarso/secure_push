package scanner

import (
	"os"
	"testing"
)

func TestScanCache_Size(t *testing.T) {
	cache := NewScanCache(true, t.TempDir())

	if cache.Size() != 0 {
		t.Errorf("Size() = %d, want 0", cache.Size())
	}

	tmpFile, err := os.CreateTemp("", "test-*.go")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	cache.Set(tmpFile.Name(), []string{"finding"})
	if cache.Size() != 1 {
		t.Errorf("Size() = %d, want 1", cache.Size())
	}

	cache.Set(tmpFile.Name(), []string{"finding2"})
	if cache.Size() != 1 {
		t.Errorf("Size() = %d, want 1 (same file)", cache.Size())
	}
}

func TestScanCache_SizeDisabled(t *testing.T) {
	cache := NewScanCache(false, t.TempDir())

	tmpFile, err := os.CreateTemp("", "test-*.go")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	cache.Set(tmpFile.Name(), []string{"finding"})
	if cache.Size() != 0 {
		t.Errorf("Size() = %d, want 0 (disabled)", cache.Size())
	}
}
