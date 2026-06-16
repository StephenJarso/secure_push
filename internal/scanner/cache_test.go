package scanner

import (
	"os"
	"testing"
	"time"
)

func TestScanCache_GetSet(t *testing.T) {
	cache := NewScanCache(true, t.TempDir())

	tmpFile, err := os.CreateTemp("", "test-*.go")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	findings := []string{"finding1", "finding2"}
	err = cache.Set(tmpFile.Name(), findings)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	got, found := cache.Get(tmpFile.Name())
	if !found {
		t.Error("Expected cache hit")
	}
	if len(got) != 2 {
		t.Errorf("Got %d findings, want 2", len(got))
	}
}

func TestScanCache_Miss(t *testing.T) {
	cache := NewScanCache(true, t.TempDir())

	_, found := cache.Get("/nonexistent/file.go")
	if found {
		t.Error("Expected cache miss")
	}
}

func TestScanCache_Disabled(t *testing.T) {
	cache := NewScanCache(false, t.TempDir())

	tmpFile, err := os.CreateTemp("", "test-*.go")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	err = cache.Set(tmpFile.Name(), []string{"finding"})
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	_, found := cache.Get(tmpFile.Name())
	if found {
		t.Error("Expected cache miss when disabled")
	}
}

func TestScanCache_Clear(t *testing.T) {
	cache := NewScanCache(true, t.TempDir())

	tmpFile, err := os.CreateTemp("", "test-*.go")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	cache.Set(tmpFile.Name(), []string{"finding"})
	cache.Clear()

	_, found := cache.Get(tmpFile.Name())
	if found {
		t.Error("Expected cache miss after clear")
	}
}

func TestScanCache_ModifiedFile(t *testing.T) {
	cache := NewScanCache(true, t.TempDir())

	tmpFile, err := os.CreateTemp("", "test-*.go")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	cache.Set(tmpFile.Name(), []string{"finding"})

	// Wait a bit and modify the file
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(tmpFile.Name(), []byte("modified content"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, found := cache.Get(tmpFile.Name())
	if found {
		t.Error("Expected cache miss for modified file")
	}
}

func TestScanCache_Stats(t *testing.T) {
	cache := NewScanCache(true, t.TempDir())

	tmpFile1, err := os.CreateTemp("", "test1-*.go")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile1.Name())

	tmpFile2, err := os.CreateTemp("", "test2-*.go")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile2.Name())

	cache.Set(tmpFile1.Name(), []string{"finding1"})
	cache.Set(tmpFile2.Name(), []string{"finding2"})

	_, _, entries := cache.Stats()
	if entries != 2 {
		t.Errorf("Expected 2 entries, got %d", entries)
	}
}
