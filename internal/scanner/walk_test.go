package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWalkDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some files
	files := []string{"file1.txt", "file2.txt", "subdir/file3.txt"}
	for _, f := range files {
		fullPath := filepath.Join(tmpDir, f)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var visited []string
	err := WalkDir(tmpDir, func(path string, info os.FileInfo) error {
		visited = append(visited, filepath.Base(path))
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir() error = %v", err)
	}

	if len(visited) != 3 {
		t.Errorf("WalkDir() visited %d files, want 3", len(visited))
	}
}

func TestWalkDirSkipsHiddenDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	hiddenDir := filepath.Join(tmpDir, ".hidden")
	if err := os.MkdirAll(hiddenDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hiddenFile := filepath.Join(hiddenDir, "secret.txt")
	if err := os.WriteFile(hiddenFile, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	var visited []string
	err := WalkDir(tmpDir, func(path string, info os.FileInfo) error {
		visited = append(visited, filepath.Base(path))
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir() error = %v", err)
	}
	if len(visited) != 0 {
		t.Errorf("WalkDir() visited %d files, want 0", len(visited))
	}
}

func TestGetFileSize(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	content := []byte("test content")
	if _, err := tmpFile.Write(content); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	size, err := GetFileSize(tmpFile.Name())
	if err != nil {
		t.Fatalf("GetFileSize() error = %v", err)
	}

	if size != int64(len(content)) {
		t.Errorf("GetFileSize() = %d, want %d", size, len(content))
	}
}

func TestFileExists(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	if !FileExists(tmpFile.Name()) {
		t.Error("FileExists() = false, want true for existing file")
	}

	if FileExists("/nonexistent/path") {
		t.Error("FileExists() = true, want false for non-existing file")
	}
}

func TestIsDir(t *testing.T) {
	tmpDir := t.TempDir()

	if !IsDir(tmpDir) {
		t.Error("IsDir() = false, want true for directory")
	}

	tmpFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	if IsDir(tmpFile.Name()) {
		t.Error("IsDir() = true, want false for file")
	}
}

func TestGetRelativePath(t *testing.T) {
	base := "/home/user/project"
	path := "/home/user/project/src/main.go"

	rel, err := GetRelativePath(base, path)
	if err != nil {
		t.Fatalf("GetRelativePath() error = %v", err)
	}

	if rel != "src/main.go" {
		t.Errorf("GetRelativePath() = %s, want src/main.go", rel)
	}
}

func TestGetRelativePathError(t *testing.T) {
	_, err := GetRelativePath("/tmp/secure-push-a", "/tmp/secure-push-b")
	if err == nil {
		t.Fatal("GetRelativePath() error = nil, want error")
	}
}

func TestValidatePath(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		err := ValidatePath("")
		if err == nil {
			t.Error("ValidatePath() should return error for empty path")
		}
	})

	t.Run("nonexistent path", func(t *testing.T) {
		err := ValidatePath("/nonexistent/path")
		if err == nil {
			t.Error("ValidatePath() should return error for nonexistent path")
		}
	})

	t.Run("file path", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "test-*.txt")
		if err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()
		defer os.Remove(tmpFile.Name())

		err = ValidatePath(tmpFile.Name())
		if err == nil {
			t.Error("ValidatePath() should return error for file path")
		}
	})

	t.Run("valid directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := ValidatePath(tmpDir)
		if err != nil {
			t.Errorf("ValidatePath() error = %v, want nil", err)
		}
	})
}

func TestGetFileInfo(t *testing.T) {
	t.Run("existing file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "test-*.txt")
		if err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()
		defer os.Remove(tmpFile.Name())

		info, err := GetFileInfo(tmpFile.Name())
		if err != nil {
			t.Fatalf("GetFileInfo() error = %v", err)
		}

		if info == nil {
			t.Error("GetFileInfo() returned nil info")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := GetFileInfo("/nonexistent/file.txt")
		if err == nil {
			t.Error("GetFileInfo() should return error for nonexistent file")
		}
	})
}
