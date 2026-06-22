package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WalkDir walks a directory and calls visit for each file
func WalkDir(path string, visit func(path string, info os.FileInfo) error) error {
	return filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if strings.HasPrefix(filepath.Base(filePath), ".") && filepath.Base(filePath) != "." {
				return filepath.SkipDir
			}
			return nil
		}

		return visit(filePath, info)
	})
}

// GetFileSize returns the size of a file
func GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// GetFileInfo returns file info for the given path, reusing stat calls
func GetFileInfo(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsDir checks if a path is a directory
func IsDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// GetRelativePath returns the relative path from base to path
func GetRelativePath(base, path string) (string, error) {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

// ValidatePath validates that a path exists and is a directory
func ValidatePath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("path does not exist: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", path)
	}

	return nil
}

// IsHiddenFile checks if a file is hidden (starts with .)
func IsHiddenFile(path string) bool {
	base := filepath.Base(path)
	return strings.HasPrefix(base, ".") && base != "." && base != ".."
}

// GetBaseName returns the base name of a file path
func GetBaseName(path string) string {
	return filepath.Base(path)
}
