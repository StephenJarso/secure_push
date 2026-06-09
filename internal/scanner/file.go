package scanner

import (
	"os"
	"path/filepath"
)

func IsBinaryFile(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	buffer := make([]byte, 512)
	_, err = file.Read(buffer)
	if err != nil {
		return false, err
	}

	return IsBinary(buffer), nil
}

func IsBinary(data []byte) bool {
	for _, b := range data[:min(len(data), 512)] {
		if b == 0 {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func GetFileExtension(path string) string {
	return filepath.Ext(path)
}

func IsTextFile(path string) (bool, error) {
	isBinary, err := IsBinaryFile(path)
	return !isBinary, err
}
