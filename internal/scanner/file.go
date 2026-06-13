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
	n, err := file.Read(buffer)
	if err != nil && err.Error() != "EOF" {
		return false, err
	}

	return IsBinary(buffer[:n]), nil
}

func IsBinary(data []byte) bool {
	checkLen := len(data)
	if checkLen > 512 {
		checkLen = 512
	}
	for i := 0; i < checkLen; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

func GetFileExtension(path string) string {
	return filepath.Ext(path)
}

func IsTextFile(path string) (bool, error) {
	isBinary, err := IsBinaryFile(path)
	return !isBinary, err
}
