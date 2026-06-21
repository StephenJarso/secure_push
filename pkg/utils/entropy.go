package utils

import (
	"math"
)

// CalculateEntropy calculates the Shannon entropy of a byte slice
// Used to detect high-entropy strings that may be secrets
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count frequency of each byte
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate Shannon entropy
	entropy := 0.0
	length := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// IsHighEntropy checks if data has high entropy (likely a secret)
// Returns true if entropy is above the threshold
func IsHighEntropy(data []byte, threshold float64) bool {
	return CalculateEntropy(data) >= threshold
}

// IsBase64Encoded checks if a string appears to be base64 encoded
func IsBase64Encoded(s string) bool {
	if len(s) < 16 {
		return false
	}

	// Check for base64 character set
	base64Chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	for _, c := range s {
		if !containsRune(base64Chars, c) {
			return false
		}
	}

	// Check for padding
	if len(s)%4 == 0 {
		return true
	}

	return false
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
