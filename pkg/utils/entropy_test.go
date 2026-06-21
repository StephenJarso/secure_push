package utils

import (
	"math"
	"testing"
)

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected float64
	}{
		{"empty", []byte{}, 0},
		{"single char", []byte("a"), 0},
		{"repeated chars", []byte("aaaa"), 0},
		{"mixed case", []byte("abc"), 1.584962500721156},
		{"all unique", []byte("abcd"), 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateEntropy(tt.data)
			if math.Abs(got-tt.expected) > 0.0001 {
				t.Errorf("CalculateEntropy() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsHighEntropy(t *testing.T) {
	// High entropy data (random-looking)
	highEntropy := []byte("xK9mN2pQ5rS8tV1w")
	if !IsHighEntropy(highEntropy, 3.0) {
		t.Error("Expected high entropy data to be detected")
	}

	// Low entropy data (repeated)
	lowEntropy := []byte("aaaaaaaaaaaaaaaa")
	if IsHighEntropy(lowEntropy, 3.0) {
		t.Error("Expected low entropy data to not be detected")
	}
}

func TestIsBase64Encoded(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid base64", "SGVsbG9Xb3Jrcw==", true},
		{"valid base64 no padding", "SGVsbG9Xb3Jrcw", false}, // Too short for our check
		{"too short", "abc", false},
		{"invalid chars", "abc$def", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBase64Encoded(tt.input)
			if got != tt.expected {
				t.Errorf("IsBase64Encoded() = %v, want %v", got, tt.expected)
			}
		})
	}
}
