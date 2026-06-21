package utils

import (
	"regexp"
)

// CompileRegex compiles a regex pattern with error handling
func CompileRegex(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile(pattern)
}

// MatchString checks if a string matches a regex pattern
func MatchString(pattern, s string) (bool, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(s), nil
}

// FindAllString finds all matches of a pattern in a string
func FindAllString(pattern, s string) ([]string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return re.FindAllString(s, -1), nil
}

// FindAllStringSubmatch finds all matches including submatches
func FindAllStringSubmatch(pattern, s string) ([][]string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return re.FindAllStringSubmatch(s, -1), nil
}

// MustCompile panics if the pattern cannot be compiled
func MustCompile(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
