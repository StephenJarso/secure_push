package detectors

import (
	"path/filepath"
	"strings"
)

type EnvDetector struct{}

func (d *EnvDetector) Name() string {
	return "ENV_FILE"
}

func (d *EnvDetector) Severity() Severity {
	return Critical
}

func (d *EnvDetector) Detect(content string, filename string) ([]Finding, error) {
	base := filepath.Base(filename)
	lower := strings.ToLower(base)

	// Match .env, .env.local, .env.development, .env.production, .env.test, .envrc, .env.sample, etc.
	if strings.HasPrefix(lower, ".env") || lower == ".envrc" {
		return []Finding{{
			Rule:     d.Name(),
			Severity: d.Severity(),
			File:     filename,
			Line:     1,
			Message:  ".env file should not be committed",
		}}, nil
	}

	// Match env files like env, env.local, env.development, etc.
	if lower == "env" || strings.HasPrefix(lower, "env.") {
		return []Finding{{
			Rule:     d.Name(),
			Severity: d.Severity(),
			File:     filename,
			Line:     1,
			Message:  "env file should not be committed",
		}}, nil
	}

	return nil, nil
}
