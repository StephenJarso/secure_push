package detectors

import (
	"path/filepath"
	"strings"
)

type ConfigDetector struct{}

func (d *ConfigDetector) Name() string {
	return "CONFIG_FILE"
}

func (d *ConfigDetector) Severity() Severity {
	return High
}

var configExtensions = map[string]bool{
	".yaml": true, ".yml": true, ".json": true, ".xml": true,
	".toml": true, ".ini": true, ".cfg": true, ".conf": true,
	".properties": true, ".envrc": true,
}

var configFilenames = map[string]bool{
	"config": true, "configuration": true, "settings": true,
	"application": true, "appsettings": true, "web.config": true,
	"app.config": true, "package.json": true, "composer.json": true,
	"pom.xml": true, "build.gradle": true, "requirements.txt": true,
	"gemfile": true, "dockerfile": true, "docker-compose.yml": true,
	"docker-compose.yaml": true, "makefile": true, "cmakelists.txt": true,
	"secure-push.yaml": true, ".secure-push.yaml": true, "secure-push.yml": true,
	".secure-push.yml": true, "config.yaml": true, "config.yml": true,
}

func (d *ConfigDetector) Detect(content string, filename string) ([]Finding, error) {
	base := strings.ToLower(filepath.Base(filename))
	ext := filepath.Ext(base)

	// Check for .env.* files (e.g., .env.local, .env.production)
	if strings.HasPrefix(base, ".env") {
		return []Finding{{
			Rule:     d.Name(),
			Severity: d.Severity(),
			File:     filename,
			Line:     1,
			Message:  "Config file detected - review for sensitive data",
		}}, nil
	}

	if configExtensions[ext] {
		return []Finding{{
			Rule:     d.Name(),
			Severity: d.Severity(),
			File:     filename,
			Line:     1,
			Message:  "Config file detected - review for sensitive data",
		}}, nil
	}

	if configFilenames[base] {
		return []Finding{{
			Rule:     d.Name(),
			Severity: d.Severity(),
			File:     filename,
			Line:     1,
			Message:  "Config file detected - review for sensitive data",
		}}, nil
	}

	return nil, nil
}
