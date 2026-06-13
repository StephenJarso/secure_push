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
	".properties": true,
}

var configFilenames = map[string]bool{
	"config": true, "configuration": true, "settings": true,
	"application": true, "appsettings": true, "web.config": true,
	"app.config": true, "package.json": true, "composer.json": true,
	"pom.xml": true, "build.gradle": true, "requirements.txt": true,
	"gemfile": true, "dockerfile": true, "docker-compose.yml": true,
	"docker-compose.yaml": true, "makefile": true, "cmakelists.txt": true,
}

func (d *ConfigDetector) Detect(content string, filename string) ([]Finding, error) {
	base := filepath.Base(filename)
	ext := strings.ToLower(filepath.Ext(base))
	name := strings.ToLower(base)

	if configExtensions[ext] {
		return []Finding{{
			Rule:     d.Name(),
			Severity: d.Severity(),
			File:     filename,
			Line:     1,
			Message:  "Config file detected - review for sensitive data",
		}}, nil
	}

	if configFilenames[name] {
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
