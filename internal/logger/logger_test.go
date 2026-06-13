package logger

import (
	"bytes"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	log := New(Debug)
	if log == nil {
		t.Error("New() returned nil")
	}
	if log.level != Debug {
		t.Errorf("level = %d, want %d", log.level, Debug)
	}
}

func TestDebug(t *testing.T) {
	var buf bytes.Buffer
	log := &Logger{level: Debug, output: &buf}
	log.Debug("test message: %s", "value")

	if !strings.Contains(buf.String(), "DEBUG") {
		t.Error("Debug() did not output DEBUG level")
	}
	if !strings.Contains(buf.String(), "test message") {
		t.Error("Debug() did not output message")
	}
}

func TestInfo(t *testing.T) {
	var buf bytes.Buffer
	log := &Logger{level: Info, output: &buf}
	log.Info("info message")

	if !strings.Contains(buf.String(), "INFO") {
		t.Error("Info() did not output INFO level")
	}
}

func TestWarn(t *testing.T) {
	var buf bytes.Buffer
	log := &Logger{level: Warn, output: &buf}
	log.Warn("warn message")

	if !strings.Contains(buf.String(), "WARN") {
		t.Error("Warn() did not output WARN level")
	}
}

func TestError(t *testing.T) {
	var buf bytes.Buffer
	log := &Logger{level: Error, output: &buf}
	log.Error("error message")

	if !strings.Contains(buf.String(), "ERROR") {
		t.Error("Error() did not output ERROR level")
	}
}

func TestLogLevelFiltering(t *testing.T) {
	tests := []struct {
		name     string
		level    Level
		debugMsg string
		infoMsg  string
	}{
		{"debug level", Debug, "show", "show"},
		{"info level", Info, "", "show"},
		{"warn level", Warn, "", ""},
		{"error level", Error, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := &Logger{level: tt.level, output: &buf}

			log.Debug("debug")
			log.Info("info")

			if tt.debugMsg == "show" && !strings.Contains(buf.String(), "DEBUG") {
				t.Error("expected DEBUG output")
			}
			if tt.debugMsg == "" && strings.Contains(buf.String(), "DEBUG") {
				t.Error("unexpected DEBUG output")
			}
		})
	}
}
