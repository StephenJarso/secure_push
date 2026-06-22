package logger

import (
	"fmt"
	"io"
	"os"
	"time"
)

type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
)

type Logger struct {
	level  Level
	output io.Writer
}

func New(level Level) *Logger {
	return &Logger{
		level:  level,
		output: os.Stderr,
	}
}

// SetOutput changes the output destination for the logger
func (l *Logger) SetOutput(w io.Writer) {
	l.output = w
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() Level {
	return l.level
}

// IsDebugEnabled returns true if debug logging is enabled
func (l *Logger) IsDebugEnabled() bool {
	return l.level <= Debug
}

// IsInfoEnabled returns true if info logging is enabled
func (l *Logger) IsInfoEnabled() bool {
	return l.level <= Info
}

// IsWarnEnabled returns true if warn logging is enabled
func (l *Logger) IsWarnEnabled() bool {
	return l.level <= Warn
}

// IsErrorEnabled returns true if error logging is enabled
func (l *Logger) IsErrorEnabled() bool {
	return l.level <= Error
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level <= Debug {
		l.log("DEBUG", format, args...)
	}
}

func (l *Logger) Info(format string, args ...interface{}) {
	if l.level <= Info {
		l.log("INFO", format, args...)
	}
}

func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level <= Warn {
		l.log("WARN", format, args...)
	}
}

func (l *Logger) Error(format string, args ...interface{}) {
	if l.level <= Error {
		l.log("ERROR", format, args...)
	}
}

func (l *Logger) log(level, format string, args ...interface{}) {
	timestamp := time.Now().Format(time.RFC3339)
	message := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.output, "[%s] %s: %s\n", timestamp, level, message)
}
