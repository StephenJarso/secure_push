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
