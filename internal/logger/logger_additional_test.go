package logger

import (
	"testing"
)

func TestLogger_GetLevel(t *testing.T) {
	tests := []struct {
		level Level
		want  Level
	}{
		{Debug, Debug},
		{Info, Info},
		{Warn, Warn},
		{Error, Error},
	}

	for _, tt := range tests {
		l := New(tt.level)
		if got := l.GetLevel(); got != tt.want {
			t.Errorf("GetLevel() = %v, want %v", got, tt.want)
		}
	}
}

func TestLogger_IsDebugEnabled(t *testing.T) {
	l := New(Debug)
	if !l.IsDebugEnabled() {
		t.Error("IsDebugEnabled() should be true for Debug level")
	}

	l = New(Info)
	if l.IsDebugEnabled() {
		t.Error("IsDebugEnabled() should be false for Info level")
	}
}

func TestLogger_IsInfoEnabled(t *testing.T) {
	l := New(Info)
	if !l.IsInfoEnabled() {
		t.Error("IsInfoEnabled() should be true for Info level")
	}

	l = New(Warn)
	if l.IsInfoEnabled() {
		t.Error("IsInfoEnabled() should be false for Warn level")
	}
}

func TestLogger_IsWarnEnabled(t *testing.T) {
	l := New(Warn)
	if !l.IsWarnEnabled() {
		t.Error("IsWarnEnabled() should be true for Warn level")
	}

	l = New(Error)
	if l.IsWarnEnabled() {
		t.Error("IsWarnEnabled() should be false for Error level")
	}
}

func TestLogger_IsErrorEnabled(t *testing.T) {
	l := New(Error)
	if !l.IsErrorEnabled() {
		t.Error("IsErrorEnabled() should be true for Error level")
	}
}
