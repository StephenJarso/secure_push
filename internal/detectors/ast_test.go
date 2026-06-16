package detectors

import (
	"testing"
)

func TestASTDetector_Name(t *testing.T) {
	d := &ASTDetector{}
	if got := d.Name(); got != "AST_ANALYSIS" {
		t.Errorf("Name() = %v, want %v", got, "AST_ANALYSIS")
	}
}

func TestASTDetector_Severity(t *testing.T) {
	d := &ASTDetector{}
	if got := d.Severity(); got != Medium {
		t.Errorf("Severity() = %v, want %v", got, Medium)
	}
}

func TestASTDetector_Detect_NonGoFile(t *testing.T) {
	d := &ASTDetector{}
	got, err := d.Detect("some content", "test.txt")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Detect() returned %d findings, want 0", len(got))
	}
}

func TestASTDetector_Detect_InvalidGo(t *testing.T) {
	d := &ASTDetector{}
	got, err := d.Detect("this is not valid go code", "test.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Detect() returned %d findings, want 0", len(got))
	}
}

func TestASTDetector_Detect_DangerousFunction(t *testing.T) {
	d := &ASTDetector{}
	content := `package main

import "os/exec"

func main() {
	exec.Command("ls")
}`
	got, err := d.Detect(content, "test.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Detect() returned %d findings, want 1", len(got))
	}
	if got[0].Rule != "AST_ANALYSIS" {
		t.Errorf("Rule = %v, want AST_ANALYSIS", got[0].Rule)
	}
}

func TestASTDetector_Detect_HardcodedCredential(t *testing.T) {
	d := &ASTDetector{}
	content := `package main

func main() {
	password := "secret123"
}`
	got, err := d.Detect(content, "test.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
	if got[0].Severity != High {
		t.Errorf("Severity = %v, want HIGH", got[0].Severity)
	}
}

func TestASTDetector_Detect_NoIssues(t *testing.T) {
	d := &ASTDetector{}
	content := `package main

import "fmt"

func main() {
	fmt.Println("hello")
}`
	got, err := d.Detect(content, "test.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Detect() returned %d findings, want 0", len(got))
	}
}
