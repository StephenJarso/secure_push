package detectors

import (
	"testing"
)

func TestSecretsDetector_DetectAWSKey(t *testing.T) {
	d := &SecretsDetector{}
	got, err := d.Detect("aws_key = 'AKIAIOSFODNN7EXAMPLE'", "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}

func TestSecretsDetector_DetectDBURL(t *testing.T) {
	d := &SecretsDetector{}
	got, err := d.Detect("db_url = 'postgres://user:password@localhost:5432/mydb'", "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}

func TestSecretsDetector_DetectWebhook(t *testing.T) {
	d := &SecretsDetector{}
	got, err := d.Detect("webhook = 'https://example.com/webhook/callback'", "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}

func TestSecretsDetector_DetectMultipleSecrets(t *testing.T) {
	d := &SecretsDetector{}
	content := "password = 'secret123'\napikey = 'abcdefghijklmnopqrstuvwxyz1234567890'\ntoken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'"
	got, err := d.Detect(content, "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) < 3 {
		t.Errorf("Detect() returned %d findings, want at least 3", len(got))
	}
}

func TestSecretsDetector_DetectEmptyContent(t *testing.T) {
	d := &SecretsDetector{}
	got, err := d.Detect("", "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Detect() returned %d findings, want 0", len(got))
	}
}

func TestSecretsDetector_DetectCommentedLine(t *testing.T) {
	d := &SecretsDetector{}
	got, err := d.Detect("# password = 'secret123'", "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Detect() returned %d findings, want 0", len(got))
	}
}
