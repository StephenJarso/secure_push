package detectors

import (
	"testing"
)

func TestAuthDetector_DetectSlackToken(t *testing.T) {
	d := &AuthDetector{}
	got, err := d.Detect("slack_token = 'xoxb-test0000000-test00000000000-TESTTESTTEST'", "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}

func TestAuthDetector_DetectDiscordWebhook(t *testing.T) {
	d := &AuthDetector{}
	got, err := d.Detect("discord_webhook = 'https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'", "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}

func TestAuthDetector_DetectTelegramBotToken(t *testing.T) {
	d := &AuthDetector{}
	got, err := d.Detect("telegram_token = '1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghiJKLMNO'", "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}

func TestAuthDetector_DetectAzureKeyVault(t *testing.T) {
	d := &AuthDetector{}
	got, err := d.Detect("-----BEGIN AZURE KEY VAULT-----\nkey-data\n-----END AZURE KEY VAULT-----", "azure.key")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}

func TestAuthDetector_DetectPersonalAccessToken(t *testing.T) {
	d := &AuthDetector{}
	got, err := d.Detect("pat = 'abc123def456ghij789klmn.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ'", "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}

func TestAuthDetector_DetectFigmaToken(t *testing.T) {
	d := &AuthDetector{}
	got, err := d.Detect("figma_token = 'figd_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH'", "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}

func TestAuthDetector_DetectNotionToken(t *testing.T) {
	d := &AuthDetector{}
	got, err := d.Detect("notion_token = 'secret_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs'", "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}

func TestAuthDetector_DetectLinearToken(t *testing.T) {
	d := &AuthDetector{}
	got, err := d.Detect("linear_api_token = 'lin_api_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH'", "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}

func TestAuthDetector_DetectIntercomToken(t *testing.T) {
	d := &AuthDetector{}
	got, err := d.Detect("intercom_token = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH'", "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}
