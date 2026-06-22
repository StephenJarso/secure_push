package scanner

import (
	"testing"

	"secure-push/internal/config"
	"secure-push/internal/detectors"
	"secure-push/internal/logger"
)

func TestScanner_GetCache(t *testing.T) {
	cfg := config.DefaultConfig()
	log := logger.New(logger.Info)

	detectorList := []detectors.Detector{
		&detectors.EnvDetector{},
	}

	s := New(detectorList, cfg, log)
	cache := s.GetCache()

	if cache == nil {
		t.Error("GetCache() returned nil")
	}
}

func TestScanner_GetDetectorCount(t *testing.T) {
	cfg := config.DefaultConfig()
	log := logger.New(logger.Info)

	detectorList := []detectors.Detector{
		&detectors.EnvDetector{},
		&detectors.SecretsDetector{},
		&detectors.AuthDetector{},
	}

	s := New(detectorList, cfg, log)
	count := s.GetDetectorCount()

	if count != 3 {
		t.Errorf("GetDetectorCount() = %d, want 3", count)
	}
}

func TestScanner_GetDetectorCountEmpty(t *testing.T) {
	cfg := config.DefaultConfig()
	log := logger.New(logger.Info)

	s := New([]detectors.Detector{}, cfg, log)
	count := s.GetDetectorCount()

	if count != 0 {
		t.Errorf("GetDetectorCount() = %d, want 0", count)
	}
}
