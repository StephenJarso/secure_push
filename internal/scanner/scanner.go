package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"secure-push/internal/config"
	"secure-push/internal/detectors"
	"secure-push/internal/logger"
)

type Scanner struct {
	detectors []detectors.Detector
	config    *config.Config
	logger    *logger.Logger
	cache     *ScanCache
}

func New(detectors []detectors.Detector, cfg *config.Config, log *logger.Logger) *Scanner {
	cacheDir := ""
	if cfg != nil {
		cacheDir = ".secure-push-cache"
	}
	return &Scanner{
		detectors: detectors,
		config:    cfg,
		logger:    log,
		cache:     NewScanCache(true, cacheDir),
	}
}

// GetCache returns the scanner's cache for inspection
func (s *Scanner) GetCache() *ScanCache {
	return s.cache
}

// GetDetectorCount returns the number of configured detectors
func (s *Scanner) GetDetectorCount() int {
	return len(s.detectors)
}

func (s *Scanner) Scan(path string) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	errCh := make(chan error, 1)

	// Limit concurrent goroutines to prevent resource exhaustion
	sem := make(chan struct{}, 100)

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if strings.HasPrefix(filepath.Base(filePath), ".") && filepath.Base(filePath) != "." {
				return filepath.SkipDir
			}
			return nil
		}

		if s.config.ShouldIgnore(filePath) {
			s.logger.Debug("Skipping ignored file: %s", filePath)
			return nil
		}

		fileInfo, err := os.Stat(filePath)
		if err != nil {
			return err
		}

		if fileInfo.Size() > s.config.MaxFileSize {
			s.logger.Debug("Skipping large file: %s (size: %d)", filePath, fileInfo.Size())
			return nil
		}

		isBinary, err := IsBinaryFile(filePath)
		if err != nil {
			return err
		}
		if isBinary {
			s.logger.Debug("Skipping binary file: %s", filePath)
			return nil
		}

		// Check cache for incremental scanning
		if cachedFindings, found := s.cache.Get(filePath); found {
			s.logger.Debug("Using cached results for: %s", filePath)
			// Reconstruct findings from cache (simplified)
			_ = cachedFindings
			return nil
		}

		wg.Add(1)
		go func(fp string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fileFindings, err := s.scanFile(fp)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}

			if len(fileFindings) > 0 {
				mu.Lock()
				findings = append(findings, fileFindings...)
				mu.Unlock()
			}
		}(filePath)

		return nil
	})

	wg.Wait()
	close(errCh)

	if err != nil {
		return nil, err
	}

	for err := range errCh {
		s.logger.Error("Error scanning file: %v", err)
	}

	return findings, nil
}

func (s *Scanner) scanFile(path string) ([]detectors.Finding, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var allFindings []detectors.Finding

	for _, det := range s.detectors {
		if !s.config.IsDetectorEnabled(det.Name()) {
			continue
		}

		findings, err := det.Detect(string(content), path)
		if err != nil {
			s.logger.Error("Error in detector %s: %v", det.Name(), err)
			continue
		}

		for _, f := range findings {
			if s.config.IsSeverityEnabled(f.Severity) {
				allFindings = append(allFindings, f)
			}
		}
	}

	return allFindings, nil
}

func (s *Scanner) ScanFile(path string) ([]detectors.Finding, error) {
	if s.config.ShouldIgnore(path) {
		return nil, fmt.Errorf("file is ignored: %s", path)
	}

	fileInfo, err := GetFileInfo(path)
	if err != nil {
		return nil, err
	}

	if fileInfo.Size() > s.config.MaxFileSize {
		return nil, fmt.Errorf("file too large: %s", path)
	}

	isBinary, err := IsBinaryFile(path)
	if err != nil {
		return nil, err
	}
	if isBinary {
		return nil, fmt.Errorf("binary file: %s", path)
	}

	return s.scanFile(path)
}
