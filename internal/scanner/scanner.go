package scanner

import (
	"os"
	"sync"
	"strings"
	"path/filepath"
	"github.com/stephenjarso/secure-push/internal/detectors"


	"golang.org/x/sync/errgroup"
)

type Scanner struct {
	detectors []detectors.Detector
}

func New(dets ...detectors.Detector) *Scanner {
	return &Scanner{detectors: dets}
}

func (s *Scanner) Scan(root string) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	var mu sync.Mutex
	var g errgroup.Group

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip hidden dirs like .git
			if strings.HasPrefix(filepath.Base(path), ".") && path != root {
				return filepath.SkipDir
			}
			return nil
		}

		g.Go(func() error {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			for _, det := range s.detectors {
				f, err := det.Detect(string(content), path)
				if err != nil {
					return err
				}
				if len(f) > 0 {
					mu.Lock()
					findings = append(findings, f...)
					mu.Unlock()
				}
			}
			return nil
		})
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return findings, err
}
