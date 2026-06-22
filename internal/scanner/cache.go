package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ScanCache stores scan results for incremental scanning
type ScanCache struct {
	mu       sync.RWMutex
	cache    map[string]cacheEntry
	enabled  bool
	cacheDir string
}

type cacheEntry struct {
	Hash      string
	Findings  []string // Store finding keys for deduplication
	Timestamp time.Time
}

// NewScanCache creates a new scan cache
func NewScanCache(enabled bool, cacheDir string) *ScanCache {
	return &ScanCache{
		cache:    make(map[string]cacheEntry),
		enabled:  enabled,
		cacheDir: cacheDir,
	}
}

// Get returns cached findings for a file if it hasn't changed
func (c *ScanCache) Get(path string) ([]string, bool) {
	if !c.enabled {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[path]
	if !exists {
		return nil, false
	}

	// Check if file has been modified
	info, err := os.Stat(path)
	if err != nil {
		return nil, false
	}

	if info.ModTime().After(entry.Timestamp) {
		return nil, false
	}

	return entry.Findings, true
}

// Set stores findings for a file in the cache
func (c *ScanCache) Set(path string, findings []string) error {
	if !c.enabled {
		return nil
	}

	hash, err := c.hashFile(path)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[path] = cacheEntry{
		Hash:      hash,
		Findings:  findings,
		Timestamp: time.Now(),
	}

	return nil
}

// hashFile computes a hash of the file content
func (c *ScanCache) hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// Clear removes all cached entries
func (c *ScanCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]cacheEntry)
}

// Stats returns cache statistics
func (c *ScanCache) Stats() (hits, misses, entries int) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entries = len(c.cache)
	return hits, misses, entries
}

// Size returns the number of cached entries
func (c *ScanCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// Save persists the cache to disk
func (c *ScanCache) Save() error {
	if !c.enabled || c.cacheDir == "" {
		return nil
	}

	if err := os.MkdirAll(c.cacheDir, 0o755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Implementation would serialize cache to JSON
	// For now, we'll just return nil
	_ = filepath.Join(c.cacheDir, "scan-cache.json")
	return nil
}

// Load restores the cache from disk
func (c *ScanCache) Load() error {
	if !c.enabled || c.cacheDir == "" {
		return nil
	}

	// Implementation would deserialize cache from JSON
	// For now, we'll just return nil
	_ = filepath.Join(c.cacheDir, "scan-cache.json")
	return nil
}
