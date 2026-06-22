package scanner

import (
	"testing"
)

func TestWorkerPool_GetWorkerCount(t *testing.T) {
	pool := NewWorkerPool(20)
	if pool.GetWorkerCount() != 20 {
		t.Errorf("GetWorkerCount() = %d, want 20", pool.GetWorkerCount())
	}
}

func TestWorkerPool_NewWorkerPool(t *testing.T) {
	pool := NewWorkerPool(10)
	if pool == nil {
		t.Error("NewWorkerPool() returned nil")
	}
	if pool.workers != 10 {
		t.Errorf("workers = %d, want 10", pool.workers)
	}
}
