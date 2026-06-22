package scanner

// Parallel scanning utilities for improved performance
// This file contains helper functions for concurrent file processing

// MaxConcurrentFiles limits the number of files processed concurrently
const MaxConcurrentFiles = 100

// DefaultWorkerCount is the default number of worker goroutines
const DefaultWorkerCount = 10

// WorkerPool manages a pool of worker goroutines for parallel processing
type WorkerPool struct {
	workers int
	jobs    chan func()
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workers int) *WorkerPool {
	return &WorkerPool{
		workers: workers,
		jobs:    make(chan func()),
	}
}

// Start begins processing jobs
func (p *WorkerPool) Start() {
	for i := 0; i < p.workers; i++ {
		go func() {
			for job := range p.jobs {
				job()
			}
		}()
	}
}

// Submit adds a job to the pool
func (p *WorkerPool) Submit(job func()) {
	p.jobs <- job
}

// Stop stops the worker pool
func (p *WorkerPool) Stop() {
	close(p.jobs)
}

// GetWorkerCount returns the number of workers
func (p *WorkerPool) GetWorkerCount() int {
	return p.workers
}
