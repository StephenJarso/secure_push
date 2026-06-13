package scanner

// Parallel scanning utilities for improved performance
// This file contains helper functions for concurrent file processing

// MaxConcurrentFiles limits the number of files processed concurrently
const MaxConcurrentFiles = 100

// DefaultWorkerCount is the default number of worker goroutines
const DefaultWorkerCount = 10
