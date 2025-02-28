//go:build windows
// +build windows

package filtering

import (
	"fmt"
	"github.com/0xrawsec/golang-etw/etw"
	"go.uber.org/zap"
	"sync"
	"time"
)

// DeduplicationFilter handles query deduplication
type DeduplicationFilter struct {
	logger         *zap.Logger
	enabled        bool
	window         time.Duration
	recentQueries  map[string]time.Time
	recentQueriesMux sync.RWMutex
}

// NewDeduplicationFilter creates a new DeduplicationFilter
func NewDeduplicationFilter(logger *zap.Logger, enabled bool, windowSeconds int) *DeduplicationFilter {
	filter := &DeduplicationFilter{
		logger:         logger,
		enabled:        enabled,
		window:         time.Duration(windowSeconds) * time.Second,
		recentQueries:  make(map[string]time.Time),
	}
	
	logger.Info("Deduplication filter initialized", 
		zap.Bool("enabled", enabled),
		zap.Int("windowSeconds", windowSeconds))
	
	return filter
}

// ShouldFilter checks if a query should be filtered due to deduplication
func (f *DeduplicationFilter) ShouldFilter(event *etw.Event, getEventDataString func(*etw.Event, string) (string, bool)) bool {
	// If deduplication is disabled, don't filter
	if !f.enabled {
		return false
	}
	
	// Only deduplicate query events
	if event.System.EventID != 3006 {
		return false
	}
	
	// Extract the query name and type
	queryName, nameOk := getEventDataString(event, "QueryName")
	queryType, typeOk := getEventDataString(event, "QueryType")
	
	if !nameOk || !typeOk || queryName == "" {
		return false
	}
	
	// Create a cache key combining name and type
	cacheKey := fmt.Sprintf("%s:%s", queryName, queryType)
	
	// Check if this query exists in the cache
	f.recentQueriesMux.RLock()
	lastSeen, exists := f.recentQueries[cacheKey]
	f.recentQueriesMux.RUnlock()
	
	// If it exists and is within the deduplication window, filter it
	now := time.Now()
	if exists && now.Sub(lastSeen) < f.window {
		f.logger.Debug("Filtering duplicate query", 
			zap.String("domain", queryName),
			zap.String("type", queryType),
			zap.Duration("age", now.Sub(lastSeen)))
		return true
	}
	
	// Otherwise, update the cache with current time
	f.recentQueriesMux.Lock()
	f.recentQueries[cacheKey] = now
	
	// Prune cache occasionally when it gets too large
	if len(f.recentQueries) > 10000 {
		for k, t := range f.recentQueries {
			if now.Sub(t) > f.window {
				delete(f.recentQueries, k)
			}
		}
	}
	f.recentQueriesMux.Unlock()
	
	return false
}

// GetCacheSize returns the current size of the deduplication cache
func (f *DeduplicationFilter) GetCacheSize() int {
	f.recentQueriesMux.RLock()
	defer f.recentQueriesMux.RUnlock()
	
	return len(f.recentQueries)
}

// Cleanup performs maintenance on the deduplication cache
func (f *DeduplicationFilter) Cleanup() {
	f.recentQueriesMux.Lock()
	defer f.recentQueriesMux.Unlock()
	
	now := time.Now()
	beforeSize := len(f.recentQueries)
	
	for k, t := range f.recentQueries {
		if now.Sub(t) > f.window {
			delete(f.recentQueries, k)
		}
	}
	
	afterSize := len(f.recentQueries)
	
	if beforeSize != afterSize {
		f.logger.Debug("Cleaned deduplication cache",
			zap.Int("beforeSize", beforeSize),
			zap.Int("afterSize", afterSize),
			zap.Int("removed", beforeSize - afterSize))
	}
}
