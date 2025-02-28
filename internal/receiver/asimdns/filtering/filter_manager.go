//go:build windows
// +build windows

package filtering

import (
	"github.com/0xrawsec/golang-etw/etw"
	"go.uber.org/zap"
	"sync"
	"sync/atomic"
	"time"
)

// EventTypeMapping represents a cached event type and subtype
type EventTypeMapping struct {
	Type    string
	SubType string
}

// FilterManager manages all filtering components
type FilterManager struct {
	logger             *zap.Logger
	eventTypeFilter    *EventTypeFilter
	domainFilter       *DomainFilter
	queryTypeFilter    *QueryTypeFilter
	deduplicationFilter *DeduplicationFilter
	
	// Counters for monitoring
	totalEvents        int64
	filteredEvents     int64
	
	// Function for accessing event data
	getEventDataFunc   func(*etw.Event, string) (string, bool)
	
	// Function for getting event type and subtype
	getEventTypeFunc   func(uint16) (string, string)
	
	// Cache for event type mapping
	eventTypeCache     map[uint16]EventTypeMapping
	eventTypeCacheMux  sync.RWMutex
}

// NewFilterManager creates a new filter manager
func NewFilterManager(
	logger *zap.Logger, 
	includeInfoEvents bool, 
	excludedEventIDs []uint16,
	excludedDomains []string,
	excludeAAAARecords bool,
	enableDeduplication bool,
	deduplicationWindow int,
	getEventDataFunc func(*etw.Event, string) (string, bool),
	getEventTypeFunc func(uint16) (string, string)) *FilterManager {
	
	manager := &FilterManager{
		logger:             logger,
		eventTypeFilter:    NewEventTypeFilter(logger, includeInfoEvents, excludedEventIDs),
		domainFilter:       NewDomainFilter(logger, excludedDomains),
		queryTypeFilter:    NewQueryTypeFilter(logger, excludeAAAARecords),
		deduplicationFilter: NewDeduplicationFilter(logger, enableDeduplication, deduplicationWindow),
		totalEvents:        0,
		filteredEvents:     0,
		getEventDataFunc:   getEventDataFunc,
		getEventTypeFunc:   getEventTypeFunc,
		eventTypeCache:     make(map[uint16]EventTypeMapping),
	}
	
	// Start cache maintenance routine if deduplication is enabled
	if enableDeduplication {
		go manager.startCacheMaintenanceRoutine()
	}
	
	logger.Info("Filter manager initialized with all components")
	
	return manager
}

// startCacheMaintenanceRoutine periodically cleans the deduplication cache
func (fm *FilterManager) startCacheMaintenanceRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		fm.deduplicationFilter.Cleanup()
	}
}

// ShouldFilter checks if an event should be filtered based on all filtering criteria
func (fm *FilterManager) ShouldFilter(event *etw.Event) bool {
	eventID := event.System.EventID
	
	// Increment total events counter
	atomic.AddInt64(&fm.totalEvents, 1)
	
	// Get event type and subtype (with caching for performance)
	eventType, eventSubType := fm.getEventTypeWithCache(eventID)
	
	// 1. Event Type Filtering
	if fm.eventTypeFilter.ShouldFilter(eventID, eventType, eventSubType) {
		atomic.AddInt64(&fm.filteredEvents, 1)
		return true
	}
	
	// 2. Domain Filtering for query events
	if (eventID == 3006 || eventID == 3008) && fm.domainFilter.ShouldFilter(event, fm.getEventDataFunc) {
		atomic.AddInt64(&fm.filteredEvents, 1)
		return true
	}
	
	// 3. AAAA Record Filtering
	if fm.queryTypeFilter.ShouldFilter(event, fm.getEventDataFunc) {
		atomic.AddInt64(&fm.filteredEvents, 1)
		return true
	}
	
	// 4. Query Deduplication
	if fm.deduplicationFilter.ShouldFilter(event, fm.getEventDataFunc) {
		atomic.AddInt64(&fm.filteredEvents, 1)
		return true
	}
	
	// If we reach here, the event should not be filtered
	return false
}

// getEventTypeWithCache retrieves event type with caching
func (fm *FilterManager) getEventTypeWithCache(eventID uint16) (string, string) {
	// Try to get from cache first
	fm.eventTypeCacheMux.RLock()
	cachedValue, exists := fm.eventTypeCache[eventID]
	fm.eventTypeCacheMux.RUnlock()
	
	if exists {
		return cachedValue.Type, cachedValue.SubType
	}
	
	// Get the event type using the stored function
	eventType, eventSubType := fm.getEventTypeFunc(eventID)
	
	// Cache the value for future use
	fm.eventTypeCacheMux.Lock()
	fm.eventTypeCache[eventID] = EventTypeMapping{
		Type: eventType, 
		SubType: eventSubType,
	}
	fm.eventTypeCacheMux.Unlock()
	
	return eventType, eventSubType
}

// GetTotalEvents returns the total number of events processed
func (fm *FilterManager) GetTotalEvents() int64 {
	return atomic.LoadInt64(&fm.totalEvents)
}

// GetFilteredEvents returns the number of events filtered
func (fm *FilterManager) GetFilteredEvents() int64 {
	return atomic.LoadInt64(&fm.filteredEvents)
}

// GetFilterPercentage returns the percentage of events filtered
func (fm *FilterManager) GetFilterPercentage() float64 {
	total := atomic.LoadInt64(&fm.totalEvents)
	filtered := atomic.LoadInt64(&fm.filteredEvents)
	
	if total == 0 {
		return 0
	}
	
	return float64(filtered) / float64(total) * 100
}
