//go:build windows
// +build windows

package filtering

import (
	"go.uber.org/zap"
)

// EventTypeFilter handles filtering based on event type and IDs
type EventTypeFilter struct {
	logger          *zap.Logger
	includeInfoEvents bool
	excludedEventIDs map[uint16]bool
}

// NewEventTypeFilter creates a new EventTypeFilter
func NewEventTypeFilter(logger *zap.Logger, includeInfoEvents bool, excludedEventIDs []uint16) *EventTypeFilter {
	filter := &EventTypeFilter{
		logger:          logger,
		includeInfoEvents: includeInfoEvents,
		excludedEventIDs: make(map[uint16]bool),
	}
	
	// Initialize the excluded event IDs map
	for _, id := range excludedEventIDs {
		filter.excludedEventIDs[id] = true
		logger.Debug("Added excluded event ID", zap.Uint16("eventID", id))
	}
	
	logger.Info("Event type filter initialized", 
		zap.Bool("includeInfoEvents", includeInfoEvents),
		zap.Int("excludedEventIDsCount", len(excludedEventIDs)))
	
	return filter
}

// ShouldFilter checks if an event ID should be filtered
func (f *EventTypeFilter) ShouldFilter(eventID uint16, eventType, eventSubType string) bool {
	// Check if it's in the excluded event IDs list
	if f.excludedEventIDs != nil && f.excludedEventIDs[eventID] {
		f.logger.Debug("Filtering event by ID", zap.Uint16("eventID", eventID))
		return true
	}
	
	// Check if it's an "Info" event that should be excluded
	if !f.includeInfoEvents && eventType == "Info" {
		f.logger.Debug("Filtering Info event", 
			zap.Uint16("eventID", eventID),
			zap.String("eventType", eventType),
			zap.String("eventSubType", eventSubType))
		return true
	}
	
	return false
}
