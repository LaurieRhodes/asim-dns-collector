//go:build windows
// +build windows

package filtering

import (
	"github.com/0xrawsec/golang-etw/etw"
	"go.uber.org/zap"
)

// QueryTypeFilter handles filtering based on query type
type QueryTypeFilter struct {
	logger            *zap.Logger
	excludeAAAARecords bool
}

// NewQueryTypeFilter creates a new QueryTypeFilter
func NewQueryTypeFilter(logger *zap.Logger, excludeAAAARecords bool) *QueryTypeFilter {
	filter := &QueryTypeFilter{
		logger:            logger,
		excludeAAAARecords: excludeAAAARecords,
	}
	
	logger.Info("Query type filter initialized", 
		zap.Bool("excludeAAAARecords", excludeAAAARecords))
	
	return filter
}

// ShouldFilter checks if a query should be filtered based on type
func (f *QueryTypeFilter) ShouldFilter(event *etw.Event, getEventDataString func(*etw.Event, string) (string, bool)) bool {
	// If AAAA record filtering is disabled, don't filter
	if !f.excludeAAAARecords {
		return false
	}
	
	// Check if it's a query event
	if event.System.EventID != 3006 {
		return false
	}
	
	// Extract the query type from the event
	queryType, ok := getEventDataString(event, "QueryType")
	if !ok {
		return false
	}
	
	// AAAA record type is 28
	isAAAA := queryType == "28"
	
	if isAAAA {
		queryName, nameOk := getEventDataString(event, "QueryName")
		dnsName := "<unknown>"
		if nameOk {
			dnsName = queryName
		}
		
		f.logger.Debug("Filtering AAAA record", 
			zap.String("domain", dnsName),
			zap.String("queryType", queryType))
	}
	
	return isAAAA
}
