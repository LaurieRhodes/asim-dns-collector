//go:build windows
// +build windows

// Package filtering provides modular components for filtering DNS events from Windows ETW.
//
// This package contains the following filtering capabilities:
// 1. EventTypeFilter: Filters based on event type and ID
// 2. DomainFilter: Filters based on domain patterns
// 3. QueryTypeFilter: Filters specific DNS query types (e.g., AAAA records)
// 4. DeduplicationFilter: Deduplicates repeated queries in a time window
//
// The FilterManager orchestrates these components and provides a unified interface.
package filtering

// Version of the filtering package
const Version = "1.0.0"
