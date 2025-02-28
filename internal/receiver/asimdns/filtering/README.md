# ASIM DNS Filtering Package

This package provides modular filtering components for the ASIM DNS Collector. It includes several filter types that can be composed to implement complex filtering logic.

## Package Structure

- **event_type.go**: Filtering based on event type and ID
- **domain.go**: Filtering based on domain patterns (using wildcards)
- **query_type.go**: Filtering specific query types (e.g., AAAA records)
- **deduplication.go**: Deduplication of repeated queries 
- **filter_manager.go**: Orchestrator for all filtering components
- **package.go**: Package documentation

## Filter Types

### Event Type Filter

The `EventTypeFilter` filters events based on their event type or specific event IDs:

```go
filter := filtering.NewEventTypeFilter(
    logger,           // zap.Logger
    false,            // includeInfoEvents
    []uint16{1001, 1015, 1016, 1019},  // excludedEventIDs
)

if filter.ShouldFilter(eventID, eventType, eventSubType) {
    // Skip this event
}
```

### Domain Filter

The `DomainFilter` filters events based on domain patterns:

```go
filter := filtering.NewDomainFilter(
    logger,          // zap.Logger
    []string{        // excludedDomains
        "*.opinsights.azure.com",
        "wpad.*",
    },
)

if filter.ShouldFilter(event, getEventDataString) {
    // Skip this event
}
```

### Query Type Filter

The `QueryTypeFilter` filters specific DNS query types (e.g., AAAA records):

```go
filter := filtering.NewQueryTypeFilter(
    logger,          // zap.Logger
    true,            // excludeAAAARecords
)

if filter.ShouldFilter(event, getEventDataString) {
    // Skip this event
}
```

### Deduplication Filter

The `DeduplicationFilter` removes duplicate queries within a time window:

```go
filter := filtering.NewDeduplicationFilter(
    logger,          // zap.Logger
    true,            // enabled
    300,             // windowSeconds (5 minutes)
)

if filter.ShouldFilter(event, getEventDataString) {
    // Skip this event as duplicate
}
```

## Filter Manager

The `FilterManager` orchestrates all filtering components and provides a unified interface:

```go
manager := filtering.NewFilterManager(
    logger,                   // zap.Logger
    includeInfoEvents,        // Include Info events?
    excludedEventIDs,         // Event IDs to exclude
    excludedDomains,          // Domain patterns to exclude
    excludeAAAARecords,       // Exclude AAAA records?
    enableDeduplication,      // Enable deduplication?
    deduplicationWindow,      // Deduplication window in seconds
    getEventDataString,       // Function to get event data
    getAsimEventType,         // Function to get event type
)

// Check if an event should be filtered
if manager.ShouldFilter(event) {
    // Skip this event
}

// Get statistics
totalEvents := manager.GetTotalEvents()
filteredEvents := manager.GetFilteredEvents()
percentage := manager.GetFilterPercentage()
```

## Thread Safety

All components in this package are designed to be thread-safe and can be safely used from multiple goroutines. The deduplication filter in particular uses a read-write mutex to protect the cache.

## Performance Considerations

1. **Domain Pattern Compilation**: Domain patterns are compiled to regexes just once during initialization
2. **Event Type Caching**: Event types are cached for better performance
3. **Deduplication Pruning**: The deduplication cache is periodically pruned
4. **Atomic Counters**: The filter manager uses atomic operations for counters

## Usage in ASIM DNS Collector

This package is used by the ASIM DNS Collector to filter out low-value events and improve the signal-to-noise ratio. The collector initializes the filter manager in `newDNSEtwReceiver` and uses it in `convertEventToLogs`.
