# ASIM DNS Transformation Implementation

## Overview

This document details the implementation of the transformation layer that converts Windows DNS Client ETW events into the Microsoft Sentinel ASIM DNS Activity Logs schema. It serves as a reference for understanding the current implementation and for guiding future work on adding filtering capabilities to improve the signal-to-noise ratio.

## Current Status

The ASIM DNS Collector has successfully implemented the schema transformation, but testing has identified a high volume of events with limited security value. The implementation now needs to be extended with filtering capabilities to improve efficiency and focus on security-relevant DNS events.

## Architecture

The transformation is implemented in the `convertEventToLogs` function within `asimdns_windows.go`, which is structured in a modular approach:

1. **Core Transformation**: The main function orchestrates the transformation and delegates specific tasks to helper functions
2. **Event Classification**: Determines event types and subtypes based on ETW event IDs
3. **Field Mapping**: Sets ASIM fields from corresponding ETW data
4. **Device & Network Enrichment**: Adds system context like hostname, IP, OS version
5. **DNS Metadata Mapping**: Maps DNS query types, response codes, and flags

## ETW to ASIM Event Type Mapping

| ETW Event ID | Description | ASIM EventType | ASIM EventSubType |
|--------------|-------------|----------------|-------------------|
| 3006 | DNS query sent | Query | request |
| 3008 | DNS response received | Query | response |
| 3020 | DNS cache entry added | DnsCache | add |
| 3019 | DNS cache entry removed | DnsCache | remove |
| Other | Other DNS events | Info | status |

## Field Mapping Implementation

### Core ASIM Fields

| ASIM Field | Source | Transformation | 
|------------|--------|----------------|
| TimeGenerated | event.System.TimeCreated.SystemTime | Direct mapping via timestamp |
| EventType | event.System.EventID | Mapped through `getAsimEventType()` |
| EventSubType | event.System.EventID | Mapped through `getAsimEventType()` |
| EventCount | N/A | Fixed value (1) |
| EventProduct | N/A | Fixed value ("DNS Client") |
| EventVendor | N/A | Fixed value ("Microsoft") |
| EventOriginalType | event.System.EventID | Converted to string |
| EventResult | Status/QueryStatus | "Success"/"Failure" based on status code |
| EventResultDetails | Status/QueryStatus | DNS response name from `getDnsResponseName()` |
| AdditionalFields | Non-standard fields | JSON encoded remaining fields |

### DNS-Specific Fields

| ASIM Field | Source | Transformation |
|------------|--------|----------------|
| DnsQuery | QueryName | Direct mapping |
| DnsQueryType | QueryType | Converted from string to int |
| DnsQueryTypeName | QueryType | Mapped through `getDnsQueryTypeName()` |
| DnsResponseCode | Status/QueryStatus | Direct mapping for responses |
| DnsResponseName | Status/QueryStatus | Mapped through `getDnsResponseName()` |
| DnsFlags | QueryOptions | Extracted flags as string |
| DnsFlagsRecursionDesired | QueryOptions | Extracted bit flag |
| DnsFlagsCheckingDisabled | QueryOptions | Extracted bit flag |
| DnsSessionId | ProcessID, EventID, Timestamp | Generated unique ID |
| DnsNetworkDuration | QueryDuration | Direct mapping for responses |

## Event Volume Challenges

Testing has revealed high data volumes (8,000+ events in 2 hours from a single server with no clients), including many events with limited security value:

1. **Repetitive informational events**: Events with EventType "Info" and EventSubType "status" (EventIDs 1001, 1015, 1016, 1019) represent 60-70% of the total volume
2. **Routine operational queries**: Regular DNS queries to operational domains (Azure monitoring, Windows services)
3. **Duplicate query types**: Both A and AAAA records for the same domain queries
4. **Polling queries**: Regular repeated DNS queries to the same domains

## Filtering Requirements

To address the high event volume, filtering capabilities need to be implemented:

### 1. Event Type Filtering

Implementation for filtering specific event types:

```go
// In convertEventToLogs
if !r.config.IncludeInfoEvents && (eventID == 1001 || eventID == 1015 || 
                                   eventID == 1016 || eventID == 1019) {
    return plog.NewLogs() // Skip these events
}
```

### 2. Domain Pattern Filtering

Implementation for filtering specific domain patterns:

```go
// In convertEventToLogs, for query events
if eventID == 3006 {
    if queryName, ok := getEventDataString(event, "QueryName"); ok {
        for _, pattern := range r.config.ExcludedDomains {
            if matchDomainPattern(pattern, queryName) {
                return plog.NewLogs() // Skip this event
            }
        }
    }
}
```

### 3. Query Deduplication

Implementation for deduplicating repeated queries:

```go
// Add to receiver struct
type DNSEtwReceiver struct {
    // ...existing fields
    recentQueries     map[string]time.Time
    recentQueriesMux  sync.RWMutex
    dedupeWindow      time.Duration
}

// In convertEventToLogs
if r.config.EnableDeduplication && eventID == 3006 {
    if queryName, ok := getEventDataString(event, "QueryName"); ok {
        if queryType, ok := getEventDataString(event, "QueryType"); ok {
            cacheKey := fmt.Sprintf("%s-%s", queryName, queryType)
            
            r.recentQueriesMux.RLock()
            lastSeen, exists := r.recentQueries[cacheKey]
            r.recentQueriesMux.RUnlock()
            
            now := time.Now()
            if exists && now.Sub(lastSeen) < r.dedupeWindow {
                return plog.NewLogs() // Skip this event
            }
            
            // Update cache with current timestamp
            r.recentQueriesMux.Lock()
            r.recentQueries[cacheKey] = now
            r.recentQueriesMux.Unlock()
        }
    }
}
```

### 4. Configuration Updates

The configuration structure needs to be updated to support these filtering options:

```go
type Config struct {
    // ... existing fields
    
    // Event type filtering
    IncludeInfoEvents bool     `mapstructure:"include_info_events"`
    ExcludedEventIDs  []uint16 `mapstructure:"excluded_event_ids"`
    
    // Domain filtering
    ExcludedDomains []string `mapstructure:"excluded_domains"`
    
    // Query deduplication
    EnableDeduplication  bool `mapstructure:"enable_deduplication"`
    DeduplicationWindow  int  `mapstructure:"deduplication_window"`
    
    // Query type filtering
    ExcludeAAAARecords bool `mapstructure:"exclude_aaaa_records"`
}
```

## Implementation Plan

The next phase of development will focus on:

1. Implementing the filtering framework in the receiver
2. Adding configuration options and validation
3. Creating efficient pattern matching for domains
4. Developing a caching mechanism for deduplication
5. Testing filtering performance and accuracy

## Security Considerations

Key security considerations for implementing filtering:

1. **Default to Security**: Default configuration should prioritize security over volume reduction
2. **Transparency**: Filtered events should be visible in metrics or logs
3. **Review**: Filtering rules should be regularly reviewed and updated
4. **Testing**: Validation should ensure security-relevant events are not inadvertently filtered

## High-value DNS Events for Security

These patterns should never be filtered as they have high security relevance:

1. **Domain Generation Algorithms (DGAs)**: Random-looking domain names
2. **Data Exfiltration**: Unusually long subdomains or high query volume
3. **DNS Tunneling**: Abnormal query patterns or record types
4. **Command & Control**: Communication with known malicious domains
5. **DNS Rebinding**: Rapidly changing DNS responses

## Sample Configuration with Filtering

```yaml
receivers:
  asimdns:
    session_name: "DNSClientTrace"
    provider_guid: "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
    
    # Event type filtering
    include_info_events: false
    excluded_event_ids: [1001, 1015, 1016, 1019]
    
    # Domain filtering
    excluded_domains:
      - "*.opinsights.azure.com"
      - "*.internal.cloudapp.net"
      - "wpad*"
      - "_ldap._tcp.dc._msdcs.*"
    
    # Query deduplication
    enable_deduplication: true
    deduplication_window: 300  # seconds
    
    # Query type filtering
    exclude_aaaa_records: true
```

## Conclusion

The ASIM DNS Collector has successfully implemented the transformation layer for converting Windows DNS Client events to the Microsoft Sentinel ASIM schema. The next phase will focus on implementing intelligent filtering to improve the signal-to-noise ratio while preserving security-relevant events. This will significantly enhance the usability and value of the collector for security operations.
