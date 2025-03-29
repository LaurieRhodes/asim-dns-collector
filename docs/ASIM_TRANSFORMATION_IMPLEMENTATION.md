# ASIM DNS Transformation Implementation

## Overview

This document details the implementation of the transformation layer that converts Windows DNS Server ETW events into the Microsoft Sentinel ASIM DNS Activity Logs schema. It serves as a reference for understanding the current implementation and for guiding future work on filtering capabilities to improve the signal-to-noise ratio.

## Current Status

The ASIM DNS Collector has successfully implemented the schema transformation for DNS Server events. The implementation includes filtering capabilities to improve efficiency and focus on security-relevant DNS events.

## Architecture

The transformation is implemented in two main functions:

1. `convertEventToLogs` in `asimdns_windows.go` - The main orchestration function that delegates to specific handlers
2. `handleDnsServerEvent` in `dns_server_helpers.go` - Specific handler for DNS Server events

This modular approach provides:

1. **Provider-specific Processing**: Different handlers for DNS Server vs DNS Client events
2. **Event Classification**: Determines event types and subtypes based on ETW event IDs
3. **Field Mapping**: Sets ASIM fields from corresponding ETW data
4. **Device & Network Enrichment**: Adds system context like hostname, IP, OS version
5. **DNS Metadata Mapping**: Maps DNS query types, response codes, and flags

## ETW to ASIM Event Type Mapping for DNS Server

| ETW Event ID | Description | ASIM EventType | ASIM EventSubType |
|--------------|-------------|----------------|-------------------|
| 256, 257 | Query received | Query | request |
| 258, 259 | Response events | Query | response |
| 260, 261 | Recursion events | Query | recursive |
| Other | Other DNS events | Info | status |

## Field Mapping Implementation for DNS Server

### Core ASIM Fields

| ASIM Field | Source | Transformation | 
|------------|--------|----------------|
| TimeGenerated | event.System.TimeCreated.SystemTime | Direct mapping via timestamp |
| EventType | event.System.EventID | Mapped through `getAsimDnsServerEventType()` |
| EventSubType | event.System.EventID | Mapped through `getAsimDnsServerEventType()` |
| EventCount | N/A | Fixed value (1) |
| EventProduct | N/A | Fixed value ("DNS Server") |
| EventVendor | N/A | Fixed value ("Microsoft") |
| EventOriginalType | event.System.EventID | Converted to string |
| EventResult | RCODE | "Success"/"Failure" based on response code |
| EventResultDetails | RCODE | DNS response name from `getDnsResponseName()` |
| AdditionalFields | Non-standard fields | JSON encoded remaining fields |

### DNS-Specific Fields

| ASIM Field | Source | Transformation |
|------------|--------|----------------|
| DnsQuery | QNAME | Direct mapping |
| DnsQueryType | QTYPE | Converted from string to int |
| DnsQueryTypeName | QTYPE | Mapped through `getDnsQueryTypeName()` |
| DnsResponseCode | RCODE | Direct mapping for responses |
| DnsResponseName | RCODE | Mapped through `getDnsResponseName()` |
| DnsFlags | Combined | Derived from RD, CD, AA, AD flags |
| DnsFlagsRecursionDesired | RD | True if RD=1 |
| DnsFlagsCheckingDisabled | CD | True if CD=1 |
| DnsSessionId | ProcessID, EventID, Timestamp | Generated unique ID |
| SrcIpAddr | CLIENT_IP/Source | Client IP address |
| SrcPortNumber | Port | Client port |
| DstPortNumber | N/A | Fixed value (53) |
| NetworkProtocol | TCP | "TCP" if TCP=1, otherwise "UDP" |
| DnsZone | Zone | Direct mapping if available |

## Filtering Features

The collector now implements several filtering mechanisms to improve the signal-to-noise ratio:

### 1. Event Type Filtering

Configuration options for filtering specific event types:

```go
// Include or exclude Info events
if !config.IncludeInfoEvents && eventType == "Info" {
    return true // Filter this event
}

// Filter specific event IDs
if config.ExcludedEventIDs != nil && config.ExcludedEventIDs[eventID] {
    return true // Filter this event
}
```

### 2. Domain Pattern Filtering

Filtering based on domain name patterns:

```go
// Check domain against exclude patterns
if queryName, ok := getEventDataString(event, "QNAME"); ok {
    for _, regex := range domainRegexes {
        if regex.MatchString(queryName) {
            return true // Filter this event
        }
    }
}
```

### 3. Query Deduplication

Deduplication of repeated queries within a configurable time window:

```go
// Create a cache key combining name and type
cacheKey := fmt.Sprintf("%s:%s", queryName, queryType)

// Check if this query exists in the cache and is recent
now := time.Now()
if exists && now.Sub(lastSeen) < f.window {
    return true // Filter duplicate query
}

// Otherwise, update the cache with current time
f.recentQueries[cacheKey] = now
```

### 4. Query Type Filtering

Optional filtering of AAAA (IPv6) records:

```go
// Check if it's a query event
if event.System.EventID != 256 {
    return false
}

// Check if it's an AAAA record
if queryType == "28" { // AAAA record type
    return true // Filter this event
}
```

## Configuration for DNS Server

The configuration structure now supports DNS Server-specific settings:

```go
type Config struct {
    // Session configuration
    SessionName  string `mapstructure:"session_name"`
    ProviderGUID string `mapstructure:"provider_guid"`
    EnableFlags  uint64 `mapstructure:"enable_flags"`
    EnableLevel  int    `mapstructure:"enable_level"`
    
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

## Sample DNS Server Configuration

```yaml
receivers:
  asimdns:
    # ETW session name
    session_name: "DNSServerTrace"
    # DNS Server Provider Configuration - Microsoft-Windows-DNSServer
    provider_guid: "{EB79061A-A566-4698-9119-3ED2807060E7}"
    # Enable relevant keywords for DNS Server queries
    # 0x0000000000000001: QUERY_RECEIVED
    # 0x0000000000000002: RESPONSE_SUCCESS
    # 0x0000000000000004: RESPONSE_FAILURE
    # 0x0000000000000008: IGNORED_QUERY
    # 0x0000000000000010: RECURSE_QUERY_OUT
    # 0x0000000000000020: RECURSE_RESPONSE_IN
    enable_flags: 0x000000000000003F  # Combined flags for query-related events
    # Information level (4 is Informational, 5 is Verbose)
    enable_level: 4
    
    # -- Filtering Configuration --
    
    # Event type filtering
    include_info_events: true   # Include "Info" event types for DNS Server
    excluded_event_ids: []      # No excluded event IDs by default
    
    # Domain filtering - exclude common operational queries
    excluded_domains:
      - "*.opinsights.azure.com"         # Azure monitoring
      - "*.guestconfiguration.azure.com" # Azure guest config
      - "*.internal.cloudapp.net"        # Azure internal
      - "wpad.*"                         # Web proxy auto-discovery
    
    # Query deduplication
    enable_deduplication: true          # Enable deduplication of repeated queries
    deduplication_window: 300           # Time window in seconds (5 minutes)
    
    # Query type filtering
    exclude_aaaa_records: false         # Keep IPv6 AAAA record queries for DNS Server
```

## High-value DNS Server Events for Security

The following DNS Server event patterns have high security relevance and should not be filtered:

1. **Suspicious or Malicious Domains**: Connections to known bad domains or IOCs
2. **Domain Generation Algorithms (DGAs)**: Random-looking domain names
3. **DNS Tunneling**: Abnormal query patterns, long subdomains, or unusual record types
4. **High Query Volume**: Sudden increases in query volume to specific domains
5. **Zone Transfer Attempts**: Unauthorized AXFR queries
6. **DNS Rebinding**: Rapidly changing DNS responses
7. **DNS Amplification**: High volume of recursive queries

## Performance Considerations

The implementation includes several optimizations for processing DNS Server events at scale:

1. **Early Filtering**: Events are filtered before expensive processing
2. **Field Caching**: Event types and response codes are cached for performance
3. **Efficient Pattern Matching**: Pre-compiled regex patterns for domain matching
4. **Event Batching**: Events are processed in batches before being sent to exporters
5. **Periodic Maintenance**: Background routines clean up caches to prevent memory growth

## Conclusion

The ASIM DNS Collector now focuses on DNS Server events and implements a comprehensive transformation layer with intelligent filtering. This approach significantly improves the signal-to-noise ratio while preserving security-relevant events, enhancing the usability and value of the collector for security operations. The collector still maintains backward compatibility with DNS Client events for environments where that's needed.
