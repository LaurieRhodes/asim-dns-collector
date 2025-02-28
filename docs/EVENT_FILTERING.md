# DNS Event Filtering Guide

## Overview

This document outlines the design and implementation strategies for filtering Windows DNS Client events in the ASIM DNS Collector. Testing has shown that the collector captures a high volume of events (8,000+ in 2 hours from a single server), many of which have limited security value. This guide explains the filtering approach to increase the signal-to-noise ratio while preserving security-relevant DNS information.

## Filtering Objectives

1. **Reduce Data Volume**: Minimize storage costs and analytical overhead in Microsoft Sentinel
2. **Improve Signal-to-Noise Ratio**: Focus on security-relevant DNS events
3. **Maintain Detection Capability**: Preserve all events necessary for threat detection
4. **User Configurability**: Allow customization without code changes

## Event Analysis Findings

Analysis of collected DNS events reveals several patterns that contribute to high volume with limited security value:

### 1. Repetitive Informational Events

Events with EventType "Info" and EventSubType "status" (EventIDs 1001, 1015, 1016, 1019) represent 60-70% of the total volume but provide minimal security context:

```
"2025-02-26T21:10:41.065946Z","Info","status","1","DNS Client","Microsoft","1001","DNS","DNS","Windows","10.0.14393","WORKGROUP","10.5.0.7","","","","10.5.0.7","1240","53","DNS","","","","1240-1001-1740604241065946500","NA","NA","{\"Address\":\"168.63.129.16\",\"AddressLength\":\"16\",\"DynamicAddress\":\"dynamic\",\"Index\":\"1\",\"Interface\":\"Ethernet\",\"TotalServerCount\":\"1\"}"
```

### 2. Routine Operational Queries

Regular DNS queries to operational domains occur frequently:

- Azure monitoring domains (`*.opinsights.azure.com`, `*.guestconfiguration.azure.com`)
- Internal Windows domains (`wpad.*`, `_ldap._tcp.dc._msdcs.*`)
- Cloud infrastructure domains (`*.internal.cloudapp.net`)

### 3. Duplicate Query Types

For nearly every domain query, the collector captures both:
- A records (IPv4 lookups)
- AAAA records (IPv6 lookups)

This effectively doubles the event volume while providing minimal additional security context.

### 4. Polling Queries

Many applications poll the same domains repeatedly (every minute or several minutes), generating largely duplicate information:

```
"2025-02-26T21:01:41.060062Z","Query","request","1","DNS Client","Microsoft","3006","DNS","DNS","Windows","10.0.14393","WORKGROUP","10.5.0.7","2b567116-9c70-416e-ba3e-6eb2a459ea71.ods.opinsights.azure.com","28","AAAA","10.5.0.7","2884","53","DNS","false","false","","2884-3006-1740603701060062200","NA","NA","{\"InterfaceIndex\":\"0\",\"IsAsyncQuery\":\"0\",\"IsNetworkQuery\":\"0\",\"NetworkQueryIndex\":\"0\"}"
"2025-02-26T21:02:41.063726Z","Query","request","1","DNS Client","Microsoft","3006","DNS","DNS","Windows","10.0.14393","WORKGROUP","10.5.0.7","2b567116-9c70-416e-ba3e-6eb2a459ea71.ods.opinsights.azure.com","28","AAAA","10.5.0.7","2884","53","DNS","false","false","","2884-3006-1740603761063726200","NA","NA","{\"InterfaceIndex\":\"0\",\"IsAsyncQuery\":\"0\",\"IsNetworkQuery\":\"0\",\"NetworkQueryIndex\":\"0\"}"
```

## Filtering Strategies

### 1. Event Type Filtering

Filter events based on EventID or EventType/EventSubType combinations:

```go
// Event type filtering in convertEventToLogs
if !r.config.IncludeInfoEvents && (event.System.EventID == 1001 || 
                                  event.System.EventID == 1015 || 
                                  event.System.EventID == 1016 || 
                                  event.System.EventID == 1019) {
    return plog.NewLogs() // Return empty logs to skip these events
}

// Alternative approach using a map for efficiency
var excludedEventIDs = map[uint16]bool{
    1001: true,
    1015: true,
    1016: true,
    1019: true,
}

if excludedEventIDs[event.System.EventID] && !r.config.IncludeInfoEvents {
    return plog.NewLogs()
}
```

### 2. Domain Filtering

Implement domain pattern matching to exclude routine operational domains:

```go
// Domain filtering for DNS query events
if event.System.EventID == 3006 {
    queryName, hasName := getEventDataString(event, "QueryName")
    if hasName {
        // Check if domain should be excluded
        for _, pattern := range r.config.ExcludedDomains {
            if matchDomainPattern(pattern, queryName) {
                return plog.NewLogs()
            }
        }
    }
}

// Domain pattern matching function
func matchDomainPattern(pattern, domain string) bool {
    // Convert dots to literal dots and asterisks to regex wildcards
    regexPattern := strings.Replace(pattern, ".", "\\.", -1)
    regexPattern = strings.Replace(regexPattern, "*", ".*", -1)
    regex, err := regexp.Compile("^" + regexPattern + "$")
    if err != nil {
        return false
    }
    return regex.MatchString(domain)
}
```

### 3. Query Deduplication

Implement time-based caching to deduplicate repetitive queries:

```go
// Add to receiver struct
type DNSEtwReceiver struct {
    // ...existing fields
    recentQueries     map[string]time.Time
    recentQueriesMux  sync.RWMutex
    dedupeWindow      time.Duration
}

// Initialize in constructor
func newDNSEtwReceiver(...) {
    return &DNSEtwReceiver{
        // ...existing fields
        recentQueries: make(map[string]time.Time),
        dedupeWindow:  time.Duration(r.config.DeduplicationWindow) * time.Second,
    }, nil
}

// Implement in convertEventToLogs
if r.config.EnableDeduplication && event.System.EventID == 3006 {
    queryName, hasName := getEventDataString(event, "QueryName")
    queryType, hasType := getEventDataString(event, "QueryType")
    
    if hasName && hasType {
        cacheKey := fmt.Sprintf("%s-%s", queryName, queryType)
        
        r.recentQueriesMux.RLock()
        lastSeen, exists := r.recentQueries[cacheKey]
        r.recentQueriesMux.RUnlock()
        
        now := time.Now()
        if exists && now.Sub(lastSeen) < r.dedupeWindow {
            return plog.NewLogs()
        }
        
        r.recentQueriesMux.Lock()
        r.recentQueries[cacheKey] = now
        
        // Prune cache occasionally
        if len(r.recentQueries) > 1000 {
            for k, t := range r.recentQueries {
                if now.Sub(t) > r.dedupeWindow {
                    delete(r.recentQueries, k)
                }
            }
        }
        r.recentQueriesMux.Unlock()
    }
}
```

### 4. Query Type Filtering

Option to collect only A or AAAA records to reduce duplicate events:

```go
if r.config.ExcludeAAAARecords && event.System.EventID == 3006 {
    queryType, hasType := getEventDataString(event, "QueryType")
    if hasType && queryType == "28" { // 28 = AAAA record
        return plog.NewLogs()
    }
}
```

## Configuration Extension

Add these filtering options to the collector configuration:

```go
// Config structure extension
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

Example YAML configuration:

```yaml
receivers:
  asimdns:
    session_name: "DNSClientTrace"
    provider_guid: "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
    enable_flags: 0x8000000000000FFF
    enable_level: 5
    
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

## Implementation Plan

1. **Config Structure**: Update the configuration structure with filtering options
2. **Validation**: Add validation for filtering configuration
3. **Domain Matcher**: Implement efficient domain pattern matching
4. **Deduplication**: Add cache-based query deduplication
5. **Filter Logic**: Implement the filtering logic in convertEventToLogs
6. **Performance Testing**: Test impact on throughput and resource usage
7. **Documentation**: Update configuration and usage documentation

## Security Considerations

When implementing filtering, consider these security best practices:

1. **Default to Security**: Default configuration should prioritize security over volume reduction
2. **Customizability**: Allow security teams to customize filtering based on their environment
3. **Transparency**: Make filtered events visible in logs or metrics
4. **Testing**: Validate that security-relevant events are not inadvertently filtered
5. **Review**: Regularly review filtering rules to ensure they remain appropriate

## Common Security-Relevant DNS Patterns

These DNS patterns have high security value and should not be filtered:

1. **Domain Generation Algorithms (DGAs)**: Random-looking domain names
2. **Data Exfiltration**: Unusually long subdomains or high query volume
3. **DNS Tunneling**: Abnormal query patterns or record types
4. **Command & Control**: Communication with known malicious domains
5. **DNS Rebinding**: Rapidly changing DNS responses
6. **Zone Transfers**: AXFR or IXFR record queries
7. **DNS Amplification**: Unusually high query rates
8. **Fast Flux**: Rapidly changing IP addresses for the same domain

## Next Steps

1. Implement the filtering framework in the receiver
2. Add configuration validation and documentation
3. Test filtering performance and accuracy
4. Validate security impact of filtering

## Conclusion

Implementing intelligent filtering will significantly improve the usability of the ASIM DNS Collector for security operations. By focusing on security-relevant events and reducing noise, we can provide more value while reducing costs and analytical overhead.
