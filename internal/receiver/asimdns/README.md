# ASIM DNS Collector Implementation

## Overview

This directory contains the implementation of the ASIM DNS Collector, which:
1. Captures Windows DNS Client events via ETW (Event Tracing for Windows)
2. Transforms events into Microsoft Sentinel ASIM DNS Activity Logs schema
3. Applies filtering to improve signal-to-noise ratio
4. Exports the transformed and filtered data to Azure Event Hubs

## Code Structure

The implementation has been refactored into a modular structure for better maintainability and easier development:

### Core Files

- `asimdns.go`: Contains the core configuration structure and non-Windows stub implementation
- `asimdns_windows.go`: Windows-specific implementation using ETW
- `helpers.go`: General helper functions (device info, IP address, Windows version)
- `dns_helpers.go`: DNS-specific helper functions (query types, response codes, flags)

## Filtering Implementation

The filtering implementation is modular and extensible:

1. **Event Type Filtering**: Excludes specific event types with low security value (EventIDs 1001, 1015, 1016, 1019)
2. **Domain Pattern Filtering**: Filters out routine operational domains using pattern matching
3. **Query Deduplication**: Eliminates repetitive identical queries within a configurable time window
4. **Query Type Filtering**: Optional filtering of AAAA (IPv6) records to reduce duplication

## Configuration Options

The collector supports extensive configuration options:

```yaml
receivers:
  asimdns:
    # Standard configuration
    session_name: "DNSClientTrace"
    provider_guid: "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
    enable_flags: 0x8000000000000FFF
    enable_level: 5
    
    # Filtering options
    include_info_events: false
    excluded_event_ids: [1001, 1015, 1016, 1019]
    excluded_domains:
      - "*.opinsights.azure.com"
      - "*.internal.cloudapp.net"
    enable_deduplication: true
    deduplication_window: 300
    exclude_aaaa_records: true
```

## Debugging

For troubleshooting, a special debug configuration is available in `configs/debug_config.yaml`:

1. Minimal filtering to capture most events
2. Console logging for immediate visibility
3. Debug-level logging to see detailed information
4. Both console and Event Hub export to compare results

## Performance Optimization

The implementation has been optimized for performance:

1. **Early Filtering**: Events are filtered before expensive processing
2. **Efficient Data Structures**: Maps used for O(1) lookups
3. **Pre-compiled Regexes**: Domain patterns compiled once at startup
4. **Thread Safety**: Mutexes protect shared data structures
5. **Periodic Cache Cleaning**: Deduplication cache is periodically pruned

## Usage Recommendations

1. Start with default filtering settings
2. Monitor event volume and adjust filtering as needed
3. For high-volume environments, increase deduplication window and add domain patterns
4. For security-focused environments, carefully review excluded domains

## Testing

To test the implementation:

1. Use the `debug_config.yaml` configuration
2. Monitor console output to verify events are being processed
3. Compare event volumes with and without filtering
4. Validate that security-relevant events are preserved

## Future Improvements

Potential enhancements for the future:

1. Machine learning-based anomaly detection for DNS events
2. Additional filtering based on process or user context
3. Correlation with other Windows event sources
4. Statistical analysis of DNS patterns for threat detection
