# ASIM DNS Collector Filtering Guide

## Overview

The ASIM DNS Collector now includes powerful filtering capabilities to improve the signal-to-noise ratio while preserving security-relevant DNS events. This document provides guidance on configuring and using these filtering features effectively.

## Available Filtering Options

The ASIM DNS Collector supports four primary filtering mechanisms:

1. **Event Type Filtering**: Filter out specific event types or event IDs
2. **Domain Pattern Filtering**: Filter out specific domains using pattern matching
3. **Query Deduplication**: Remove duplicate queries within a configurable time window
4. **Query Type Filtering**: Filter specific DNS record types (e.g., AAAA records)

## Configuration

### Event Type Filtering

```yaml
receivers:
  asimdns:
    # Standard configuration options...
    
    # Event type filtering
    include_info_events: false   # Set to true to include "Info" events
    excluded_event_ids: [1001, 1015, 1016, 1019]  # Event IDs to exclude
```

- `include_info_events`: When set to `false`, excludes all events with type "Info" and subtype "status"
- `excluded_event_ids`: Specifies specific event IDs to exclude regardless of their type

### Domain Pattern Filtering

```yaml
receivers:
  asimdns:
    # Standard configuration options...
    
    # Domain filtering
    excluded_domains:
      - "*.opinsights.azure.com"         # Azure monitoring
      - "*.internal.cloudapp.net"        # Azure internal
      - "wpad.*"                         # Web proxy auto-discovery
```

- `excluded_domains`: A list of domain patterns to exclude
- Patterns support wildcards (`*`) which match any number of characters
- Each domain is converted to a regex pattern and compiled for efficient matching

### Query Deduplication

```yaml
receivers:
  asimdns:
    # Standard configuration options...
    
    # Query deduplication
    enable_deduplication: true          # Enable deduplication
    deduplication_window: 300           # Time window in seconds (5 minutes)
```

- `enable_deduplication`: Enables or disables the deduplication feature
- `deduplication_window`: Specifies the time window (in seconds) within which duplicate queries will be filtered

### Query Type Filtering

```yaml
receivers:
  asimdns:
    # Standard configuration options...
    
    # Query type filtering
    exclude_aaaa_records: true          # Filter out IPv6 AAAA record queries
```

- `exclude_aaaa_records`: When set to `true`, filters out all AAAA (IPv6) record queries, which can significantly reduce volume in environments primarily using IPv4

## Example Configuration

Here's a complete example configuration with all filtering options enabled:

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
      - "*.guestconfiguration.azure.com"
      - "*.internal.cloudapp.net"
      - "wpad.*"
      - "_ldap._tcp.dc._msdcs.*"
      - "*.windows.com"
      - "*.microsoft.com"
      - "*.msftncsi.com"
    
    # Query deduplication
    enable_deduplication: true
    deduplication_window: 300
    
    # Query type filtering
    exclude_aaaa_records: true
```

## Usage Recommendations

### General Guidelines

1. **Start with Default Settings**: The default filtering configuration is designed to provide good balance between signal-to-noise ratio and security visibility.
2. **Monitor Event Volume**: After enabling filtering, monitor the event volume to ensure it's at an acceptable level.
3. **Adjust Gradually**: Make incremental changes to the filtering configuration and observe the impact before making further adjustments.

### Recommended Settings by Environment

#### Small Environments (1-50 hosts)
```yaml
include_info_events: false
excluded_event_ids: [1001, 1015, 1016, 1019]
enable_deduplication: true
deduplication_window: 300
exclude_aaaa_records: true
```

#### Medium Environments (50-500 hosts)
```yaml
include_info_events: false
excluded_event_ids: [1001, 1015, 1016, 1019]
excluded_domains:
  - "*.opinsights.azure.com"
  - "*.internal.cloudapp.net"
  - "wpad.*"
enable_deduplication: true
deduplication_window: 180
exclude_aaaa_records: true
```

#### Large Environments (500+ hosts)
```yaml
include_info_events: false
excluded_event_ids: [1001, 1015, 1016, 1019]
excluded_domains:
  - "*.opinsights.azure.com"
  - "*.guestconfiguration.azure.com"
  - "*.internal.cloudapp.net"
  - "wpad.*"
  - "_ldap._tcp.dc._msdcs.*"
  - "*.windows.com"
  - "*.microsoft.com"
  - "*.msftncsi.com"
enable_deduplication: true
deduplication_window: 120
exclude_aaaa_records: true
```

## Common Domain Patterns

Here are common domain patterns you may want to consider excluding:

### Microsoft/Windows Services
- `*.windows.com`
- `*.microsoft.com`
- `*.msftncsi.com`
- `*.update.microsoft.com`
- `*.windowsupdate.com`

### Azure Services
- `*.opinsights.azure.com`
- `*.guestconfiguration.azure.com` 
- `*.internal.cloudapp.net`
- `*.blob.core.windows.net`
- `*.azurewebsites.net`

### Active Directory
- `_ldap._tcp.dc._msdcs.*`
- `_kerberos._tcp.*`
- `_kpasswd._tcp.*`

### Network Services
- `wpad.*` (Web Proxy Auto-Discovery)
- `_ntp._udp.*` (NTP time services)

### Security Considerations

Always ensure you're not filtering out security-relevant DNS events. Here are some guidelines:

1. **Never exclude Query events**: The EventType "Query" with subtypes "request" and "response" are critical for security monitoring.
2. **Be cautious with domain patterns**: Ensure your patterns aren't too broad, which could inadvertently filter important domains.
3. **Monitor for evasion**: Adversaries may attempt to evade detection by using similar domains to legitimate services.
4. **Regularly review filtered events**: Periodically sample the filtered events to ensure you're not missing important security information.

## Performance Impact

Filtering provides several performance benefits:

1. **Reduced Storage Costs**: Fewer events mean lower storage requirements in Microsoft Sentinel.
2. **Improved Query Performance**: Analysts will experience faster query results with a more focused dataset.
3. **Reduced Network Traffic**: Less data is sent to Azure Event Hubs, reducing bandwidth usage.
4. **More Efficient Analysis**: Security teams can focus on relevant events rather than sifting through noise.

## Troubleshooting

If you're experiencing issues with filtering:

1. **Check Logs**: Set the logging level to debug to see detailed information about filtered events.
2. **Verify Regex Patterns**: Ensure your domain patterns are correctly formatted and not too restrictive.
3. **Monitor Memory Usage**: If deduplication is enabled with a large time window, monitor memory usage to ensure it doesn't grow excessively.
4. **Test Configuration Changes**: Test any configuration changes in a non-production environment before deploying them to production.

## Conclusion

Proper filtering configuration will significantly improve the usability of the ASIM DNS Collector for security operations. By focusing on security-relevant events and reducing noise, you can provide more value while reducing costs and analytical overhead. Regularly review and adjust your filtering strategy to ensure it aligns with your security monitoring requirements.
