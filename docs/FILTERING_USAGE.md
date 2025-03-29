# ASIM DNS Collector Filtering Guide

## Overview

The ASIM DNS Collector includes powerful filtering capabilities to improve the signal-to-noise ratio while preserving security-relevant DNS events. This document provides guidance on configuring and using these filtering features effectively with both DNS Server and DNS Client events.

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
    # DNS Server Configuration
    provider_guid: "{EB79061A-A566-4698-9119-3ED2807060E7}"
    
    # Event type filtering
    include_info_events: true    # Set to true to include "Info" events
    excluded_event_ids: []       # Event IDs to exclude
```

- `include_info_events`: 
  - For DNS Server: When set to `false`, excludes all events with type "Info" and subtype "status"
  - For DNS Client: Typically set to `false` to exclude informational events (EventIDs 1001, 1015, 1016, 1019)
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
- Works with both DNS Server (QNAME field) and DNS Client (QueryName field) events

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
- Especially useful for DNS Server logs where the same domain might be queried repeatedly by different clients

### Query Type Filtering

```yaml
receivers:
  asimdns:
    # Standard configuration options...
    
    # Query type filtering
    exclude_aaaa_records: false         # Filter out IPv6 AAAA record queries
```

- `exclude_aaaa_records`:
  - When set to `true`, filters out all AAAA (IPv6) record queries
  - For DNS Server, typically set to `false` to maintain visibility of all query types
  - For DNS Client, often set to `true` to reduce volume in environments primarily using IPv4

## Example DNS Server Configuration

Here's a complete example configuration with filtering options for DNS Server:

```yaml
receivers:
  asimdns:
    # ETW session name
    session_name: "DNSServerTrace"
    # DNS Server Provider Configuration
    provider_guid: "{EB79061A-A566-4698-9119-3ED2807060E7}"
    # Enable relevant keywords for DNS Server queries
    enable_flags: 0x000000000000003F  # Combined flags for query-related events
    enable_level: 4  # Information level
    
    # Event type filtering
    include_info_events: true   # Include "Info" event types for DNS Server
    excluded_event_ids: []      # No excluded event IDs by default
    
    # Domain filtering
    excluded_domains:
      - "*.opinsights.azure.com"
      - "*.guestconfiguration.azure.com"
      - "*.internal.cloudapp.net"
      - "wpad.*"
    
    # Query deduplication
    enable_deduplication: true
    deduplication_window: 300
    
    # Query type filtering
    exclude_aaaa_records: false  # Keep IPv6 AAAA record queries for DNS Server
```

## Example DNS Client Configuration

Here's a complete example configuration with filtering options for DNS Client:

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

### Recommended Settings for DNS Server Environments

#### Small DNS Server Environments
```yaml
include_info_events: true
excluded_event_ids: []
enable_deduplication: true
deduplication_window: 300
exclude_aaaa_records: false
```

#### Medium DNS Server Environments
```yaml
include_info_events: true
excluded_event_ids: []
excluded_domains:
  - "*.opinsights.azure.com"
  - "*.internal.cloudapp.net"
  - "wpad.*"
enable_deduplication: true
deduplication_window: 180
exclude_aaaa_records: false
```

#### Large DNS Server Environments
```yaml
include_info_events: true
excluded_event_ids: []
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
exclude_aaaa_records: false
```

## Common Domain Patterns

Here are common domain patterns you may want to consider excluding for both DNS Server and DNS Client events:

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

## Security Considerations for DNS Server Monitoring

The DNS Server provides valuable security insights that should be preserved:

1. **External Client Access**: DNS Server logs show which external clients are querying your DNS servers, providing visibility into potential reconnaissance.
2. **Recursive Queries**: DNS Server recursive query events can identify potential DNS tunneling or data exfiltration.
3. **Zone Transfer Attempts**: Keep events related to zone transfer requests (AXFR/IXFR) as they might indicate reconnaissance.
4. **Query Volume Patterns**: DNS Server logs can show abnormal query patterns from specific clients, which might indicate compromised hosts.

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
   ```yaml
   service:
     telemetry:
       logs:
         level: "debug"
   ```

2. **Verify Regex Patterns**: Ensure your domain patterns are correctly formatted and not too restrictive.
   - For example, `*` characters are automatically converted to `.*` in regex patterns
   - You can test patterns using the logging exporter to see which domains are being matched

3. **Monitor Memory Usage**: If deduplication is enabled with a large time window, monitor memory usage to ensure it doesn't grow excessively.
   - The deduplication cache is periodically cleaned, but very large windows can cause temporary memory growth
   - Consider reducing the window size on high-volume DNS servers

4. **Test Configuration Changes**: Test any configuration changes in a non-production environment before deploying them to production.
   - Use the debug logging mode to verify the expected behavior
   - Check the filter statistics periodically reported in the logs

5. **Check Filter Statistics**: The collector logs filtering statistics every 10 seconds, showing how many events were filtered vs. passed through:
   ```
   DNS event statistics total_received=5000 filtered_count=3200 passed_filters=1800 filter_percentage=64.0
   ```

## Comparing DNS Server and DNS Client Filtering

| Feature | DNS Server | DNS Client |
|---------|------------|------------|
| Event Volume | High (all client queries) | Lower (only local queries) |
| Security Visibility | Higher (see all client activity) | Lower (only local activity) |
| Recommended Filtering | Less aggressive | More aggressive |
| Domain Filtering | Focus on operational domains | Exclude many routine domains |
| AAAA Filtering | Usually keep (exclude_aaaa_records: false) | Often exclude (exclude_aaaa_records: true) |
| Info Events | Usually include (include_info_events: true) | Usually exclude (include_info_events: false) |

## Conclusion

Proper filtering configuration will significantly improve the usability of the ASIM DNS Collector for security operations. By focusing on security-relevant events and reducing noise, you can provide more value while reducing costs and analytical overhead. 

For DNS Server environments, the ability to monitor all client queries offers enhanced security visibility, but requires careful filtering to manage the higher volume of events. The recommended configurations in this guide provide a good starting point, but should be adjusted based on your specific environment and security requirements.

Regularly review and adjust your filtering strategy to ensure it aligns with your security monitoring requirements as your environment evolves.
