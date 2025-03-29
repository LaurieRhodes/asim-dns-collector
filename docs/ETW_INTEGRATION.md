# ETW Integration Details

## Overview
The ASIM DNS Collector uses the [golang-etw](https://github.com/0xrawsec/golang-etw) library to capture Windows DNS Server and DNS Client events via ETW (Event Tracing for Windows) without CGO dependencies. This document provides technical details about the ETW integration.

## Implementation Strategy

### ETW Session Management
- **Session Creation**: Using `etw.NewRealTimeSession()` to create a new ETW session
- **Provider Enablement**: Configuring the DNS Server or DNS Client provider with appropriate keywords and level
- **Session Parameters**: Optimized buffer settings for real-time event collection

```go
// Creating an ETW session
session := etw.NewRealTimeSession(sessionName)

// Enabling the DNS provider
provider, err := etw.ParseProvider(providerGUID)
provider.EnableLevel = uint8(config.EnableLevel)
provider.MatchAnyKeyword = config.EnableFlags
session.EnableProvider(provider)
```

### Event Consumption
- **Consumer Creation**: Using `etw.NewRealTimeConsumer()` to consume events
- **Event Callback**: Custom callback function to process events
- **Channel-Based Processing**: Asynchronous event processing

```go
// Creating an ETW consumer
consumer := etw.NewRealTimeConsumer(ctx)
consumer.FromSessions(session)

// Setting up event callback
consumer.EventCallback = func(event *etw.Event) error {
    // Process the event
    return nil
}
```

### Event Structure
Windows DNS ETW events contain the following data structure:

- **Header Information**:
  - Provider GUID and Name
  - Event ID
  - Timestamp
  - Process ID and Thread ID

- **Event Data**:
  - For DNS Server events: QNAME, QTYPE, CLIENT_IP, etc.
  - For DNS Client events: QueryName, QueryType, QueryStatus, etc.

## Windows DNS Providers

### DNS Server Provider
- **Provider GUID**: `{EB79061A-A566-4698-9119-3ED2807060E7}`
- **Provider Name**: `Microsoft-Windows-DNSServer`

#### Important DNS Server Event IDs

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 256, 257 | DNS Query Received | QNAME, QTYPE, CLIENT_IP, Port |
| 258, 259 | DNS Response Sent | QNAME, QTYPE, RCODE |
| 260, 261 | DNS Recursion Events | QNAME, QTYPE, RD |

#### DNS Server Keywords
The `enable_flags` parameter controls which types of DNS Server events to capture:

| Value | Event Types |
|-------|------------|
| 0x0000000000000001 | QUERY_RECEIVED |
| 0x0000000000000002 | RESPONSE_SUCCESS |
| 0x0000000000000004 | RESPONSE_FAILURE |
| 0x0000000000000008 | IGNORED_QUERY |
| 0x0000000000000010 | RECURSE_QUERY_OUT |
| 0x0000000000000020 | RECURSE_RESPONSE_IN |
| 0x000000000000003F | All query-related events |

### DNS Client Provider
- **Provider GUID**: `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`
- **Provider Name**: `Microsoft-Windows-DNS-Client`

#### Important DNS Client Event IDs

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 3006 | DNS Query Sent | QueryName, QueryType, QueryOptions |
| 3008 | DNS Response Received | QueryName, QueryType, QueryStatus, ResponseTime |
| 3020 | DNS Cache Entry Added | QueryName, QueryType, TTL |
| 3019 | DNS Cache Entry Removed | QueryName, QueryType |

#### DNS Client Keywords
The `enable_flags` parameter controls which types of DNS Client events to capture:

| Value | Event Types |
|-------|------------|
| 0x8000000000000001 | Query events |
| 0x8000000000000002 | Cache events |
| 0x8000000000000004 | Configuration events |
| 0x8000000000000008 | Networking events |
| 0x8000000000000FFF | All event types |

### Trace Levels
The `enable_level` parameter controls the verbosity of events for both providers:

| Value | Level | Description |
|-------|-------|-------------|
| 1 | Critical | Only critical events |
| 2 | Error | Error events and above |
| 3 | Warning | Warning events and above |
| 4 | Information | Information events and above (recommended for DNS Server) |
| 5 | Verbose | All events (most detailed, recommended for DNS Client) |

## OpenTelemetry Log Transformation

### DNS Server Events Transformation
DNS Server events are transformed to OpenTelemetry logs with the following structure:

```
Logs
└── ResourceLogs
    └── Resource
        └── Attributes
            ├── service.name: "windows_dns_server"
            └── ...
    └── ScopeLogs
        └── Scope
            └── Name: "asim.dns.events"
        └── LogRecords
            └── LogRecord
                ├── Timestamp: <event timestamp>
                ├── Body: "DNS Server Event: <event_type> <event_subtype> (ID: <event_id>)"
                ├── Attributes
                │   ├── EventProduct: "DNS Server"
                │   ├── EventVendor: "Microsoft"
                │   ├── EventOriginalType: <event_id>
                │   ├── EventType: "Query"
                │   ├── EventSubType: <"request"|"response"|"recursive">
                │   ├── DnsQuery: <QNAME>
                │   ├── DnsQueryType: <QTYPE>
                │   ├── DnsQueryTypeName: <query type name>
                │   ├── SrcIpAddr: <CLIENT_IP>
                │   ├── SrcPortNumber: <Port>
                │   ├── DstPortNumber: 53
                │   ├── NetworkProtocol: <"TCP"|"UDP">
                │   ├── DnsFlagsRecursionDesired: <boolean>
                │   ├── DnsResponseCode: <RCODE>
                │   ├── DnsResponseName: <response code name>
                │   └── ... (other event-specific attributes)
```

### DNS Client Events Transformation
DNS Client events are transformed with a similar structure:

```
Logs
└── ResourceLogs
    └── Resource
        └── Attributes
            ├── service.name: "windows_dns_client"
            └── ...
    └── ScopeLogs
        └── Scope
            └── Name: "asim.dns.events"
        └── LogRecords
            └── LogRecord
                ├── Timestamp: <event timestamp>
                ├── Body: "DNS Client Event: <event_type> <event_subtype> (ID: <event_id>)"
                ├── Attributes
                │   ├── EventProduct: "DNS Client"
                │   ├── EventVendor: "Microsoft"
                │   ├── EventOriginalType: <event_id>
                │   ├── EventType: <"Query"|"DnsCache">
                │   ├── EventSubType: <"request"|"response"|"add"|"remove">
                │   ├── DnsQuery: <QueryName>
                │   ├── DnsQueryType: <QueryType>
                │   ├── DnsQueryTypeName: <query type name>
                │   ├── SrcIpAddr: <local IP>
                │   ├── SrcPortNumber: <SourcePort>
                │   ├── DstIpAddr: <ServerList>
                │   ├── DstPortNumber: 53
                │   ├── NetworkProtocol: "UDP"
                │   ├── DnsFlagsRecursionDesired: <boolean>
                │   ├── DnsResponseCode: <Status>
                │   ├── DnsResponseName: <response code name>
                │   └── ... (other event-specific attributes)
```

## Provider Selection and Configuration

The ASIM DNS Collector can be configured to use either the DNS Server provider or the DNS Client provider by setting the appropriate `provider_guid` in the configuration:

```yaml
# DNS Server Configuration
provider_guid: "{EB79061A-A566-4698-9119-3ED2807060E7}"

# DNS Client Configuration
provider_guid: "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
```

The collector automatically adjusts default settings based on which provider is selected:

- For DNS Server, the default level is 4 (Information) and the default flags are 0x3F (all query-related events)
- For DNS Client, the default level is 5 (Verbose) and the default flags are 0x8000000000000FFF (all events)

## Comparison with CGO Approach

| Feature | golang-etw | CGO Approach |
|---------|------------|--------------|
| Dependencies | Pure Go, no external libraries | Requires C compiler, MinGW on Windows |
| Build Process | Simple, CGO_ENABLED=0 works | Complex, CGO_ENABLED=1 required |
| Cross-Compilation | Easier across platforms | Difficult with C dependencies |
| Performance | Comparable | Potentially slightly faster |
| Maintainability | Higher | Lower due to C dependencies |
| API Flexibility | High-level, developer-friendly | Lower-level, closer to Windows API |

## Specific ETW Challenges

### Session Cleanup

Proper cleanup of ETW sessions is important to avoid resource leaks:

```go
// In Shutdown method
if r.session != nil {
    r.logger.Info("Stopping ETW session")
    if err := r.session.Stop(); err != nil {
        r.logger.Warn("Error stopping ETW session", zap.Error(err))
    }
}
```

### Preventing Duplicate Sessions

The collector includes safeguards to avoid creating duplicate ETW sessions with the same name:

```go
// Check if session already exists
existingSessions, err := etw.ListSessions()
for _, existingSession := range existingSessions {
    if existingSession.Properties.LoggerName == sessionName {
        // Session exists, need to clean it up first
        if err := etw.StopSessionByName(sessionName); err != nil {
            return fmt.Errorf("failed to stop existing session: %w", err)
        }
        break
    }
}
```

## References

- [golang-etw GitHub Repository](https://github.com/0xrawsec/golang-etw)
- [Microsoft DNS Server Provider Documentation](https://learn.microsoft.com/en-us/windows/win32/etw/microsoft-windows-dnsserver)
- [Microsoft DNS Client Provider Documentation](https://docs.microsoft.com/en-us/windows/win32/wec/windows-event-channels-for-services-and-drivers)
- [ETW Tracing Documentation](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
