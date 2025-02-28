# ETW Integration Details

## Overview
The ASIM DNS Collector uses the [golang-etw](https://github.com/0xrawsec/golang-etw) library to capture Windows DNS Client events via ETW (Event Tracing for Windows) without CGO dependencies. This document provides technical details about the ETW integration.

## Implementation Strategy

### ETW Session Management
- **Session Creation**: Using `etw.NewRealTimeSession()` to create a new ETW session
- **Provider Enablement**: Configuring the DNS Client provider with appropriate keywords and level
- **Session Parameters**: Optimized buffer settings for real-time event collection

```go
// Creating an ETW session
session := etw.NewRealTimeSession(sessionName)

// Enabling the DNS Client provider
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
The Windows DNS Client ETW events contain the following data structure:

- **Header Information**:
  - Provider GUID and Name
  - Event ID
  - Timestamp
  - Process ID and Thread ID

- **Event Data**:
  - Query Name (for DNS query events)
  - Query Type (A, AAAA, MX, etc.)
  - Query Status (for response events)
  - DNS Server used
  - Response time

## Windows DNS Client Provider

### Provider Details
- **Provider GUID**: `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`
- **Provider Name**: `Microsoft-Windows-DNS-Client`

### Important Event IDs

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 3006 | DNS Query Sent | QueryName, QueryType, QueryOptions |
| 3008 | DNS Response Received | QueryName, QueryType, QueryStatus, ResponseTime |
| 3020 | DNS Cache Entry Added | QueryName, QueryType, TTL |
| 3019 | DNS Cache Entry Removed | QueryName, QueryType |

### Configuration Options

#### Keywords
The `enable_flags` parameter controls which types of events to capture:

| Value | Event Types |
|-------|------------|
| 0x8000000000000001 | Query events |
| 0x8000000000000002 | Cache events |
| 0x8000000000000004 | Configuration events |
| 0x8000000000000008 | Networking events |
| 0x8000000000000FFF | All event types |

#### Trace Levels
The `enable_level` parameter controls the verbosity of events:

| Value | Level | Description |
|-------|-------|-------------|
| 1 | Critical | Only critical events |
| 2 | Error | Error events and above |
| 3 | Warning | Warning events and above |
| 4 | Information | Information events and above |
| 5 | Verbose | All events (most detailed) |

## OpenTelemetry Log Transformation

DNS events are transformed to OpenTelemetry logs with the following structure:

```
Logs
└── ResourceLogs
    └── Resource
        └── Attributes
            ├── service.name: "windows_dns_client"
            └── ...
    └── ScopeLogs
        └── Scope
            └── Name: "dns.client.events"
        └── LogRecords
            └── LogRecord
                ├── Timestamp: <event timestamp>
                ├── Body: "DNS Event: <event_id>"
                ├── Attributes
                │   ├── provider.name: "Microsoft-Windows-DNS-Client"
                │   ├── provider.guid: "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
                │   ├── event.id: <event_id>
                │   ├── process.pid: <process_id>
                │   ├── dns.QueryName: <query_name>
                │   ├── dns.QueryType: <query_type>
                │   └── ... (other event-specific attributes)
```

## Comparison with CGO Approach

| Feature | golang-etw | CGO Approach |
|---------|------------|--------------|
| Dependencies | Pure Go, no external libraries | Requires C compiler, MinGW on Windows |
| Build Process | Simple, CGO_ENABLED=0 works | Complex, CGO_ENABLED=1 required |
| Cross-Compilation | Easier across platforms | Difficult with C dependencies |
| Performance | Comparable | Potentially slightly faster |
| Maintainability | Higher | Lower due to C dependencies |
| API Flexibility | High-level, developer-friendly | Lower-level, closer to Windows API |

## References

- [golang-etw GitHub Repository](https://github.com/0xrawsec/golang-etw)
- [Microsoft DNS Client Provider Documentation](https://docs.microsoft.com/en-us/windows/win32/wec/windows-event-channels-for-services-and-drivers)
- [ETW Tracing Documentation](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
